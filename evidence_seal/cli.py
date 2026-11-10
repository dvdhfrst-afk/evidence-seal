"""Command line entry point."""

from __future__ import annotations

import argparse
import errno
import json
import os
import importlib
import sys
import traceback
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from . import __version__, library, render, reporting, scan, sealing, showing, stamping, trust, verification
from .errors import DerError, EvidenceSealError, TokenFormatError, UsageError
from .manifest import MAX_SIDE_FILE_BYTES, read_limited
from .results import EXIT_FAILED, EXIT_INTERNAL, EXIT_INTERRUPTED, EXIT_USAGE, EXIT_VERIFIED, Status, Verification
from .console import clear_progress as _clear_progress
from .console import progress as _progress
from .console import say as _say
from .console import self_command as _self_command
from .console import shown as _shown
from .console import warn as _warn
from .console import write_utf8 as _write_utf8
from .text import count_of
from .trust import TrustStore

EXIT_CODES_HELP = (
    "exit codes: 0 VERIFIED, 1 FAILED, 2 bad arguments or an unreadable file (no verdict),"
    " 3 INCOMPLETE (not a pass), 4 a bug in this tool (no verdict), 130 interrupted"
)


class _ExcludeAction(argparse.Action):
    """Keeps --exclude and --exclude-from in the order given, because the last rule that applies wins."""

    def __call__(self, parser, namespace, values, option_string=None):
        items = list(getattr(namespace, self.dest) or [])
        items.append((option_string, values))
        setattr(namespace, self.dest, items)


def _add_exclude_options(parser: argparse.ArgumentParser, pattern_help: str) -> None:
    parser.add_argument("--exclude", action=_ExcludeAction, dest="exclude", default=[], metavar="PATTERN", help=pattern_help)
    parser.add_argument(
        "--exclude-from",
        action=_ExcludeAction,
        dest="exclude",
        metavar="FILE",
        help="read patterns from this file, one per line, with # for comments; can repeat",
    )


def _exclude_rules(args: argparse.Namespace) -> List[Tuple[str, str]]:
    rules: List[Tuple[str, str]] = []
    for option, value in args.exclude:
        if option == "--exclude-from":
            rules.extend(scan.read_exclude_file(Path(value)))
        elif scan.parse_rule(value) is None:
            raise UsageError(f"the exclude pattern {value!r} has nothing to match")
        else:
            rules.append((value, "--exclude"))
    return rules


def _positive_seconds(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number of seconds") from None
    if not 0 < value < 86400:
        raise argparse.ArgumentTypeError("must be more than 0 and less than a day, in seconds")
    return value


def _retry_count(text: str) -> int:
    if not text.isascii() or not text.isdigit() or int(text) > 10:
        raise argparse.ArgumentTypeError("must be a whole number from 0 to 10")
    return int(text)


def _verify_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("manifest", type=Path, help="the manifest file")
    parser.add_argument("--token", type=Path, help="the token file (default: the .tsr beside the manifest)")
    parser.add_argument("--folder", type=Path, help="the sealed folder (default: found from the manifest)")
    parser.add_argument(
        "--ca",
        type=Path,
        action="append",
        default=[],
        metavar="FILE",
        help="trust this root certificate file, instead of the built-in fingerprints; can repeat",
    )
    parser.add_argument(
        "--untrusted",
        type=Path,
        action="append",
        default=[],
        metavar="FILE",
        help="extra certificates to build the chain from (not trusted by themselves); can repeat",
    )
    parser.add_argument("--query", type=Path, help="the saved .tsq request (default: the .tsq beside the token)")
    _add_exclude_options(parser, "do not report new files matching this; sealed files are always checked; can repeat")
    parser.add_argument("--allow-added", action="store_true", help="new files alone do not fail the file check")
    parser.add_argument("--skip-files", action="store_true", help="check only the token; the result cannot be a pass")
    parser.add_argument("--openssl", action="store_true", help="also run openssl ts -verify and report its answer")
    _add_no_library_option(parser)


def _add_no_library_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--no-library",
        action="store_true",
        help="do not record this run in the seal library (EVIDENCE_SEAL_LIBRARY=off does the same for every run)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evidence-seal",
        description="Prove that exact files existed by a given date, with a manifest and an RFC 3161 timestamp.",
        epilog="Typical use: seal a folder, stamp the manifest, and verify any time later. Add --help after a command for its options.",
        allow_abbrev=False,
    )
    parser.add_argument("--version", action="version", version=f"evidence-seal {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    seal = commands.add_parser(
        "seal",
        help="write a manifest of a folder's files; stays offline",
        description="Write a text manifest of the SHA-256 hash of every file in a folder. Nothing leaves this computer.",
        epilog="exit codes: 0 sealed, 1 could not seal, and nothing was written, 2 bad arguments",
        allow_abbrev=False,
    )
    seal.add_argument("folder", type=Path, help="the folder to seal")
    seal.add_argument("--purpose", help="why this seal is being made, in your words; required unless --dry-run")
    _add_exclude_options(seal, "leave out matching files, or put them back with a leading !; can repeat")
    seal.add_argument("--dry-run", action="store_true", help="show what would be sealed and left out; opens and writes nothing")
    seal.add_argument("--out", type=Path, help="manifest path (default: beside the folder)")
    seal.add_argument("--date", help="value for the created field, which is only a claim (default: now)")
    seal.add_argument("--force", action="store_true", help="replace an existing manifest that has no token beside it")
    _add_no_library_option(seal)

    stamp = commands.add_parser(
        "stamp",
        help="get a timestamp for a manifest; the only command that uses the network",
        description="Send the hash of a manifest to a timestamp authority and save its signed answer. Only the hash leaves this computer.",
        epilog="exit codes: 0 token saved, 1 no token saved, 2 bad arguments",
        allow_abbrev=False,
    )
    stamp.add_argument("manifest", type=Path, help="the manifest file")
    stamp.add_argument("--tsa-url", default=trust.DEFAULT_TSA_URL, help="timestamp authority URL (default: %(default)s)")
    stamp.add_argument("--hash", default="sha256", dest="hash_name", help="sha256, sha384 or sha512 (default: %(default)s)")
    stamp.add_argument("--policy", help="ask for this policy OID (object identifier)")
    stamp.add_argument("--out", type=Path, help="token path (default: the manifest's name with .tsr)")
    stamp.add_argument(
        "--timeout",
        type=_positive_seconds,
        default=stamping.DEFAULT_TIMEOUT,
        metavar="SECONDS",
        help="seconds to wait for each attempt (default: %(default)s)",
    )
    stamp.add_argument(
        "--retries",
        type=_retry_count,
        default=stamping.DEFAULT_RETRIES,
        metavar="N",
        help="times to ask again after a network failure or a busy authority, waiting between tries (default: %(default)s)",
    )
    stamp.add_argument("--ca", type=Path, action="append", default=[], metavar="FILE", help="trust this root file for the check")
    stamp.add_argument("--force", action="store_true", help="replace an existing token, keeping a dated copy of the old one")
    _add_no_library_option(stamp)

    verify = commands.add_parser(
        "verify",
        help="check the files and the token; exit 0 only when everything passed",
        description="Check the folder against the manifest, and the token against the manifest. Stays offline.",
        epilog=EXIT_CODES_HELP,
        allow_abbrev=False,
    )
    _verify_arguments(verify)
    verify.add_argument("--json", action="store_true", help="print the result as JSON")

    show = commands.add_parser(
        "show",
        help="print what a token says, in plain language",
        description="Print what a token says. This checks nothing and says so.",
        epilog="exit codes: 0 a token was read, 1 this is not a token or it holds a refusal, 2 the file cannot be read",
        allow_abbrev=False,
    )
    show.add_argument("token", type=Path, help="the token file")
    show.add_argument("--json", action="store_true", help="print as JSON")

    report = commands.add_parser(
        "report",
        help="write a one-page summary a reviewer can check independently",
        description="Run the same checks as verify and write one page, with the openssl commands to repeat them.",
        epilog=EXIT_CODES_HELP,
        allow_abbrev=False,
    )
    _verify_arguments(report)
    report.add_argument("--format", choices=("text", "html"), default="text", help="report format (default: %(default)s)")
    report.add_argument("--out", help="report path, or - for standard output (default: beside the manifest)")
    report.add_argument("--force", action="store_true", help="replace an existing report")
    for module in _command_modules():
        COMMANDS.update(module.register(commands))
    return parser


# Modules that add their own commands. Each has register(commands), which adds its parsers to the
# subparsers object and returns a dict from command name to handler.
COMMAND_MODULES: Tuple[str, ...] = ()


def _command_modules():
    return [importlib.import_module(f".{name}", __package__) for name in COMMAND_MODULES]


def _options(args: argparse.Namespace, report=None) -> verification.VerifyOptions:
    return verification.VerifyOptions(
        manifest_path=args.manifest,
        token_path=args.token,
        folder=args.folder,
        ca_files=args.ca,
        untrusted_files=args.untrusted,
        query_path=args.query,
        excludes=_exclude_rules(args),
        allow_added=args.allow_added,
        skip_files=args.skip_files,
        cross_check=args.openssl,
        report=report,
    )


def _print_preview(preview: sealing.SealPreview) -> None:
    _say("Dry run: no file was opened or hashed, and nothing was written.")
    _say(f"Would seal {count_of(len(preview.files), 'file')}, {count_of(preview.total_bytes, 'byte')}, from {preview.folder}")
    _say(f"Manifest would be: {preview.manifest_path}")
    if preview.manifest_exists:
        _say("  It already exists, so a real run needs --force or another --out.")
    _say()
    _say(f"Files ({len(preview.files)}):")
    for relative, size in preview.files:
        _say(f"  {size:>12}  {relative}")
    if preview.left_out:
        _say()
        _say(f"Left out ({len(preview.left_out)}):")
        for shown, rule in preview.left_out:
            _say(f"  {shown}  by {rule.text} ({rule.source or 'no source'})")
    if preview.links or preview.special:
        _say()
        _say(f"Listed by name only, not hashed ({len(preview.links) + len(preview.special)}):")
        for relative in preview.links + preview.special:
            _say(f"  {relative}")
    _print_unmatched(preview.unmatched)
    if preview.errors:
        _say()
        _say(f"Could not be read, so a real run would stop ({len(preview.errors)}):")
        for relative, reason in preview.errors:
            _say(f"  {relative}: {reason}")


def _print_unmatched(rules: List[scan.ExcludeRule]) -> None:
    if rules:
        _say("Exclude patterns that matched nothing, so check the spelling:")
        for rule in rules:
            _say(f"  {rule.text} ({rule.source})")


def command_seal(args: argparse.Namespace) -> int:
    rules = _exclude_rules(args)
    if args.dry_run:
        preview = sealing.preview_folder(args.folder, rules, args.out, args.date)
        _print_preview(preview)
        return EXIT_FAILED if preview.errors or not preview.files else EXIT_VERIFIED
    if args.purpose is None:
        raise UsageError("seal needs --purpose, saying why this seal is being made")
    report = _progress("Hashed")
    try:
        result = sealing.seal_folder(args.folder, args.purpose, rules, args.out, args.date, args.force, report)
    finally:
        _clear_progress(report)
    _say(f"Sealed {count_of(result.file_count, 'file')}, {count_of(result.total_bytes, 'byte')}.")
    _say(f"Manifest: {result.manifest_path}")
    if result.excluded:
        _say(f"Left out by excludes: {count_of(len(result.excluded), 'item')}.")
    if result.links or result.special:
        _say(f"Listed by name only, not hashed: {len(result.links) + len(result.special)} links or special files.")
    _print_unmatched(result.unmatched)
    _say("The manifest alone proves no date. To get a timestamp, send its hash to an authority:")
    _say(f"  {_self_command()} stamp {_shown(result.manifest_path)}")
    library.record_quietly(args.no_library, library.record_seal, result.manifest_path, args.folder)
    return EXIT_VERIFIED


def command_stamp(args: argparse.Namespace) -> int:
    try:
        store = TrustStore.from_files(args.ca)
    except EvidenceSealError as exc:
        raise UsageError(str(exc)) from None
    result = stamping.stamp_manifest(
        args.manifest,
        tsa_url=args.tsa_url,
        hash_name=args.hash_name,
        out=args.out,
        policy=args.policy,
        timeout=args.timeout,
        force=args.force,
        store=store,
        retries=args.retries,
        notify=_warn,
    )
    _say(f"Token: {result.token_path}")
    _say(f"Request: {result.query_path}")
    if result.root_path is not None:
        _say(f"Root certificate copied from the token: {result.root_path}")
        _say("  That copy is for convenience. A reviewer should get the root from the authority and compare fingerprints.")
    for path in result.kept:
        _say(f"Kept the file this replaced as: {path}")
    if result.facts is not None:
        _say(f"Time in token: {result.facts.time}")
        _say(f"Authority: {result.facts.authority or result.facts.signer or 'not stated'}")
    for check in result.checks:
        _say(f"  [{render.status_word(check.status)}] {check.title}")
    for note in result.notes:
        _say(f"  {note}")
    chain_check = next((check for check in result.checks if check.key == "chain"), None)
    if chain_check is not None and chain_check.status is not Status.PASS:
        _say(f"  Certificate chain: {chain_check.detail}")
    _say("Check it any time, offline:")
    token_option = f" --token {_shown(result.token_path)}" if args.out else ""
    _say(f"  {_self_command()} verify {_shown(Path(args.manifest))}{token_option}")
    library.record_quietly(args.no_library, library.record_stamp, args.manifest, result)
    return EXIT_VERIFIED


def _run_verify(args: argparse.Namespace):
    report = _progress("Checked")
    try:
        return verification.verify(_options(args, report))
    finally:
        _clear_progress(report)


def _record_run(command: str, args: argparse.Namespace, outcome: Verification) -> None:
    library.record_quietly(
        args.no_library, library.record_verification, command, outcome, args.manifest, args.token, args.query
    )


def command_verify(args: argparse.Namespace) -> int:
    outcome = _run_verify(args)
    if args.json:
        print(json.dumps(outcome.to_dict(), indent=2))
    else:
        sys.stdout.write(render.render_text(outcome))
    _record_run("verify", args, outcome)
    return outcome.exit_code


def command_show(args: argparse.Namespace) -> int:
    if args.token.is_dir():
        raise UsageError(f"{args.token} is a folder. Give the token file")
    data = read_limited(args.token, "token", MAX_SIDE_FILE_BYTES)
    try:
        facts = showing.describe(data)
    except (DerError, TokenFormatError) as exc:
        _warn(f"This file could not be read as a timestamp token: {exc}")
        return EXIT_FAILED
    if args.json:
        print(json.dumps(facts, indent=2))
    else:
        sys.stdout.write(showing.render_text(facts))
    return EXIT_VERIFIED if facts["granted"] and facts["time"] else EXIT_FAILED


def command_report(args: argparse.Namespace) -> int:
    target = None
    if args.out != "-":
        target = Path(args.out) if args.out else reporting.default_report_path(args.manifest, args.format)
        inputs = [args.manifest] + ([args.token] if args.token else [sealing.token_path_for(args.manifest)])
        if any(sealing.path_key(target) == sealing.path_key(path) for path in inputs):
            raise UsageError(f"the report would overwrite {target}. Choose another name with --out")
    outcome = _run_verify(args)
    root_file = args.ca[0].name if args.ca else None
    if root_file is None and sealing.root_path_for(args.manifest).is_file():
        root_file = sealing.root_path_for(args.manifest).name
    token_file = args.token.name if args.token else outcome.token_name
    context = reporting.ReportContext(
        manifest_file=args.manifest.name,
        token_file=token_file,
        root_file=root_file,
        untrusted_files=tuple(path.name for path in args.untrusted),
    )
    if args.format == "html":
        text = reporting.render_report_html(outcome, context)
    else:
        text = reporting.render_report_text(outcome, context)
    if target is None:
        _write_utf8(text)
    else:
        sealing.write_new_file(target, text.encode("utf-8"), force=args.force)
        _say(f"Report: {target}")
        _say(f"Result: {outcome.overall}")
    _record_run("report", args, outcome)
    return outcome.exit_code


COMMANDS: Dict[str, Callable[[argparse.Namespace], int]] = {
    "seal": command_seal,
    "stamp": command_stamp,
    "verify": command_verify,
    "show": command_show,
    "report": command_report,
}


def _output_is_gone(exc: OSError) -> bool:
    """The reader of the output went away. Windows reports that as an invalid argument."""
    if isinstance(exc, BrokenPipeError) or exc.errno == errno.EPIPE:
        return True
    if exc.errno != errno.EINVAL:
        return False
    try:
        sys.stdout.flush()
    except OSError:
        return True
    return False


def _silence_stdout() -> None:
    """Stops the interpreter from complaining when it flushes a closed pipe on the way out."""
    try:
        handle = os.open(os.devnull, os.O_WRONLY)
        os.dup2(handle, sys.stdout.fileno())
    except (OSError, ValueError, AttributeError):
        pass


def main(argv: Optional[List[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="backslashreplace")
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        code = COMMANDS[args.command](args)
        sys.stdout.flush()
        return code
    except UsageError as exc:
        _warn(f"error: {exc}")
        return EXIT_USAGE
    except EvidenceSealError as exc:
        _warn(f"error: {exc}")
        return EXIT_FAILED
    except KeyboardInterrupt:
        _warn("Interrupted. Files are written only once complete, so nothing was left half written.")
        return EXIT_INTERRUPTED
    except OSError as exc:
        if _output_is_gone(exc):
            _silence_stdout()
            return EXIT_USAGE
        where = f" {exc.filename}" if exc.filename else ""
        _warn(f"error:{where} {exc.strerror or exc}. No verdict was reached.")
        return EXIT_USAGE
    except MemoryError:
        _warn("error: this computer ran out of memory for this run. No verdict was reached.")
        return EXIT_USAGE
    except Exception as exc:  # A bug here must not look like a verdict, or end in a wall of text
        if os.environ.get("EVIDENCE_SEAL_DEBUG"):
            traceback.print_exc()
        _warn(
            f"error: this is a bug in evidence-seal, not a problem with your files ({type(exc).__name__}: {exc})."
            " No verdict was reached. Run again with EVIDENCE_SEAL_DEBUG=1 set for details."
        )
        return EXIT_INTERNAL
