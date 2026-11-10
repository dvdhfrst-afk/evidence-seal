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

from . import __version__, authorities, library, render, report_formats, reporting, scan, sealing, settings, showing, stamping, trust, verification
from .errors import DerError, EvidenceSealError, TokenFormatError, UsageError
from .manifest import MAX_SIDE_FILE_BYTES, read_limited
from .results import EXIT_FAILED, EXIT_INTERNAL, EXIT_INTERRUPTED, EXIT_USAGE, EXIT_VERIFIED, Status, Verification
from .console import clear_progress as _clear_progress
from .console import progress as _progress
from .console import say as _say
from .console import self_command as _self_command
from .console import shown as _shown
from .console import warn as _warn
from .console import deliver as _deliver
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


def add_exclude_options(parser: argparse.ArgumentParser, pattern_help: str) -> None:
    parser.add_argument("--exclude", action=_ExcludeAction, dest="exclude", default=[], metavar="PATTERN", help=pattern_help)
    parser.add_argument(
        "--exclude-from",
        action=_ExcludeAction,
        dest="exclude",
        metavar="FILE",
        help="read patterns from this file, one per line, with # for comments; can repeat",
    )


def exclude_rules(args: argparse.Namespace) -> List[Tuple[str, str]]:
    """Patterns from the settings come first, so a pattern given here, such as !name, can undo one of them."""
    rules: List[Tuple[str, str]] = list(getattr(args, "settings_excludes", []))
    for option, value in args.exclude:
        if option == "--exclude-from":
            rules.extend(scan.read_exclude_file(Path(value)))
        elif scan.parse_rule(value) is None:
            raise UsageError(f"the exclude pattern {value!r} has nothing to match")
        else:
            rules.append((value, "--exclude"))
    return rules


def _add_settings_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group(
        "settings", "Options not given here come from the settings file: the chosen profile, then [defaults]."
    )
    group.add_argument("--profile", metavar="NAME", help="use this profile from the settings file")
    which = group.add_mutually_exclusive_group()
    which.add_argument(
        "--settings", dest="settings_file", type=Path, metavar="FILE", help="use this settings file instead of the usual one"
    )
    which.add_argument("--no-settings", action="store_true", help="ignore the settings file and use built-in defaults")


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
        help="trust only this root certificate file, instead of the built-in fingerprints and your authority list; can repeat",
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
    add_exclude_options(parser, "do not report new files matching this; sealed files are always checked; can repeat")
    parser.add_argument("--allow-added", action="store_true", help="new files alone do not fail the file check")
    parser.add_argument("--skip-files", action="store_true", help="check only the token; the result cannot be a pass")
    parser.add_argument("--openssl", action="store_true", help="also run openssl ts -verify and report its answer")
    _add_settings_options(parser)
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
    seal.add_argument(
        "--purpose", help="why this seal is being made, in your words; required unless --dry-run or the settings give a purpose"
    )
    add_exclude_options(seal, "leave out matching files, or put them back with a leading !; can repeat")
    seal.add_argument("--dry-run", action="store_true", help="show what would be sealed and left out; opens and writes nothing")
    seal.add_argument("--out", type=Path, help="manifest path (default: beside the folder)")
    seal.add_argument("--date", help="value for the created field, which is only a claim (default: now)")
    seal.add_argument("--force", action="store_true", help="replace an existing manifest that has no token beside it")
    _add_settings_options(seal)
    _add_no_library_option(seal)

    stamp = commands.add_parser(
        "stamp",
        help="get a timestamp for a manifest; the only command that uses the network",
        description="Send the hash of a manifest to a timestamp authority and save its signed answer. Only the hash leaves this computer.",
        epilog="exit codes: 0 token saved, 1 no token saved, 2 bad arguments",
        allow_abbrev=False,
    )
    stamp.add_argument("manifest", type=Path, help="the manifest file")
    stamp.add_argument("--tsa-url", help=f"timestamp authority URL (default: {settings.built_in('authority')})")
    stamp.add_argument(
        "--authority",
        metavar="NAME",
        help="use this authority from the authority list, with its URL, policy and hash, and check the answer against its roots",
    )
    stamp.add_argument("--hash", dest="hash_name", help="sha256, sha384 or sha512 (default: sha256, or the authority's)")
    stamp.add_argument("--policy", help="ask for this policy OID (object identifier) (default: none, or the authority's)")
    stamp.add_argument("--out", type=Path, help="token path (default: the manifest's name with .tsr)")
    stamp.add_argument(
        "--timeout",
        type=settings.positive_seconds,
        metavar="SECONDS",
        help=f"seconds to wait for each attempt (default: {settings.built_in('timeout')})",
    )
    stamp.add_argument(
        "--retries",
        type=settings.retry_count,
        metavar="N",
        help=(
            "times to ask again after a network failure or a busy authority, waiting between tries"
            f" (default: {settings.built_in('retries')})"
        ),
    )
    stamp.add_argument(
        "--ca", type=Path, action="append", default=[], metavar="FILE", help="trust only this root file for the check; can repeat"
    )
    stamp.add_argument("--force", action="store_true", help="replace an existing token, keeping a dated copy of the old one")
    _add_settings_options(stamp)
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
    report.add_argument(
        "--format",
        choices=report_formats.FORMAT_NAMES,
        help="report format: " + "; ".join(f"{item.name}, {item.description}" for item in report_formats.REPORT_FORMATS)
        + f" (default: {settings.built_in('report-format')})",
    )
    report.add_argument("--out", help="report path, or - for standard output (default: beside the manifest)")
    report.add_argument("--force", action="store_true", help="replace an existing report")
    for module in _command_modules():
        COMMANDS.update(module.register(commands))
    return parser


# Modules that add their own commands. Each has register(commands), which adds its parsers to the
# subparsers object and returns a dict from command name to handler.
COMMAND_MODULES: Tuple[str, ...] = ("settings_commands", "authority_commands", "exporting", "comparing", "library_commands", "web")


def _command_modules():
    return [importlib.import_module(f".{name}", __package__) for name in COMMAND_MODULES]


SETTINGS_COMMANDS = ("seal", "stamp", "verify", "report")


def _apply_settings(args: argparse.Namespace) -> None:
    """Fills in every option not given on the command line: the profile, then [defaults], then built-in values.

    A list given on the command line (--ca, --untrusted) replaces the settings' list. Exclude patterns
    are the exception: the settings' come first and the command line's are applied after them.
    """
    chosen = settings.settings_for(args.settings_file, args.profile, args.no_settings)
    args.resolved_settings = chosen
    if not chosen.library:
        args.no_library = True
    if args.command == "seal":
        args.settings_excludes = chosen.exclude_items()
        template = chosen.value("purpose")
        if args.purpose is None and template is not None:
            created = sealing.normalize_created(args.date)
            folder = Path(args.folder).resolve()
            args.date = created
            args.purpose = settings.expand_purpose(str(template), folder.name or ".", created)
        return
    if args.command == "stamp":
        if args.tsa_url is None and args.authority is None:
            try:
                args.tsa_url, args.authority = settings.resolve_authority(str(chosen.value("authority")))
            except UsageError as exc:
                raise UsageError(f"{exc} ({chosen['authority'].source()})") from None
        if args.authority is None:
            args.ca = args.ca or chosen.files("ca")
        for name, key in (("hash_name", "hash"), ("policy", "policy"), ("timeout", "timeout"), ("retries", "retries")):
            if getattr(args, name) is not None:
                continue
            if args.authority is not None and key in ("hash", "policy") and chosen[key].origin == "built-in":
                continue  # the authority's own entry decides these unless the settings say otherwise
            setattr(args, name, chosen.value(key))
        return
    args.ca = args.ca or chosen.files("ca")
    args.settings_excludes = chosen.exclude_items()
    args.untrusted = args.untrusted or chosen.files("untrusted")
    args.allow_added = args.allow_added or bool(chosen.value("allow-added"))
    args.openssl = args.openssl or bool(chosen.value("openssl"))
    if args.command == "report" and args.format is None:
        args.format = chosen.value("report-format")


def _options(args: argparse.Namespace, report=None) -> verification.VerifyOptions:
    return verification.VerifyOptions(
        manifest_path=args.manifest,
        token_path=args.token,
        folder=args.folder,
        ca_files=args.ca,
        untrusted_files=args.untrusted,
        query_path=args.query,
        excludes=exclude_rules(args),
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
    rules = exclude_rules(args)
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


def _stamp_settings(args: argparse.Namespace) -> Tuple[str, str, Optional[str], TrustStore, Optional[authorities.Entry]]:
    """The URL, hash, policy and roots for a stamp, from the options or from an authority list entry."""
    if args.authority is None:
        try:
            store = TrustStore.from_files(args.ca) if args.ca else authorities.default_store()
        except EvidenceSealError as exc:
            raise UsageError(str(exc)) from None
        return args.tsa_url or trust.DEFAULT_TSA_URL, args.hash_name or "sha256", args.policy, store, None
    if args.tsa_url is not None:
        raise UsageError("--authority and --tsa-url cannot be used together. The authority's entry holds its URL")
    if args.ca:
        raise UsageError("--authority checks the answer against the roots in its entry, so --ca cannot be added")
    entry = authorities.find(args.authority)
    if entry is None:
        raise UsageError(f"there is no authority named {args.authority!r} in the list. See the names with: authority list")
    if not entry.roots:
        raise UsageError(
            f"no root is trusted for {entry.name} yet, so its answer could not be checked. Nothing was sent."
            f" Add one with: authority trust {entry.name} --root FILE"
        )
    return entry.url, args.hash_name or entry.hash_name, args.policy or entry.policy, authorities.store_for(entry), entry


def command_stamp(args: argparse.Namespace) -> int:
    url, hash_name, policy, store, entry = _stamp_settings(args)
    result = stamping.stamp_manifest(
        args.manifest,
        tsa_url=url,
        hash_name=hash_name,
        out=args.out,
        policy=policy,
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
    if entry is not None:
        _say(f"From the authority list: {entry.name}, checked against its roots only")
        if entry.test:
            _say(f"  {entry.name} is a local test authority. This token proves nothing to anyone else.")
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
    chosen = report_formats.by_name(args.format)
    target = None
    if args.out != "-":
        target = Path(args.out) if args.out else report_formats.default_report_path(args.manifest, chosen.name)
        token = args.token if args.token else sealing.token_path_for(args.manifest)
        protected = sealing.files_of(args.manifest, reports=False) + [token] + list(args.ca) + list(args.untrusted)
        sealing.refuse_to_replace(target, protected + ([args.query] if args.query else []), "the report")
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
    _deliver(chosen.render(outcome, context), target, args.force, chosen.binary)
    if target is not None:
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
        if args.command in SETTINGS_COMMANDS:
            _apply_settings(args)
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
