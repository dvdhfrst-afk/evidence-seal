"""Command line entry point."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional, Tuple

from . import __version__, render, reporting, scan, sealing, showing, stamping, trust, verification
from .errors import DerError, EvidenceSealError, TokenFormatError, UsageError
from .results import EXIT_FAILED, EXIT_USAGE, EXIT_VERIFIED, Status
from .trust import TrustStore


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
    parser.add_argument("--query", type=Path, help="the saved .tsq request (default: the .tsq beside the manifest)")
    _add_exclude_options(parser, "do not report new files matching this; sealed files are always checked; can repeat")
    parser.add_argument("--allow-added", action="store_true", help="new files alone do not fail the file check")
    parser.add_argument("--skip-files", action="store_true", help="check only the token; the result cannot be a pass")
    parser.add_argument("--openssl", action="store_true", help="also run openssl ts -verify and report its answer")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evidence-seal",
        description="Prove that exact files existed by a given date, with a manifest and an RFC 3161 timestamp.",
    )
    parser.add_argument("--version", action="version", version=f"evidence-seal {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    seal = commands.add_parser("seal", help="write a manifest of a folder's files; stays offline")
    seal.add_argument("folder", type=Path)
    seal.add_argument("--purpose", help="why this seal is being made, in your words; required unless --dry-run")
    _add_exclude_options(seal, "leave out matching files, or put them back with a leading !; can repeat")
    seal.add_argument("--dry-run", action="store_true", help="show what would be sealed and left out; opens and writes nothing")
    seal.add_argument("--out", type=Path, help="manifest path (default: beside the folder)")
    seal.add_argument("--date", help="value for the created field (default: now)")
    seal.add_argument("--force", action="store_true", help="replace an existing manifest")

    stamp = commands.add_parser("stamp", help="get a timestamp for a manifest; the only command that uses the network")
    stamp.add_argument("manifest", type=Path)
    stamp.add_argument("--tsa-url", default=trust.DEFAULT_TSA_URL, help="timestamp authority URL (default: %(default)s)")
    stamp.add_argument("--hash", default="sha256", dest="hash_name", help="sha256, sha384 or sha512 (default: %(default)s)")
    stamp.add_argument("--policy", help="ask for this policy OID")
    stamp.add_argument("--out", type=Path, help="token path (default: the manifest's name with .tsr)")
    stamp.add_argument("--timeout", type=float, default=stamping.DEFAULT_TIMEOUT, help="seconds to wait (default: %(default)s)")
    stamp.add_argument("--ca", type=Path, action="append", default=[], metavar="FILE", help="trust this root file for the check")
    stamp.add_argument("--force", action="store_true", help="replace an existing token")

    verify = commands.add_parser("verify", help="check the files and the token; exit 0 only when everything passed")
    _verify_arguments(verify)
    verify.add_argument("--json", action="store_true", help="print the result as JSON")

    show = commands.add_parser("show", help="print what a token says, in plain language")
    show.add_argument("token", type=Path)
    show.add_argument("--json", action="store_true", help="print as JSON")

    report = commands.add_parser("report", help="write a one-page summary a reviewer can check independently")
    _verify_arguments(report)
    report.add_argument("--format", choices=("text", "html"), default="text", help="report format (default: %(default)s)")
    report.add_argument("--out", help="report path, or - for standard output (default: beside the manifest)")
    report.add_argument("--force", action="store_true", help="replace an existing report")
    return parser


def _options(args: argparse.Namespace) -> verification.VerifyOptions:
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
    )


def _print_preview(preview: sealing.SealPreview) -> None:
    print("Dry run: no file was opened or hashed, and nothing was written.")
    print(f"Would seal {len(preview.files)} files, {preview.total_bytes} bytes, from {preview.folder}")
    print(f"Manifest would be: {preview.manifest_path}")
    if preview.manifest_exists:
        print("  It already exists, so a real run needs --force or another --out.")
    print(f"\nFiles ({len(preview.files)}):")
    for relative, size in preview.files:
        print(f"  {size:>12}  {relative}")
    if preview.left_out:
        print(f"\nLeft out ({len(preview.left_out)}):")
        for shown, rule in preview.left_out:
            print(f"  {shown}  by {rule.text} ({rule.source or 'no source'})")
    if preview.links or preview.special:
        print(f"\nListed by name only, not hashed ({len(preview.links) + len(preview.special)}):")
        for relative in preview.links + preview.special:
            print(f"  {relative}")
    _print_unmatched(preview.unmatched)
    if preview.errors:
        print(f"\nCould not be read, so a real run would stop ({len(preview.errors)}):")
        for relative, reason in preview.errors:
            print(f"  {relative}: {reason}")


def _print_unmatched(rules: List[scan.ExcludeRule]) -> None:
    if rules:
        print("Exclude patterns that matched nothing, so check the spelling:")
        for rule in rules:
            print(f"  {rule.text} ({rule.source})")


def command_seal(args: argparse.Namespace) -> int:
    rules = _exclude_rules(args)
    if args.dry_run:
        preview = sealing.preview_folder(args.folder, rules, args.out, args.date)
        _print_preview(preview)
        return EXIT_FAILED if preview.errors or not preview.files else EXIT_VERIFIED
    if args.purpose is None:
        raise UsageError("seal needs --purpose, saying why this seal is being made")
    result = sealing.seal_folder(args.folder, args.purpose, rules, args.out, args.date, args.force)
    print(f"Sealed {result.file_count} files, {result.total_bytes} bytes.")
    print(f"Manifest: {result.manifest_path}")
    if result.excluded:
        print(f"Left out by excludes: {len(result.excluded)} items.")
    if result.links or result.special:
        print(f"Listed by name only, not hashed: {len(result.links) + len(result.special)} links or special files.")
    _print_unmatched(result.unmatched)
    print("The manifest alone proves no date. To get a timestamp, send its hash to an authority:")
    print(f"  python -m evidence_seal stamp {_shown(result.manifest_path)}")
    return EXIT_VERIFIED


def _shown(path: Path) -> str:
    return reporting.quote_argument(str(path))


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
    )
    print(f"Token: {result.token_path}")
    print(f"Request: {result.query_path}")
    if result.root_path is not None:
        print(f"Root certificate copied from the token: {result.root_path}")
        print("  That copy is for convenience. A reviewer should get the root from the authority and compare fingerprints.")
    if result.facts is not None:
        print(f"Time in token: {result.facts.time}")
        print(f"Authority: {result.facts.authority or result.facts.signer or 'not stated'}")
    for check in result.checks:
        print(f"  [{render.status_word(check.status)}] {check.title}")
    for note in result.notes:
        print(f"  {note}")
    chain_check = next((check for check in result.checks if check.key == "chain"), None)
    if chain_check is not None and chain_check.status is not Status.PASS:
        print(f"  Certificate chain: {chain_check.detail}")
    print("Check it any time, offline:")
    token_option = f" --token {_shown(result.token_path)}" if args.out else ""
    print(f"  python -m evidence_seal verify {_shown(Path(args.manifest))}{token_option}")
    return EXIT_VERIFIED


def command_verify(args: argparse.Namespace) -> int:
    outcome = verification.verify(_options(args))
    if args.json:
        print(json.dumps(outcome.to_dict(), indent=2, ensure_ascii=False))
    else:
        sys.stdout.write(render.render_text(outcome))
    return outcome.exit_code


def command_show(args: argparse.Namespace) -> int:
    try:
        data = args.token.read_bytes()
    except OSError as exc:
        raise UsageError(f"cannot read token {args.token}: {exc.strerror or exc}") from None
    try:
        facts = showing.describe(data)
    except (DerError, TokenFormatError) as exc:
        print(f"This file could not be read as a timestamp token: {exc}", file=sys.stderr)
        return EXIT_FAILED
    if args.json:
        print(json.dumps(facts, indent=2, ensure_ascii=False))
    else:
        sys.stdout.write(showing.render_text(facts))
    return EXIT_VERIFIED if facts["granted"] and facts["time"] else EXIT_FAILED


def command_report(args: argparse.Namespace) -> int:
    outcome = verification.verify(_options(args))
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
    if args.out == "-":
        sys.stdout.write(text)
    else:
        target = Path(args.out) if args.out else reporting.default_report_path(args.manifest, args.format)
        sealing.write_new_file(target, text.encode("utf-8"), force=args.force)
        print(f"Report: {target}")
        print(f"Result: {outcome.overall}")
    return outcome.exit_code


COMMANDS = {
    "seal": command_seal,
    "stamp": command_stamp,
    "verify": command_verify,
    "show": command_show,
    "report": command_report,
}


def main(argv: Optional[List[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="backslashreplace")
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return COMMANDS[args.command](args)
    except UsageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except EvidenceSealError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAILED
    except BrokenPipeError:
        return EXIT_FAILED
