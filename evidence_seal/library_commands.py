"""The library command: list, show, import, verify, check, forget, tag, untag, log and where.

Registered through ``cli.COMMAND_MODULES``. Storage lives in ``library.py``. These actions read the
files a user names and write only inside the library folder, never beside the user's files.

For other parts of the tool: ``verify_seal(library, sha, folder, report)`` is ``library verify`` for
one seal, with progress sent to ``report``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from . import library as lib
from . import manifest, scan, sealing, verification
from .console import clear_progress, progress, say, size_text
from .errors import EvidenceSealError, UsageError
from .library import Library, LibraryError
from .results import (
    EXIT_FAILED,
    EXIT_INCOMPLETE,
    EXIT_VERIFIED,
    FAILED,
    INCOMPLETE,
    JSON_SCHEMA_VERSION,
    Check,
    Status,
    Verification,
)
from .text import count_of
from .trust import TrustStore

ID_HELP = "a seal ID (6 or more hex digits from the start of the manifest's SHA-256) or a manifest file"
READ_EXITS = "exit codes: 0 done, 1 the library could not be read, 2 bad arguments or an unknown ID"
CHANGE_EXITS = "exit codes: 0 done, 1 the library could not be changed, 2 bad arguments or an unknown ID"
MAX_IMPORT_ENTRIES = 200000
MAX_IMPORT_DEPTH = 32
MAX_SHOWN_RUNS = 50
_TOKEN_ENDINGS = (sealing.TOKEN_SUFFIX, ".tst")
_NOT_MANIFESTS = sealing.COMPANION_SUFFIXES + (".tst",)
_ANY_NATIVE = b"evidence-seal manifest v"
LIBRARY_VERIFY = "library verify"


def register(commands: Any) -> Dict[str, Callable[[argparse.Namespace], int]]:
    parser = commands.add_parser(
        "library",
        help="the seals made or checked on this computer: list, show, verify and more",
        description=(
            "A record of every seal made or checked on this computer, with copies of its manifest, tokens,"
            " requests and root certificates. It never moves, changes or deletes your own files."
        ),
        epilog=(
            "Each action has its own --help and exit codes. Commands record into the library unless given"
            " --no-library, or unless EVIDENCE_SEAL_LIBRARY=off is set."
        ),
        allow_abbrev=False,
    )
    actions = parser.add_subparsers(dest="library_action", required=True, metavar="ACTION")

    def action(name: str, summary: str, description: str, epilog: str) -> argparse.ArgumentParser:
        return actions.add_parser(name, help=summary, description=description, epilog=epilog, allow_abbrev=False)

    listing = action("list", "list the seals in the library", "List every seal in the library, oldest first.", READ_EXITS)
    listing.add_argument("--folder", type=Path, help="only seals whose folder was last seen at this path")
    listing.add_argument("--tag", help="only seals with this tag")
    listing.add_argument("--json", action="store_true", help="print as JSON")

    show = action(
        "show", "everything the library knows about one seal", "Show one seal: tokens, verification runs and events.", READ_EXITS
    )
    show.add_argument("id", metavar="ID", help=ID_HELP)
    show.add_argument("--json", action="store_true", help="print as JSON")

    importing = action(
        "import",
        "add seals made before the library existed",
        "Find manifests, and the tokens, requests and root copies beside them, and add them to the library."
        " Nothing is written beside your files.",
        "exit codes: 0 every manifest found was added or already known, 1 something was skipped, 2 bad arguments",
    )
    importing.add_argument("paths", nargs="+", type=Path, metavar="PATH", help="a manifest file, or a folder to look in")
    importing.add_argument("--recursive", action="store_true", help="look in folders inside each folder too")
    importing.add_argument("--dry-run", action="store_true", help="say what would be added, and write nothing")
    importing.add_argument("--json", action="store_true", help="print as JSON")

    checking = action(
        "verify",
        "verify seals from the library's own copies",
        "Verify seals from the library's copies of their manifest and token, against each folder's last known"
        " place, and record the result. Stays offline.",
        "exit codes: 0 every seal VERIFIED, 1 any seal FAILED, 2 bad arguments,"
        " 3 any seal INCOMPLETE (not a pass), 4 a bug in this tool",
    )
    checking.add_argument("ids", nargs="*", metavar="ID", help=ID_HELP)
    checking.add_argument("--all", action="store_true", help="verify every seal in the library")
    checking.add_argument("--folder", type=Path, help="check the files in this folder instead (one seal only)")
    checking.add_argument(
        "--ca", type=Path, action="append", default=[], metavar="FILE", help="trust this root certificate file; can repeat"
    )
    checking.add_argument("--json", action="store_true", help="print the results as JSON")

    sound = action(
        "check",
        "make sure the library itself is sound",
        "Check that every copy matches its hash, every copy the index refers to exists, nothing is left over,"
        " and SQLite finds no damage. Changes nothing.",
        "exit codes: 0 the library is sound, 1 a problem was found or the library cannot be read",
    )
    sound.add_argument("--json", action="store_true", help="print as JSON")

    forget = action(
        "forget",
        "remove a seal from the library",
        "Remove a seal from the library, with the copies nothing else uses. Your own files are never touched.",
        "exit codes: 0 forgotten, 1 not forgotten (declined, or the library could not be changed),"
        " 2 bad arguments, an unknown ID, or no --yes when not at a terminal",
    )
    forget.add_argument("id", metavar="ID", help=ID_HELP)
    forget.add_argument("--yes", action="store_true", help="do not ask first; needed when not run at a terminal")

    tag = action("tag", "add a tag to a seal", "Add a short label to a seal, for library list --tag.", CHANGE_EXITS)
    tag.add_argument("id", metavar="ID", help=ID_HELP)
    tag.add_argument("tag", metavar="TAG", help=f"the tag, 1 to {lib.MAX_TAG_LENGTH} printable characters")
    untag = action("untag", "remove a tag from a seal", "Remove a tag from a seal.", CHANGE_EXITS)
    untag.add_argument("id", metavar="ID", help=ID_HELP)
    untag.add_argument("tag", metavar="TAG", help="the tag to remove")

    log = action("log", "what happened in the library, newest first", "Show the library's journal of events.", READ_EXITS)
    log.add_argument("id", nargs="?", metavar="ID", help="only this seal's events")
    log.add_argument("--limit", type=_limit, default=20, metavar="N", help="show at most N events (default: %(default)s)")
    log.add_argument("--json", action="store_true", help="print as JSON")

    action(
        "where",
        "where the library is kept, and whether recording is on",
        "Say where the library is kept, how large it is, and whether commands record into it.",
        "exit codes: 0 done, 1 the library could not be read",
    )
    return {"library": run}


def _limit(text: str) -> int:
    if not text.isascii() or not text.isdigit() or not 1 <= int(text) <= lib.MAX_LOG_LIMIT:
        raise argparse.ArgumentTypeError(f"must be a whole number from 1 to {lib.MAX_LOG_LIMIT}")
    return int(text)


def run(args: argparse.Namespace) -> int:
    return ACTIONS[args.library_action](args)


@contextmanager
def _existing() -> Iterator[Optional[Library]]:
    """The library if there is one yet. Reading never creates it."""
    found = lib.open_library(create=False)
    try:
        yield found
    finally:
        if found is not None:
            found.close()


def _required(found: Optional[Library], text: str) -> Library:
    if found is None:
        raise UsageError(f"the library is empty, so it has no seal {text!r}. library import adds earlier seals")
    return found


def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2))


def _cut(text: Optional[str], width: int) -> str:
    text = text or "-"
    return text if len(text) <= width else text[: width - 3] + "..."


def _seal_json(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": lib.short_id(row["manifest_sha256"]),
        "manifest_sha256": row["manifest_sha256"],
        "purpose": row["purpose"],
        "created": row["created"],
        "folder_name": row["folder_name"],
        "file_count": row["file_count"],
        "total_bytes": row["total_bytes"],
        "manifest_kind": row["manifest_kind"],
        "manifest_path": row["manifest_path"],
        "folder_path": row["folder_path"],
        "added_at": row["added_at"],
        "tags": row["tags"],
        "token_time": row["token_time"],
        "last_result": row["last_result"],
        "last_checked": row["last_checked"],
    }


def _last_check(row: Dict[str, Any]) -> str:
    return f"{row['last_result']} {row['last_checked']}" if row["last_result"] else "never"


# list, show, log, where ---------------------------------------------------------------------------


def action_list(args: argparse.Namespace) -> int:
    with _existing() as found:
        rows = found.seals() if found is not None else []
    if args.folder is not None:
        wanted = sealing.path_key(args.folder)
        rows = [row for row in rows if row["folder_path"] and sealing.path_key(Path(row["folder_path"])) == wanted]
    if args.tag is not None:
        tag = lib.check_tag(args.tag)
        rows = [row for row in rows if tag in row["tags"]]
    if args.json:
        _print_json({"schema_version": JSON_SCHEMA_VERSION, "seals": [_seal_json(row) for row in rows]})
        return EXIT_VERIFIED
    if not rows:
        if args.folder is not None or args.tag is not None:
            say("No seal in the library matches.")
        else:
            say("The library has no seals yet. Seal, stamp and verify record into it, and library import adds earlier seals.")
        return EXIT_VERIFIED
    say(f"{'ID':<12}  {'CREATED':<20}  {'FILES':>7}  {'TOKEN TIME':<23}  {'LAST CHECK':<29}  PURPOSE")
    for row in rows:
        say(
            f"{lib.short_id(row['manifest_sha256']):<12}  {_cut(row['created'], 20):<20}  {row['file_count']:>7}"
            f"  {_cut(row['token_time'], 23):<23}  {_cut(_last_check(row), 29):<29}  {_cut(row['purpose'], 60)}"
        )
    say(f"{count_of(len(rows), 'seal')}. Show one with: library show ID")
    return EXIT_VERIFIED


def action_show(args: argparse.Namespace) -> int:
    with _existing() as found:
        library = _required(found, args.id)
        sha = library.resolve(args.id)
        row = library.seal(sha)
        tokens = library.tokens(sha)
        runs = library.runs(sha)
        events = library.events(sha, lib.MAX_LOG_LIMIT)
    if args.json:
        _print_json(
            {"schema_version": JSON_SCHEMA_VERSION, "seal": _seal_json(row), "tokens": tokens, "runs": runs, "events": events}
        )
        return EXIT_VERIFIED
    size = f", {count_of(row['total_bytes'], 'byte')}" if row["total_bytes"] is not None else ""
    say(f"Seal {sha}")
    say(f"  Purpose: {row['purpose'] or 'not stated'}")
    say(f"  Created (a claim by whoever sealed it): {row['created'] or 'not stated'}")
    say(f"  Folder name: {row['folder_name'] or 'not stated'}")
    say(f"  Files: {row['file_count']}{size}")
    say(f"  Manifest kind: {row['manifest_kind']}")
    say(f"  Manifest last seen at: {row['manifest_path'] or 'not known'}")
    say(f"  Folder last seen at: {row['folder_path'] or 'not known'}")
    say(f"  Added to the library: {row['added_at']}")
    say(f"  Tags: {', '.join(row['tags']) or 'none'}")
    say()
    say(f"Tokens ({len(tokens)}):")
    for token in tokens:
        state = "current" if token["is_current"] else "replaced by stamp --force"
        say(f"  {token['token_time'] or 'no time'}, from {token['authority'] or 'not named'}, serial {token['serial']} ({state})")
        say(f"    SHA-256 {token['token_sha256']}")
        say(f"    last seen at {token['token_path'] or 'not known'}")
        kept = [name for name, key in (("request", "request_sha256"), ("root copy", "root_sha256")) if token[key]]
        say(f"    also kept: {', '.join(kept) or 'nothing else'}")
    say()
    say(f"Verification runs ({len(runs)}, newest first):")
    for item in runs[:MAX_SHOWN_RUNS]:
        say(f"  {item['run_at']}  {item['overall']} (exit {item['exit_code']}) by {item['command']}")
        say(f"    folder: {item['folder_path'] or 'not checked'}")
        for check in item["checks"]:
            say(f"    [{check['status'].upper()}] {check['title']}")
    if len(runs) > MAX_SHOWN_RUNS:
        say(f"  and {len(runs) - MAX_SHOWN_RUNS} earlier runs; --json lists them all")
    say()
    say(f"Events ({len(events)}, newest first):")
    for event in events:
        say(f"  {event['at']}  {event['kind']}: {event['detail']} (evidence-seal {event['tool_version']})")
    return EXIT_VERIFIED


def action_log(args: argparse.Namespace) -> int:
    with _existing() as found:
        if found is None:
            if args.id is not None:
                _required(found, args.id)
            events: List[Dict[str, Any]] = []
        else:
            sha = found.resolve(args.id) if args.id is not None else None
            events = found.events(sha, args.limit)
    if args.json:
        _print_json({"schema_version": JSON_SCHEMA_VERSION, "events": events})
        return EXIT_VERIFIED
    if not events:
        say("The library's journal is empty.")
    for event in events:
        seal = lib.short_id(event["manifest_sha256"]) if event["manifest_sha256"] else "-"
        say(f"{event['at']}  {event['kind']:<9}  {seal:<12}  {event['detail']} ({event['tool_version']})")
    return EXIT_VERIFIED


def _folder_size(folder: Path) -> Tuple[int, int]:
    count = total = 0
    for parent, _, names in os.walk(folder):
        for name in names:
            try:
                total += os.stat(os.path.join(parent, name)).st_size
                count += 1
            except OSError:
                continue
    return count, total


def action_where(args: argparse.Namespace) -> int:
    root = lib.library_root()
    index = root / lib.INDEX_NAME
    say(f"Library: {root}")
    with _existing() as found:
        if found is None:
            say(f"Index: {index} (not created yet)")
        else:
            counts = found.counts()
            say(f"Index: {index} ({size_text(index.stat().st_size)}, schema {found.schema_version()})")
            files, total = _folder_size(found.objects_path)
            say(f"Copies: {found.objects_path} ({count_of(files, 'file')}, {size_text(total)})")
            say(f"Holds {count_of(counts['seals'], 'seal')}, {count_of(counts['tokens'], 'token')} and {count_of(counts['runs'], 'verification run')}.")
    if lib.recording_wanted(False):
        say(f"Recording: on. Turn it off for one command with --no-library, or for all with {lib.SWITCH_VARIABLE}=off.")
    else:
        say(f"Recording: off, because {lib.SWITCH_VARIABLE} is set to {os.environ.get(lib.SWITCH_VARIABLE, '')!r}.")
    say("To move it, set EVIDENCE_SEAL_HOME, which moves all of evidence-seal's own files.")
    return EXIT_VERIFIED


# tag, untag, forget, check ------------------------------------------------------------------------


def action_tag(args: argparse.Namespace) -> int:
    tag = lib.check_tag(args.tag)
    with _existing() as found:
        library = _required(found, args.id)
        sha = library.resolve(args.id)
        changed = library.tag(sha, tag) if args.library_action == "tag" else library.untag(sha, tag)
    if args.library_action == "tag":
        say(f"Tagged {lib.short_id(sha)} with {tag}." if changed else f"{lib.short_id(sha)} already has the tag {tag}. Nothing changed.")
    else:
        say(f"Removed the tag {tag} from {lib.short_id(sha)}." if changed else f"{lib.short_id(sha)} did not have the tag {tag}. Nothing changed.")
    return EXIT_VERIFIED


def _copies(count: int) -> str:
    return "1 copy" if count == 1 else f"{count} copies"


def _confirmed(question: str) -> bool:
    try:
        answer = input(question)
    except EOFError:
        return False
    return answer.strip().lower() in ("y", "yes")


def action_forget(args: argparse.Namespace) -> int:
    with _existing() as found:
        library = _required(found, args.id)
        sha = library.resolve(args.id)
        row = library.seal(sha)
        if not args.yes:
            try:
                at_terminal = sys.stdin is not None and sys.stdin.isatty()
            except (AttributeError, ValueError):
                at_terminal = False
            if not at_terminal:
                raise UsageError("forget asks before it removes a seal, and this is not a terminal. Add --yes to go ahead")
            question = f"Forget seal {lib.short_id(sha)} ({_cut(row['purpose'], 60)})? Your own files are not touched. [y/N] "
            if not _confirmed(question):
                say("Nothing was forgotten.")
                return EXIT_FAILED
        dropped = library.forget(sha)
    say(f"Forgot seal {lib.short_id(sha)}, and removed {_copies(dropped)} that nothing else in the library uses.")
    say("Your manifest, tokens and folder were not touched.")
    return EXIT_VERIFIED


def action_check(args: argparse.Namespace) -> int:
    with _existing() as found:
        if found is None:
            problems: List[str] = []
            counts = {"seals": 0, "tokens": 0, "runs": 0, "objects": 0}
        else:
            problems = found.check()
            counts = found.counts()
    if args.json:
        _print_json({"schema_version": JSON_SCHEMA_VERSION, "sound": not problems, "problems": problems, "counts": counts})
        return EXIT_FAILED if problems else EXIT_VERIFIED
    if found is None:
        say(f"There is no library yet at {lib.library_root()}, so there is nothing to check.")
        return EXIT_VERIFIED
    if not problems:
        say(
            f"The library is sound: {count_of(counts['seals'], 'seal')}, {_copies(counts['objects'])} that all match"
            " their hashes, and SQLite found no damage."
        )
        return EXIT_VERIFIED
    say(f"The library has {count_of(len(problems), 'problem')}:")
    for problem in problems:
        say(f"  {problem}")
    say("Nothing was changed. Your own files are not affected; library verify still checks a seal against them.")
    return EXIT_FAILED


# import -------------------------------------------------------------------------------------------


@dataclass
class Imported:
    path: Path
    status: str
    sha: Optional[str] = None
    reason: str = ""
    tokens_added: int = 0
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": str(self.path),
            "status": self.status,
            "id": lib.short_id(self.sha) if self.sha else None,
            "manifest_sha256": self.sha,
            "tokens_added": self.tokens_added,
            "reason": self.reason or None,
            "notes": self.notes,
        }


def _inside(path: Path, folder: Path) -> bool:
    try:
        Path(os.path.abspath(path)).relative_to(os.path.abspath(folder))
    except ValueError:
        return False
    return True


def _tokens_beside(path: Path) -> List[Path]:
    found: List[Path] = []
    keys = set()
    for candidate in sealing.companion_paths(path):
        if candidate.name.endswith(_TOKEN_ENDINGS) and candidate.is_file() and sealing.path_key(candidate) not in keys:
            keys.add(sealing.path_key(candidate))
            found.append(candidate)
    return found


def _replaced_beside(path: Path) -> List[Path]:
    return sorted(copy for copy in sealing.kept_copies(path) if copy.name.endswith(_TOKEN_ENDINGS))


def _worth_reading(path: Path) -> bool:
    """A native manifest by its first line, or any other file that has a token beside it."""
    if path.name.endswith(_NOT_MANIFESTS) or lib.is_replaced_copy(path):
        return False
    try:
        with open(path, "rb") as handle:
            start = handle.read(len(_ANY_NATIVE))
    except OSError:
        return False
    return start == _ANY_NATIVE or bool(_tokens_beside(path))


class _Finder:
    """Walks the folders given to import, bounded in depth and count, never following links."""

    def __init__(self, recursive: bool):
        self.recursive = recursive
        self.seen = 0
        self.notes: List[str] = []
        self.skip = lib.library_root()

    def manifests(self, folder: Path) -> Iterator[Path]:
        pending: List[Tuple[Path, int]] = [(folder, 0)]
        while pending:
            current, depth = pending.pop()
            if _inside(current, self.skip):
                continue
            try:
                entries = sorted(os.scandir(current), key=lambda entry: entry.name, reverse=True)
            except OSError as exc:
                self.notes.append(f"could not look in {current}: {exc.strerror or exc}")
                continue
            for entry in entries:
                self.seen += 1
                if self.seen > MAX_IMPORT_ENTRIES:
                    self.notes.append(f"stopped looking after {MAX_IMPORT_ENTRIES} files and folders; import fewer at once")
                    return
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if scan.is_link(entry, info):
                    continue
                if stat.S_ISDIR(info.st_mode):
                    if self.recursive and depth < MAX_IMPORT_DEPTH:
                        pending.append((Path(entry.path), depth + 1))
                elif stat.S_ISREG(info.st_mode) and _worth_reading(Path(entry.path)):
                    yield Path(entry.path)


def _import_one(library: Optional[Library], path: Path, explicit: bool, dry_run: bool) -> Imported:
    if _inside(path, lib.library_root()):
        return Imported(path, "skipped", reason="it is one of the library's own copies")
    try:
        data = lib.read_bounded(path, lib.MANIFEST)
    except LibraryError as exc:
        return Imported(path, "skipped", reason=str(exc))
    parsed = manifest.parse(data)
    if parsed.newer_version is not None:
        return Imported(path, "skipped", reason=f"it uses manifest format v{parsed.newer_version}, which this version cannot read")
    if parsed.kind == manifest.NATIVE and parsed.problems:
        return Imported(path, "skipped", reason=f"it is damaged: {parsed.problems[0]}")
    notes: List[str] = []
    usable = []
    for token_path, current in [(item, True) for item in _tokens_beside(path)] + [(item, False) for item in _replaced_beside(path)]:
        try:
            token, request, root = lib.read_token_files(token_path)
            lib.token_facts(token, data)
        except LibraryError as exc:
            notes.append(f"the token {token_path.name} was skipped: {exc}")
            continue
        usable.append((token_path, token, request, root, current))
    if parsed.kind == manifest.HAND_MADE and not usable and not (explicit and parsed.entries):
        reason = "it lists no hashes this tool can read" if not parsed.entries else "no token beside it covers it"
        return Imported(path, "skipped", reason=reason + ", so it was not taken for a manifest", notes=notes)
    sha = hashlib.sha256(data).hexdigest()
    folder = verification.find_folder(parsed, path, None)
    if dry_run:
        known = library is not None and library.seal(sha) is not None
        known_tokens = {token["token_sha256"] for token in library.tokens(sha)} if known and library else set()
        new = sum(1 for item in usable if hashlib.sha256(item[1]).hexdigest() not in known_tokens)
        return Imported(path, "known" if known else "added", sha, tokens_added=new, notes=notes)
    assert library is not None
    sha, added = library.add_seal(data, path, folder, "imported", f"imported from {path}")
    count = 0
    for token_path, token, request, root, current in usable:
        if library.add_token(sha, data, token, token_path, request, root, current, event="imported"):
            count += 1
    return Imported(path, "added" if added else "known", sha, tokens_added=count, notes=notes)


def action_import(args: argparse.Namespace) -> int:
    for path in args.paths:
        if not path.exists():
            raise UsageError(f"{path} does not exist")
    finder = _Finder(args.recursive)
    chosen: List[Tuple[Path, bool]] = []
    keys = set()
    for path in args.paths:
        found = [(path, True)] if path.is_file() else [(item, False) for item in finder.manifests(path)]
        for item, explicit in found:
            key = sealing.path_key(item)
            if key not in keys:
                keys.add(key)
                chosen.append((Path(os.path.abspath(item)), explicit))
    opened = lib.open_library(create=not args.dry_run) if chosen else None
    try:
        results = [_import_one(opened, item, explicit, args.dry_run) for item, explicit in chosen]
    finally:
        if opened is not None:
            opened.close()
    if args.json:
        _print_json(
            {
                "schema_version": JSON_SCHEMA_VERSION,
                "dry_run": args.dry_run,
                "results": [item.to_dict() for item in results],
                "notes": finder.notes,
            }
        )
    else:
        _print_import(results, finder, args)
    return EXIT_FAILED if any(item.status == "skipped" for item in results) else EXIT_VERIFIED


def _print_import(results: List[Imported], finder: _Finder, args: argparse.Namespace) -> None:
    if args.dry_run:
        say("Dry run: nothing was written. This is what import would do.")
    words = {"added": "Added", "known": "Known", "skipped": "Skipped"}
    if args.dry_run:
        words["added"] = "Would add"
    for item in results:
        if item.status == "skipped":
            say(f"{words['skipped']:<9}  {item.path}: {item.reason}")
        else:
            tokens = count_of(item.tokens_added, "new token" if item.status == "known" else "token")
            say(f"{words[item.status]:<9}  {lib.short_id(item.sha or '')}  {item.path} ({tokens})")
        for note in item.notes:
            say(f"           {note}")
    for note in finder.notes:
        say(f"Note: {note}")
    if not results:
        hint = "" if args.recursive else " Add --recursive to look in the folders inside too."
        say(f"No manifests were found.{hint}")
        return
    added = sum(1 for item in results if item.status == "added")
    known = sum(1 for item in results if item.status == "known")
    skipped = sum(1 for item in results if item.status == "skipped")
    tokens = sum(item.tokens_added for item in results)
    verb = "Would add" if args.dry_run else "Added"
    say(f"{verb} {count_of(added, 'seal')} and {count_of(tokens, 'token')}; {known} already known; {skipped} skipped.")
    if not args.dry_run:
        say("Only the library was written. Your files were not changed.")


# verify -------------------------------------------------------------------------------------------


@dataclass
class Checked:
    sha: str
    outcome: Optional[Verification]
    reason: str

    @property
    def overall(self) -> str:
        return self.outcome.overall if self.outcome is not None else INCOMPLETE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": lib.short_id(self.sha),
            "manifest_sha256": self.sha,
            "overall": self.overall,
            "reason": self.reason or None,
            "verification": self.outcome.to_dict() if self.outcome is not None else None,
        }


def _reason(outcome: Verification) -> str:
    for check in outcome.checks:
        if check.status is not Status.PASS:
            return f"{check.title}: {check.detail}"
    return ""


def _own_file_rules(folder: Path, paths: List[Optional[str]]) -> List[scan.ExcludeItem]:
    """The seal's own files, wherever they last were inside the folder, are not new files in it."""
    rules: List[scan.ExcludeItem] = []
    for text in paths:
        if text:
            rules.extend(sealing.own_file_rules(Path(folder).resolve(), Path(text).resolve()))
    return rules


def _verify_one(
    library: Library,
    sha: str,
    folder_override: Optional[Path],
    ca: List[Path],
    report: Optional[Callable[[scan.Meter], None]] = None,
) -> Checked:
    """Verifies one seal from the library's copies and records the run. Progress goes to ``report``
    when one is given, and to the terminal otherwise."""
    row = library.seal(sha)
    token = library.current_token(sha)
    try:
        manifest_bytes = library.read_object(sha, lib.MANIFEST)
        token_bytes = library.read_object(token["token_sha256"], lib.TOKEN) if token else None
        request_bytes = library.read_object(token["request_sha256"], lib.REQUEST) if token and token["request_sha256"] else None
    except LibraryError as exc:
        return Checked(sha, None, str(exc))
    folder_text = str(folder_override) if folder_override is not None else row["folder_path"]
    folder = Path(folder_text) if folder_text and Path(folder_text).is_dir() else None
    scratch = tempfile.mkdtemp(prefix="verify-", dir=str(library.root))
    meter = progress("Checked") if report is None else None
    try:
        copy = Path(scratch) / "manifest.txt"
        sealing.write_new_file(copy, manifest_bytes)
        token_copy = query_copy = None
        if token_bytes is not None:
            token_copy = sealing.token_path_for(copy)
            sealing.write_new_file(token_copy, token_bytes)
        if request_bytes is not None:
            query_copy = sealing.query_path_for(copy)
            sealing.write_new_file(query_copy, request_bytes)
        known_paths = [row["manifest_path"]] + [item["token_path"] for item in library.tokens(sha)]
        options = verification.VerifyOptions(
            manifest_path=copy,
            token_path=token_copy,
            folder=folder,
            ca_files=ca,
            query_path=query_copy,
            excludes=_own_file_rules(folder, known_paths) if folder else (),
            skip_files=folder is None,
            report=report or meter,
        )
        outcome = verification.verify(options)
    except EvidenceSealError as exc:
        return Checked(sha, None, str(exc))
    finally:
        clear_progress(meter)
        shutil.rmtree(scratch, ignore_errors=True)
    if folder is None:
        if folder_text:
            detail = f"the folder {folder_text} is gone; pass --folder with where it is now"
        else:
            detail = "the library does not know where the folder is; pass --folder"
        outcome.files = Check(verification.FILES, "Files match the manifest", Status.NOT_CHECKED, detail)
    if token is None:
        outcome.token_checks = [
            Check(
                verification.TOKEN,
                "A timestamp token was found",
                Status.NOT_CHECKED,
                "the library has no token for this seal; stamp the manifest, or import the folder its token is in",
            )
        ]
    outcome.manifest_name = Path(row["manifest_path"]).name if row["manifest_path"] else outcome.manifest_name
    if token is not None and token["token_path"]:
        outcome.token_name = Path(token["token_path"]).name
    library.add_run(sha, token["token_sha256"] if token else None, LIBRARY_VERIFY, outcome)
    return Checked(sha, outcome, _reason(outcome))


def verify_seal(
    library: Library,
    sha: str,
    folder: Optional[Path] = None,
    report: Optional[Callable[[scan.Meter], None]] = None,
) -> Checked:
    """What ``library verify`` does for one seal: the same check from the library's copies, recorded the same way."""
    return _verify_one(library, sha, folder, [], report)


def _worst(results: List[Checked]) -> int:
    if any(item.overall == FAILED for item in results):
        return EXIT_FAILED
    if not results or any(item.overall == INCOMPLETE for item in results):
        return EXIT_INCOMPLETE
    return EXIT_VERIFIED


def action_verify(args: argparse.Namespace) -> int:
    if args.all and args.ids:
        raise UsageError("give seal IDs or --all, not both")
    if not args.all and not args.ids:
        raise UsageError("say which seals to verify: give one or more IDs, or --all")
    if args.folder is not None and (args.all or len(args.ids) > 1):
        raise UsageError("--folder works with one seal at a time")
    if args.folder is not None and not args.folder.is_dir():
        raise UsageError(f"{args.folder} is not a folder")
    try:
        TrustStore.from_files(args.ca)
    except EvidenceSealError as exc:
        raise UsageError(str(exc)) from None
    with _existing() as found:
        if found is None:
            if args.ids:
                _required(found, args.ids[0])
            shas: List[str] = []
        else:
            shas = [row["manifest_sha256"] for row in found.seals()] if args.all else []
            for text in args.ids:
                sha = found.resolve(text)
                if sha not in shas:
                    shas.append(sha)
        results = [_verify_one(found, sha, args.folder, args.ca) for sha in shas] if found is not None else []
        token_times = {sha: (found.current_token(sha) or {}).get("token_time") for sha in shas} if found else {}
    code = _worst(results)
    if args.json:
        _print_json(
            {
                "schema_version": JSON_SCHEMA_VERSION,
                "exit_code": code,
                "results": [item.to_dict() for item in results],
            }
        )
        return code
    if not results:
        say("The library has no seals to verify, so nothing was verified.")
        return code
    say(f"{'ID':<12}  {'RESULT':<10}  {'TOKEN TIME':<23}  REASON")
    for item in results:
        say(f"{lib.short_id(item.sha):<12}  {item.overall:<10}  {_cut(token_times.get(item.sha), 23):<23}  {_cut(item.reason, 400) if item.reason else ''}")
    counts = {word: sum(1 for item in results if item.overall == word) for word in ("VERIFIED", FAILED, INCOMPLETE)}
    say(f"{counts['VERIFIED']} verified, {counts[FAILED]} failed, {counts[INCOMPLETE]} incomplete. Each one that reached a result was recorded.")
    say("library show ID lists every check of each run, and --json gives every detail.")
    return code


ACTIONS: Dict[str, Callable[[argparse.Namespace], int]] = {
    "list": action_list,
    "show": action_show,
    "import": action_import,
    "verify": action_verify,
    "check": action_check,
    "forget": action_forget,
    "tag": action_tag,
    "untag": action_tag,
    "log": action_log,
    "where": action_where,
}
