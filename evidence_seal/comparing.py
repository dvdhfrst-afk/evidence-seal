"""The diff command: compares two file lists, from manifests or from a folder hashed now.

It compares names, sizes and SHA-256 hashes, and nothing else: it checks no token and proves no date.
A file whose exact bytes turn up under a new name counts as moved. A name that differs only in its
Unicode form is matched, as verify matches it, and a note says how many were.

For other parts of the tool: ``listing_of_manifest``, ``listing_of_folder``, ``compare`` and
``render_diff(comparison, format) -> bytes``.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

from . import hashes, manifest, scan, sealing
from .cli import add_exclude_options, exclude_rules
from .console import clear_progress, deliver, out_path, progress, say, warn
from .errors import EvidenceSealError, UsageError
from .results import EXIT_FAILED, EXIT_VERIFIED
from .text import count_of, csv_table, markdown_text, printable, same_text_form

DIFF_SCHEMA_VERSION = 1
DIFF_FORMATS = ("text", "json", "csv", "markdown")
UNCHANGED = "unchanged"
CHANGED = "changed"
ADDED = "added"
REMOVED = "removed"
MOVED = "moved"
OUTCOMES = (UNCHANGED, CHANGED, ADDED, REMOVED, MOVED)
LISTS_ONLY = "This compares lists of names, sizes and SHA-256 hashes only. It checks no token and proves no date."
CSV_COLUMNS = ("path", "outcome", "new_path", "old_sha256", "new_sha256", "old_size", "new_size")


@dataclass
class Listing:
    """One side of a comparison. ``files`` maps each path to its SHA-256 and size, when the size is known."""

    label: str
    kind: str
    files: Dict[str, Tuple[str, Optional[int]]]
    by_name_only: int = 0


@dataclass
class Change:
    outcome: str
    path: str
    new_path: Optional[str] = None
    old_sha256: Optional[str] = None
    new_sha256: Optional[str] = None
    old_size: Optional[int] = None
    new_size: Optional[int] = None


@dataclass
class Comparison:
    old: Listing
    new: Listing
    changes: List[Change] = field(default_factory=list)
    other_unicode_forms: int = 0
    notes: List[str] = field(default_factory=list)

    def of(self, outcome: str) -> List[Change]:
        return [change for change in self.changes if change.outcome == outcome]

    @property
    def counts(self) -> Dict[str, int]:
        return {outcome: len(self.of(outcome)) for outcome in OUTCOMES}

    @property
    def identical(self) -> bool:
        return all(change.outcome == UNCHANGED for change in self.changes)


def listing_of_manifest(path: Path, label: str, warn_about: Callable[[str], None]) -> Tuple[Listing, manifest.Manifest]:
    data = manifest.read_manifest(path)
    entries = manifest.sha256_entries(data, path.name, "diff")
    for problem in data.problems:
        warn_about(f"warning: {path.name} is inconsistent: {problem}. Its entries were compared as listed")
    if data.unreadable_lines:
        warn_about(f"warning: {count_of(data.unreadable_lines, 'line')} of {path.name} could not be read as hash lines")
    files = {entry.path: (entry.hexdigest, entry.size) for entry in entries}
    return Listing(label, f"{data.kind} manifest", files, len(data.links) + len(data.special)), data


def listing_of_folder(
    folder: Path,
    label: str,
    rules: Sequence[scan.ExcludeItem],
    report: Optional[Callable[[scan.Meter], None]] = None,
) -> Listing:
    """Walks and hashes the folder as seal would, with the same rules. A file that cannot be read stops it."""
    walked = scan.walk(folder, scan.Excludes(rules))
    scan.require_clean_walk(walked)
    total = scan.measure_and_open(walked.files)
    rows = scan.hash_all(walked.files, hashes.SHA256, scan.Meter(report, len(walked.files), total))
    files = {relative: (digest, size) for relative, digest, size in rows}
    return Listing(label, "folder, hashed now", files, len(walked.links) + len(walked.special))


def compare(old: Listing, new: Listing) -> Comparison:
    comparison = Comparison(old, new)
    changes = comparison.changes
    other_forms: Dict[str, str] = {}
    for path in sorted(new.files, key=scan.sort_key):
        if path not in old.files and not path.isascii():
            other_forms.setdefault(same_text_form(path), path)
    matched: Set[str] = set()
    gone: List[str] = []
    for path in sorted(old.files, key=scan.sort_key):
        old_hash, old_size = old.files[path]
        found = path if path in new.files else None
        if found is None and not path.isascii():
            candidate = other_forms.get(same_text_form(path))
            if candidate is not None and candidate not in matched:
                found = candidate
                comparison.other_unicode_forms += 1
        if found is None:
            gone.append(path)
            continue
        matched.add(found)
        new_hash, new_size = new.files[found]
        same = new_hash == old_hash and (old_size is None or new_size is None or old_size == new_size)
        changes.append(
            Change(
                UNCHANGED if same else CHANGED,
                path,
                found if found != path else None,
                old_hash,
                new_hash,
                old_size,
                new_size,
            )
        )
    arrived = [path for path in sorted(new.files, key=scan.sort_key) if path not in matched]
    by_hash: Dict[str, List[str]] = {}
    for path in arrived:
        by_hash.setdefault(new.files[path][0], []).append(path)
    moved_to: Set[str] = set()
    for path in gone:
        old_hash, old_size = old.files[path]
        candidates = by_hash.get(old_hash)
        if candidates:
            target = candidates.pop(0)
            moved_to.add(target)
            changes.append(Change(MOVED, path, target, old_hash, old_hash, old_size, new.files[target][1]))
        else:
            changes.append(Change(REMOVED, path, None, old_hash, None, old_size, None))
    for path in arrived:
        if path not in moved_to:
            new_hash, new_size = new.files[path]
            changes.append(Change(ADDED, path, None, None, new_hash, None, new_size))
    changes.sort(key=lambda change: scan.sort_key(change.path))
    if comparison.other_unicode_forms:
        comparison.notes.append(
            f"{count_of(comparison.other_unicode_forms, 'file')} matched under another Unicode form of the same name,"
            " which copying between systems can cause. Their hashes were compared as usual."
        )
    if old.by_name_only or new.by_name_only:
        comparison.notes.append(
            f"Links and special files are not compared. {old.label} lists {old.by_name_only},"
            f" and {new.label} has {new.by_name_only}."
        )
    return comparison


def _summary(comparison: Comparison) -> str:
    if comparison.identical:
        return f"The lists are identical: {count_of(len(comparison.changes), 'file')}, all unchanged."
    counts = comparison.counts
    parts = ", ".join(f"{counts[outcome]} {outcome}" for outcome in OUTCOMES)
    return f"The lists differ: {parts}."


def _describe(change: Change) -> str:
    if change.outcome == MOVED:
        return f"{change.path} -> {change.new_path}"
    if change.new_path is not None:
        return f"{change.path} (now named {change.new_path}, the same name in another Unicode form)"
    return change.path


def _text(comparison: Comparison) -> bytes:
    lines = [
        f"Old: {comparison.old.label} ({comparison.old.kind}, {count_of(len(comparison.old.files), 'file')})",
        f"New: {comparison.new.label} ({comparison.new.kind}, {count_of(len(comparison.new.files), 'file')})",
        LISTS_ONLY,
        "",
        f"Unchanged: {comparison.counts[UNCHANGED]}",
    ]
    for outcome in (CHANGED, ADDED, REMOVED, MOVED):
        found = comparison.of(outcome)
        lines.append(f"{outcome.capitalize()}: {len(found)}")
        lines.extend(f"  {_describe(change)}" for change in found)
    if comparison.notes:
        lines.extend(["", "NOTES"])
        lines.extend(f"  {note}" for note in comparison.notes)
    lines.extend(["", _summary(comparison)])
    return ("\n".join(printable(line) for line in lines) + "\n").encode("utf-8")


def _json(comparison: Comparison) -> bytes:
    def side(listing: Listing) -> Dict[str, object]:
        return {"name": listing.label, "kind": listing.kind, "file_count": len(listing.files)}

    document = {
        "diff_schema": DIFF_SCHEMA_VERSION,
        "identical": comparison.identical,
        "old": side(comparison.old),
        "new": side(comparison.new),
        "counts": comparison.counts,
        "changes": [change.__dict__ for change in comparison.changes],
        "matched_under_another_unicode_form": comparison.other_unicode_forms,
        "notes": comparison.notes,
        "about": LISTS_ONLY,
    }
    return (json.dumps(document, indent=2) + "\n").encode("ascii")


def _csv(comparison: Comparison) -> bytes:
    escape = manifest.escape_text
    return csv_table(
        CSV_COLUMNS,
        (
            (
                escape(change.path),
                change.outcome,
                escape(change.new_path) if change.new_path is not None else "",
                change.old_sha256 or "",
                change.new_sha256 or "",
                "" if change.old_size is None else change.old_size,
                "" if change.new_size is None else change.new_size,
            )
            for change in comparison.changes
        ),
    )


def _markdown(comparison: Comparison) -> bytes:
    m = markdown_text
    lines = [
        "# File list comparison",
        "",
        f"- Old: {m(comparison.old.label)} ({m(comparison.old.kind)}, {count_of(len(comparison.old.files), 'file')})",
        f"- New: {m(comparison.new.label)} ({m(comparison.new.kind)}, {count_of(len(comparison.new.files), 'file')})",
        "",
        LISTS_ONLY,
        "",
        f"**{m(_summary(comparison))}**",
        "",
        "| Outcome | Files |",
        "| --- | --- |",
    ]
    lines.extend(f"| {outcome} | {count} |" for outcome, count in comparison.counts.items())
    for outcome in (CHANGED, ADDED, REMOVED, MOVED):
        found = comparison.of(outcome)
        if not found:
            continue
        lines.extend(["", f"## {outcome.capitalize()}", ""])
        for change in found:
            if change.outcome == MOVED:
                lines.append(f"- {m(change.path)} moved to {m(change.new_path)}")
            else:
                lines.append(f"- {m(change.path)}")
    if comparison.notes:
        lines.extend(["", "## Notes", ""])
        lines.extend(f"- {m(note)}" for note in comparison.notes)
    return ("\n".join(lines) + "\n").encode("utf-8")


_RENDERERS: Dict[str, Callable[[Comparison], bytes]] = {
    "text": _text,
    "json": _json,
    "csv": _csv,
    "markdown": _markdown,
}


def render_diff(comparison: Comparison, form: str) -> bytes:
    return _RENDERERS[form](comparison)


def _run(args: argparse.Namespace) -> int:
    if args.old.is_dir():
        raise UsageError(f"{args.old} is a folder. OLD must be a manifest; NEW may be a manifest or a folder")
    for given in (args.old, args.new):
        if not given.exists():
            raise UsageError(f"{given} does not exist")
    target = out_path(args.out)
    if target is not None:
        protected = sealing.files_of(args.old) + ([] if args.new.is_dir() else sealing.files_of(args.new))
        sealing.refuse_to_replace(target, protected, "the comparison")
    user_rules = exclude_rules(args)
    old, old_data = listing_of_manifest(args.old, str(args.old), warn)
    if args.new.is_dir():
        folder = args.new.resolve()
        rules = list(old_data.excludes) + list(user_rules) + sealing.own_file_rules(folder, args.old.resolve())
        report = progress("Hashed")
        try:
            new = listing_of_folder(folder, str(args.new), rules, report)
        finally:
            clear_progress(report)
    else:
        new = listing_of_manifest(args.new, str(args.new), warn)[0]
    if user_rules:
        leave_out = scan.Excludes(user_rules)
        for listing in (old, new):
            listing.files = {path: value for path, value in listing.files.items() if not leave_out.matches(path)}
    comparison = compare(old, new)
    deliver(render_diff(comparison, args.format), target, args.force)
    if target is not None:
        say(f"Comparison: {target}")
        say(_summary(comparison))
    return EXIT_VERIFIED if comparison.identical else EXIT_FAILED


def command_diff(args: argparse.Namespace) -> int:
    try:
        return _run(args)
    except UsageError:
        raise
    except EvidenceSealError as exc:
        # Exit code 1 means the lists differ, so any error, such as an unreadable file, must be 2.
        raise UsageError(str(exc)) from None


def register(commands) -> Dict[str, Callable[[argparse.Namespace], int]]:
    parser = commands.add_parser(
        "diff",
        help="compare two manifests, or a manifest and a folder; checks no token",
        description=(
            "Compare the file lists of two manifests, or of a manifest and a folder hashed now, and list what is"
            " unchanged, changed, added, removed or moved. Stays offline. It compares lists only:"
            " it checks no token and proves no date."
        ),
        epilog="exit codes: 0 the lists are identical, 1 they differ, 2 bad arguments or a file that cannot be read",
        allow_abbrev=False,
    )
    parser.add_argument("old", type=Path, help="the earlier manifest")
    parser.add_argument("new", type=Path, help="a later manifest, or a folder to hash now")
    add_exclude_options(
        parser, "leave matching paths out of both lists, and out of the folder walk; can repeat"
    )
    parser.add_argument("--format", choices=DIFF_FORMATS, default="text", help="output format (default: %(default)s)")
    parser.add_argument("--out", help="file to write, or - for standard output (default: standard output)")
    parser.add_argument("--force", action="store_true", help="replace an existing file; never a manifest or its companions")
    return {"diff": command_diff}
