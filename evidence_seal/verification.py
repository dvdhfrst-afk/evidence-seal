"""The verify command: files against the manifest, and the token against the manifest."""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

from . import __version__, authorities, manifest, scan, sealing, tokencheck
from .errors import CertificateFileError, UsageError
from .manifest import Entry, Manifest
from .results import (
    ADDED,
    CHANGED,
    MISSING,
    MOVED,
    NOT_COMPARED,
    UNCHANGED,
    UNREADABLE,
    Check,
    FileDifferences,
    FileRow,
    Status,
    Verification,
)
from .text import count_of, same_text_form
from .trust import TrustStore
from .x509 import Certificate, load_certificates

FILES = "files"
TOKEN = "token"

LIMITS = (
    "Certificate revocation: this tool works offline and does not ask the authority whether a certificate was revoked.",
    "Authorship: a timestamp shows the data existed by that time, not who wrote it.",
)

_ABSOLUTE = re.compile(r"^(?:[A-Za-z]:)?/")


@dataclass
class VerifyOptions:
    manifest_path: Path
    token_path: Optional[Path] = None
    folder: Optional[Path] = None
    ca_files: Sequence[Path] = ()
    untrusted_files: Sequence[Path] = ()
    query_path: Optional[Path] = None
    excludes: Sequence[scan.ExcludeItem] = ()
    allow_added: bool = False
    skip_files: bool = False
    cross_check: bool = False
    now: Optional[datetime] = None
    report: Optional[Callable[[scan.Meter], None]] = None


def _existing_token(manifest_path: Path) -> Optional[Path]:
    candidates = [
        sealing.token_path_for(manifest_path),
        manifest_path.with_name(manifest_path.name + sealing.TOKEN_SUFFIX),
        manifest_path.with_suffix(".tst"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _find_folder(data: Manifest, manifest_path: Path, explicit: Optional[Path]) -> Optional[Path]:
    if explicit is not None:
        if not Path(explicit).is_dir():
            raise UsageError(f"{explicit} is not a folder")
        return Path(explicit)
    base = manifest_path.resolve().parent
    if data.kind == manifest.HAND_MADE:
        return base
    name = data.folder_name
    if not name or name in (".", "..") or "/" in name or "\\" in name or (os.name == "nt" and ":" in name):
        return None
    if (base / name).is_dir():
        return base / name
    if same_text_form(base.name) == same_text_form(name):
        return base
    try:
        for entry in os.scandir(base):
            if same_text_form(entry.name) == same_text_form(name) and entry.is_dir():
                return Path(entry.path)
    except OSError:
        return None
    return None


def _relative_entry_path(entry: Entry, folder: Path) -> Optional[str]:
    """Paths are looked up among walked files and never opened directly from the manifest."""
    if not _ABSOLUTE.match(entry.path):
        return entry.path
    try:
        return Path(entry.path).resolve().relative_to(folder.resolve()).as_posix()
    except (ValueError, OSError):
        return None


def compare_folder(
    data: Manifest,
    folder: Path,
    excludes: Sequence[scan.ExcludeItem] = (),
    allow_added: bool = False,
    own_files: Sequence[Path] = (),
    report: Optional[Callable[[scan.Meter], None]] = None,
) -> Tuple[Check, FileDifferences]:
    """Re-hashes the folder and returns the files check and the list of differences."""
    differences = FileDifferences(total=len(data.entries))
    walked = scan.walk(folder, scan.Excludes(data.excludes))
    expected: Set[str] = set()
    missing_entries: Dict[str, Entry] = {}
    weak_seen = 0
    listed = {entry.path for entry in data.entries}
    other_forms = {
        same_text_form(name): name for name in walked.files if not name.isascii() and name not in listed
    }
    meter = scan.Meter(report, len(data.entries), data.total_bytes or 0)
    rows = differences.rows
    missing_rows: Dict[str, FileRow] = {}
    for entry in data.entries:
        row = FileRow(entry.path, UNREADABLE, entry.algorithm.display, entry.hexdigest, None, entry.size)
        rows.append(row)
        relative = _relative_entry_path(entry, folder)
        if relative is None:
            differences.unreadable.append(entry.path)
            continue
        expected.add(relative)
        found = walked.files.get(relative)
        if found is None and same_text_form(relative) in other_forms:
            actual = other_forms[same_text_form(relative)]
            found = walked.files[actual]
            expected.add(actual)
            differences.other_unicode_forms[relative] = actual
            row.found_path = actual
        if found is None:
            differences.missing.append(relative)
            missing_entries[relative] = entry
            missing_rows[relative] = row
            row.outcome = MISSING
            continue
        if entry.algorithm.weak:
            weak_seen += 1
        try:
            size = found.stat().st_size
            if entry.size is not None and size != entry.size:
                differences.changed.append(relative)
                row.outcome, row.found_size = CHANGED, size
                continue
            digest, row.found_size = scan.hash_file(found, entry.algorithm, meter)
        except OSError:
            differences.unreadable.append(relative)
            continue
        meter.add_file()
        row.found_hash = digest
        if digest == entry.hexdigest:
            differences.unchanged += 1
            row.outcome = UNCHANGED
        else:
            differences.changed.append(relative)
            row.outcome = CHANGED

    own = {sealing.path_key(path) for path in own_files}
    extra_rules = scan.Excludes(excludes)
    added_rows: Dict[str, FileRow] = {}
    for relative, found in walked.files.items():
        if relative in expected or extra_rules.matches(relative):
            continue
        if sealing.path_key(found) in own:
            differences.own_files.append(relative)
            continue
        differences.added.append(relative)
        try:
            added_rows[relative] = FileRow(relative, ADDED, found_size=found.stat().st_size)
        except OSError:
            added_rows[relative] = FileRow(relative, ADDED)
    recorded = {same_text_form(relative) for relative in data.links + data.special}
    for relative in walked.links + walked.special:
        if same_text_form(relative) not in recorded and not extra_rules.matches(relative):
            differences.added.append(relative)
            added_rows[relative] = FileRow(relative, ADDED)
    present = {same_text_form(relative) for relative in walked.links + walked.special}
    for relative in data.links + data.special:
        if same_text_form(relative) not in present:
            differences.missing.append(relative)
            rows.append(FileRow(relative, MISSING))
    differences.unreadable.extend(path for path, _ in walked.errors)
    rows.extend(FileRow(path, UNREADABLE) for path, _ in walked.errors)
    differences.changed.sort(key=scan.sort_key)
    differences.missing.sort(key=scan.sort_key)
    differences.added.sort(key=scan.sort_key)
    differences.own_files.sort(key=scan.sort_key)
    _hint_moves(differences, missing_entries, walked.files)
    for relative, new_path in differences.moved_hints.items():
        # One row stands for the missing name and the added name that now holds the same bytes.
        row = missing_rows[relative]
        row.outcome, row.found_path, row.found_hash = MOVED, new_path, row.expected_hash
        row.found_size = added_rows.pop(new_path).found_size if new_path in added_rows else row.expected_size
    rows.extend(added_rows.values())
    rows.sort(key=lambda item: scan.sort_key(item.path))
    return _files_check(data, differences, allow_added, weak_seen), differences


def _hint_moves(differences: FileDifferences, missing: Dict[str, Entry], files: Dict[str, Path]) -> None:
    """A missing file whose exact bytes turn up under a new name is worth pointing out."""
    candidates: Dict[int, List[str]] = {}
    for relative in differences.added:
        found = files.get(relative)
        if found is None:
            continue
        try:
            candidates.setdefault(found.stat().st_size, []).append(relative)
        except OSError:
            continue
    for relative, entry in missing.items():
        if entry.size is None:
            continue
        for option in candidates.get(entry.size, []):
            try:
                digest, _ = scan.hash_file(files[option], entry.algorithm)
            except OSError:
                continue
            if digest == entry.hexdigest:
                differences.moved_hints[relative] = option
                break


def _files_check(data: Manifest, differences: FileDifferences, allow_added: bool, weak_seen: int) -> Check:
    title = "Files match the manifest"
    summary = (
        f"{differences.unchanged} of {differences.total} listed files unchanged, {len(differences.changed)} changed,"
        f" {len(differences.missing)} missing, {len(differences.added)} added"
    )
    if differences.unreadable:
        summary += f", {len(differences.unreadable)} could not be read"
    if data.problems:
        return Check(FILES, title, Status.FAIL, f"the manifest is inconsistent: {data.problems[0]}")
    if not data.entries:
        return Check(FILES, title, Status.NOT_CHECKED, "the manifest lists no files in a form this tool can read")
    if differences.changed or differences.missing:
        return Check(FILES, title, Status.FAIL, summary)
    if differences.added and not allow_added:
        return Check(FILES, title, Status.FAIL, summary + " (every listed file still matches)")
    if differences.unreadable:
        return Check(FILES, title, Status.NOT_CHECKED, summary)
    if data.unreadable_lines:
        return Check(FILES, title, Status.NOT_CHECKED, summary + f"; {data.unreadable_lines} hash lines could not be read")
    if weak_seen:
        return Check(
            FILES,
            title,
            Status.NOT_CHECKED,
            summary + f"; {weak_seen} entries use a hash that is no longer collision resistant",
        )
    return Check(FILES, title, Status.PASS, summary)


def _read_optional(path: Path, what: str) -> bytes:
    return manifest.read_limited(path, what, manifest.MAX_SIDE_FILE_BYTES)


def _load_certificates(paths: Sequence[Path]) -> List[Certificate]:
    found: List[Certificate] = []
    for path in paths:
        found.extend(load_certificates(path))
    return found


def verify(options: VerifyOptions) -> Verification:
    now = options.now or datetime.now(timezone.utc)
    manifest_path = Path(options.manifest_path)
    if manifest_path.is_dir():
        raise UsageError(f"{manifest_path} is a folder. Give the manifest file that seal wrote, and --folder if needed")
    if not manifest_path.is_file():
        raise UsageError(f"manifest {manifest_path} does not exist")
    data = manifest.read_manifest(manifest_path)
    try:
        store = TrustStore.from_files(options.ca_files) if options.ca_files else authorities.default_store()
        untrusted = _load_certificates(options.untrusted_files)
    except CertificateFileError as exc:
        raise UsageError(str(exc)) from None

    token_path = Path(options.token_path) if options.token_path else _existing_token(manifest_path)
    if options.token_path and not Path(options.token_path).is_file():
        raise UsageError(f"token {options.token_path} does not exist")
    query_path = Path(options.query_path) if options.query_path else None
    if query_path is None and token_path is not None and token_path.with_suffix(sealing.QUERY_SUFFIX).is_file():
        # The request saved with this token, which is not the manifest's if a second token was made with --out.
        query_path = token_path.with_suffix(sealing.QUERY_SUFFIX)

    differences: Optional[FileDifferences] = None
    folder = None
    notes: List[str] = []
    if options.skip_files:
        files_check = Check(FILES, "Files match the manifest", Status.NOT_CHECKED, "skipped at your request")
    elif data.newer_version is not None:
        files_check = Check(
            FILES,
            "Files match the manifest",
            Status.NOT_CHECKED,
            f"this manifest uses format v{data.newer_version}, and evidence-seal {__version__} reads format"
            f" v{manifest.FORMAT_VERSION}. Use a version of evidence-seal that reads it; nothing here is damaged",
        )
    else:
        folder = _find_folder(data, manifest_path, options.folder)
        if folder is None:
            files_check = Check(
                FILES,
                "Files match the manifest",
                Status.NOT_CHECKED,
                f"the folder {data.folder_name or ''} was not found beside the manifest; pass it with --folder",
            )
        else:
            own = [manifest_path] + sealing.companion_paths(manifest_path)
            own += ([token_path] if token_path else []) + ([query_path] if query_path else [])
            own += list(options.ca_files) + list(options.untrusted_files)
            own += sealing.kept_copies(manifest_path) + (sealing.kept_copies(token_path) if token_path else [])
            files_check, differences = compare_folder(
                data,
                folder,
                options.excludes,
                options.allow_added,
                own,
                options.report,
            )
    if differences is not None and differences.own_files:
        notes.append(
            "In the folder but not compared, as the manifest's own companion files or files named in this command: "
            + ", ".join(differences.own_files)
        )
    if differences is not None and differences.other_unicode_forms:
        notes.append(
            f"{count_of(len(differences.other_unicode_forms), 'file')} matched under another Unicode form of the same"
            " name, which copying between systems can cause. The contents were compared as usual."
        )
    if data.excludes:
        notes.append(
            "Not covered by this seal: anything matching the manifest's exclude patterns: " + ", ".join(data.excludes)
        )
    if data.links or data.special:
        notes.append(
            f"The manifest lists {len(data.links) + len(data.special)} links or special files by name only."
            " Their targets and contents are not covered."
        )
    if data.note_lines:
        notes.append(f"{data.note_lines} lines of the manifest are free text. They are covered by the token as written.")

    report: Optional[tokencheck.TokenReport] = None
    test_authority = None
    if token_path is None:
        token_checks = [
            Check(
                TOKEN,
                "A timestamp token was found",
                Status.NOT_CHECKED,
                f"no token beside the manifest (looked for {sealing.token_path_for(manifest_path).name}); pass --token",
            )
        ]
    else:
        report = tokencheck.check_token(
            _read_optional(token_path, "token"),
            data.raw,
            store,
            untrusted,
            _read_optional(query_path, "request") if query_path else None,
            now,
            options.cross_check,
            manifest_path,
            token_path,
        )
        token_checks = report.checks
        notes.extend(report.notes)
        test_authority = authorities.test_authority_for(_token_certificates(report))
        if report.facts and report.facts.time and data.created and report.response and report.response.tst_info:
            stamped = report.response.tst_info.gen_time
            if _created_after(data.created, stamped):
                notes.append(
                    f"The manifest's created field ({data.created}) is later than the token's time."
                    " The created field is only a claim by whoever made the manifest."
                )

    return Verification(
        manifest_name=manifest_path.name,
        manifest_sha256=hashlib.sha256(data.raw).hexdigest(),
        manifest_kind=data.kind,
        token_name=token_path.name if token_path else None,
        folder=str(folder) if folder else None,
        purpose=data.purpose,
        created=data.created,
        file_count=len(data.entries),
        total_bytes=data.total_bytes,
        files=files_check,
        differences=differences,
        token_checks=token_checks,
        facts=report.facts if report else None,
        notes=notes,
        limits=list(LIMITS),
        anchor_certificates=report.roots if report else [],
        checked_at=tokencheck.format_time(now),
        tool_version=__version__,
        test_authority=test_authority,
        file_rows=differences.rows if differences is not None else _rows_not_compared(data),
    )


def _rows_not_compared(data: Manifest) -> List[FileRow]:
    return [
        FileRow(entry.path, NOT_COMPARED, entry.algorithm.display, entry.hexdigest, None, entry.size)
        for entry in data.entries
    ]


def _token_certificates(report: tokencheck.TokenReport) -> List[Certificate]:
    """The certificates this token carries, and the chain it was checked along."""
    carried = []
    if report.response is not None and report.response.signed_data is not None:
        carried = list(report.response.signed_data.certificates)
    return carried + report.chain


def _created_after(created: str, stamped: datetime) -> bool:
    try:
        if len(created) == 10:
            moment = datetime.strptime(created, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        else:
            moment = datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return moment > stamped
