"""The seal command: walk a folder and write its manifest."""

from __future__ import annotations

import glob
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from . import hashes, manifest, scan
from .errors import ManifestError, SealError, UsageError

TOKEN_SUFFIX = ".tsr"
QUERY_SUFFIX = ".tsq"
ROOT_SUFFIX = ".ca.crt"
REPORT_TEXT_SUFFIX = ".report.txt"
REPORT_HTML_SUFFIX = ".report.html"
OWN_FILES = "the manifest's own files"
COMPANION_SUFFIXES = (TOKEN_SUFFIX, QUERY_SUFFIX, ROOT_SUFFIX, REPORT_TEXT_SUFFIX, REPORT_HTML_SUFFIX)


@dataclass
class SealResult:
    manifest_path: Path
    file_count: int
    total_bytes: int
    links: List[str]
    special: List[str]
    excluded: List[str]
    excludes: List[str]
    unmatched: List[scan.ExcludeRule] = field(default_factory=list)


@dataclass
class SealPreview:
    """What a seal would cover, with no file opened and nothing written."""

    folder: Path
    manifest_path: Path
    manifest_exists: bool
    files: List[Tuple[str, int]]
    total_bytes: int
    links: List[str]
    special: List[str]
    left_out: List[Tuple[str, scan.ExcludeRule]]
    unmatched: List[scan.ExcludeRule]
    errors: List[Tuple[str, str]]


def normalize_created(value: Optional[str], now: Optional[datetime] = None) -> str:
    """The created field. It is a claim by whoever ran seal, and only the token proves a date."""
    if value is None:
        moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        return moment.strftime("%Y-%m-%dT%H:%M:%SZ")
    for pattern in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            datetime.strptime(value, pattern)
            return value
        except ValueError:
            continue
    raise UsageError(f"--date must look like 2026-01-31 or 2026-01-31T09:30:00Z, not {value!r}")


def default_manifest_path(folder: Path, created: str) -> Path:
    """Beside the folder, not inside it, so sealing does not change what is sealed."""
    if not folder.name:
        raise UsageError("cannot place a manifest beside the top of a drive; use --out")
    return folder.parent / f"{folder.name}-manifest-{created[:10]}.txt"


def write_new_file(path: Path, data: bytes, force: bool = False) -> None:
    """Writes through a temporary file so a crash cannot leave half a manifest or token."""
    path = Path(path)
    if path.exists() and not force:
        raise ManifestError(f"{path} already exists; use --force to replace it, or choose another name")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        handle, temp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    except OSError as exc:
        raise ManifestError(f"cannot write {path}: {exc.strerror or exc}") from None
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
        os.replace(temp_name, path)
    except OSError as exc:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise ManifestError(f"cannot write {path}: {exc.strerror or exc}") from None


def _sidecar_excludes(folder: Path, manifest_path: Path) -> List[Tuple[str, str]]:
    """If the manifest lives inside the folder, it and its companions are not part of the seal."""
    try:
        relative = manifest_path.relative_to(folder)
    except ValueError:
        return []
    names = [relative] + [relative.with_suffix(suffix) for suffix in COMPANION_SUFFIXES]
    return [(f"/{glob.escape(name.as_posix())}", OWN_FILES) for name in names]


def _your_unmatched(rules: scan.Excludes) -> List[scan.ExcludeRule]:
    return [rule for rule in rules.unmatched() if rule.source != OWN_FILES]


def _resolve_paths(
    folder: Path, excludes: Sequence[scan.ExcludeItem], out: Optional[Path], created_text: str
) -> Tuple[Path, Path, scan.Excludes]:
    folder = Path(folder).resolve()
    if not folder.is_dir():
        raise UsageError(f"{folder} is not a folder")
    manifest_path = Path(out).resolve() if out else default_manifest_path(folder, created_text)
    return folder, manifest_path, scan.Excludes(list(excludes) + _sidecar_excludes(folder, manifest_path))


def preview_folder(
    folder: Path,
    excludes: Sequence[scan.ExcludeItem] = (),
    out: Optional[Path] = None,
    created: Optional[str] = None,
) -> SealPreview:
    folder, manifest_path, rules = _resolve_paths(folder, excludes, out, normalize_created(created))
    walked = scan.walk(folder, rules)
    files: List[Tuple[str, int]] = []
    errors = list(walked.errors)
    for relative in sorted(walked.files, key=scan.sort_key):
        try:
            files.append((relative, walked.files[relative].stat().st_size))
        except OSError as exc:
            errors.append((relative, exc.strerror or str(exc)))
    left_out = []
    for relative in walked.excluded:
        is_folder = relative in walked.excluded_folders
        rule = rules.deciding_rule(relative, is_folder)
        left_out.append((relative + "/" if is_folder else relative, rule))
    return SealPreview(
        folder,
        manifest_path,
        manifest_path.exists(),
        files,
        sum(size for _, size in files),
        walked.links,
        walked.special,
        left_out,
        _your_unmatched(rules),
        errors,
    )


def seal_folder(
    folder: Path,
    purpose: str,
    excludes: Sequence[scan.ExcludeItem] = (),
    out: Optional[Path] = None,
    created: Optional[str] = None,
    force: bool = False,
) -> SealResult:
    if not purpose.strip():
        raise UsageError("--purpose must say why this seal is being made")
    created_text = normalize_created(created)
    folder, manifest_path, rules = _resolve_paths(folder, excludes, out, created_text)
    if manifest_path.exists() and not force:
        raise ManifestError(f"{manifest_path} already exists; use --force to replace it, or choose another name")
    walked = scan.walk(folder, rules)
    scan.require_clean_walk(walked)
    if not walked.files:
        raise SealError(f"{folder} has no files to seal after excludes")
    rows = scan.hash_all(walked.files, hashes.SHA256)
    data = manifest.render(
        rows,
        purpose.strip(),
        created_text,
        folder.name or ".",
        excludes=rules.patterns,
        links=walked.links,
        special=walked.special,
    )
    write_new_file(manifest_path, data, force=force)
    return SealResult(
        manifest_path,
        len(rows),
        sum(row[2] for row in rows),
        walked.links,
        walked.special,
        walked.excluded,
        rules.patterns,
        _your_unmatched(rules),
    )


def token_path_for(manifest_path: Path) -> Path:
    return Path(manifest_path).with_suffix(TOKEN_SUFFIX)


def query_path_for(manifest_path: Path) -> Path:
    return Path(manifest_path).with_suffix(QUERY_SUFFIX)


def root_path_for(manifest_path: Path) -> Path:
    return Path(manifest_path).with_suffix(ROOT_SUFFIX)


def companion_paths(manifest_path: Path) -> List[Path]:
    """The exact files this tool writes or looks for beside a manifest, and nothing else."""
    path = Path(manifest_path)
    found = [path.with_suffix(suffix) for suffix in COMPANION_SUFFIXES]
    found += [path.with_suffix(".tst"), path.with_name(path.name + TOKEN_SUFFIX)]
    return found
