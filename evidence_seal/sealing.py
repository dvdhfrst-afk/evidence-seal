"""The seal command: walk a folder and write its manifest."""

from __future__ import annotations

import glob
import os
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional, Sequence, Tuple

from . import hashes, manifest, scan
from .errors import ManifestError, SealError, UsageError

TOKEN_SUFFIX = ".tsr"
QUERY_SUFFIX = ".tsq"
ROOT_SUFFIX = ".ca.crt"
REPORT_TEXT_SUFFIX = ".report.txt"
REPORT_HTML_SUFFIX = ".report.html"
OWN_FILES = "the manifest's own files"
COMPANION_SUFFIXES = (TOKEN_SUFFIX, QUERY_SUFFIX, ROOT_SUFFIX, REPORT_TEXT_SUFFIX, REPORT_HTML_SUFFIX)
KEPT_MARK = ".replaced-"


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


def path_key(path: Path) -> str:
    """A form of a path for comparing whether two paths name the same file."""
    text = os.path.abspath(str(path))
    try:
        text = os.path.realpath(text)
    except OSError:
        pass
    if text.startswith("\\\\?\\UNC\\"):
        text = "\\\\" + text[8:]
    elif text.startswith("\\\\?\\"):
        text = text[4:]
    return os.path.normcase(text)


def _file_mode(path: Path) -> int:
    """The mode the file would have if opened normally. A temporary file starts out private to its owner."""
    try:
        return stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        mask = os.umask(0)
        os.umask(mask)
        return 0o666 & ~mask


def _sync_folder(folder: Path) -> None:
    """Asks the system to record the new name on disk too. Windows has no such call."""
    if os.name == "nt":
        return
    try:
        handle = os.open(str(folder), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(handle)
    except OSError:
        pass
    finally:
        os.close(handle)


def check_can_write(path: Path) -> None:
    """Finds out before any long work whether the file could be written at all."""
    folder = Path(path).parent
    while not folder.exists() and folder != folder.parent:
        folder = folder.parent
    try:
        handle, temp_name = tempfile.mkstemp(prefix=".evidence-seal-", suffix=".tmp", dir=str(folder))
        os.close(handle)
        os.unlink(temp_name)
    except OSError as exc:
        raise ManifestError(f"cannot write in {folder}: {exc.strerror or exc}. Choose another place with --out") from None


def write_new_file(path: Path, data: bytes, force: bool = False, mode: Optional[int] = None) -> None:
    """Writes through a temporary file so a crash cannot leave half a manifest or token.

    ``mode`` sets the permissions, for a file that must be private from the moment it has its name.
    """
    path = Path(path)
    if path.is_dir():
        raise UsageError(f"{path} is a folder. Give a file name")
    if os.path.lexists(path) and not force:
        raise ManifestError(f"{path} already exists; use --force to replace it, or choose another name")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        mode = _file_mode(path) if mode is None else mode
        handle, temp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    except OSError as exc:
        raise ManifestError(f"cannot write {path}: {exc.strerror or exc}") from None
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp_name, mode)
        os.replace(temp_name, path)
    except BaseException as exc:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        if isinstance(exc, OSError):
            raise ManifestError(f"cannot write {path}: {exc.strerror or exc}. {path} was left as it was") from None
        raise
    _sync_folder(path.parent)


def keep_copy_of(path: Path, new_bytes: bytes, moment: Optional[datetime] = None) -> Optional[Path]:
    """Copies a file that is about to be replaced by different bytes. Returns where the copy went."""
    path = Path(path)
    try:
        if path.read_bytes() == new_bytes:
            return None
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ManifestError(f"cannot read {path} to keep a copy of it: {exc.strerror or exc}") from None
    when = (moment or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
    suffix = ROOT_SUFFIX if path.name.endswith(ROOT_SUFFIX) else path.suffix
    stem = path.name[: -len(suffix)] if suffix else path.name
    number = 1
    copy = path.with_name(f"{stem}{KEPT_MARK}{when}{suffix}")
    while os.path.lexists(copy):
        number += 1
        copy = path.with_name(f"{stem}{KEPT_MARK}{when}-{number}{suffix}")
    try:
        shutil.copy2(path, copy)
    except OSError as exc:
        raise ManifestError(f"cannot keep a copy of {path}: {exc.strerror or exc}. Nothing was replaced") from None
    return copy


def kept_copies(path: Path) -> List[Path]:
    """The copies ``keep_copy_of`` made of the companions of this manifest or token."""
    path = Path(path)
    pattern = re.compile(
        re.escape(path.with_suffix("").name) + re.escape(KEPT_MARK) + r"[0-9]{8}T[0-9]{6}Z(-[0-9]+)?(\.tsr|\.tst|\.tsq|\.ca\.crt)"
    )
    try:
        return [found for found in path.parent.iterdir() if pattern.fullmatch(found.name)]
    except OSError:
        return []


def token_in_the_way(manifest_path: Path) -> Optional[Path]:
    """A token beside this manifest, which replacing the manifest would make worthless."""
    for candidate in (token_path_for(manifest_path), manifest_path.with_name(manifest_path.name + TOKEN_SUFFIX)):
        if candidate.is_file():
            return candidate
    return None


def _sidecar_excludes(folder: Path, manifest_path: Path) -> List[Tuple[str, str]]:
    """If the manifest lives inside the folder, it and its companions are not part of the seal."""
    try:
        relative = manifest_path.relative_to(folder)
    except ValueError:
        return []
    if not relative.name:
        return []
    names = [relative] + [relative.with_suffix(suffix) for suffix in COMPANION_SUFFIXES]
    rules = [(f"/{glob.escape(name.as_posix())}", OWN_FILES) for name in names]
    rules.append((f"/{glob.escape(relative.with_suffix('').as_posix())}{KEPT_MARK}*", OWN_FILES))
    return rules


def _your_unmatched(rules: scan.Excludes) -> List[scan.ExcludeRule]:
    return [rule for rule in rules.unmatched() if rule.source != OWN_FILES]


def _resolve_paths(
    folder: Path, excludes: Sequence[scan.ExcludeItem], out: Optional[Path], created_text: str
) -> Tuple[Path, Path, scan.Excludes]:
    given = folder
    folder = Path(folder).resolve()
    if not folder.exists():
        raise UsageError(f"{given} does not exist")
    if not folder.is_dir():
        raise UsageError(f"{given} is a file, and seal takes a folder. Put the files you want to seal in a folder")
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
    report: Optional[Callable[[scan.Meter], None]] = None,
) -> SealResult:
    if not purpose.strip():
        raise UsageError("--purpose must say why this seal is being made")
    created_text = normalize_created(created)
    folder, manifest_path, rules = _resolve_paths(folder, excludes, out, created_text)
    if manifest_path.is_dir():
        raise UsageError(f"{manifest_path} is a folder. Give --out a file name")
    if manifest_path.exists() and not force:
        raise ManifestError(f"{manifest_path} already exists; use --force to replace it, or choose another name")
    token = token_in_the_way(manifest_path) if manifest_path.exists() else None
    if token is not None:
        raise SealError(
            f"{token} covers the manifest {manifest_path.name}, and replacing that manifest would make the token"
            " worthless. An old token cannot be issued again, so nothing was replaced. Choose a new name with --out,"
            " or move both files somewhere safe first"
        )
    check_can_write(manifest_path)
    walked = scan.walk(folder, rules)
    scan.require_clean_walk(walked)
    if not walked.files:
        raise SealError(f"{folder} has no files to seal after excludes")
    total = scan.measure_and_open(walked.files)
    rows = scan.hash_all(walked.files, hashes.SHA256, scan.Meter(report, len(walked.files), total))
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
