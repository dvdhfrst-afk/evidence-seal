"""Walks a folder and hashes raw file bytes.

Files are read in binary mode and hashed as they are. Line endings are never
touched, because changing a single byte would break the proof. Links are never
followed: a link could point at a copy of the sealed content somewhere else and
make a changed folder look unchanged.
"""

from __future__ import annotations

import fnmatch
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from .errors import SealError
from .hashes import HashAlgorithm

CHUNK = 1024 * 1024

_REPARSE_LINK_TAGS = {0xA000000C, 0xA0000003}  # Windows symbolic link and mount point


class Excludes:
    """Exclude patterns.

    A pattern with no slash matches any single path component, so ``.git`` drops a
    folder of that name at any depth. A pattern with a slash, including a leading
    one, matches the whole relative path from the top of the folder. Matching is
    case sensitive on every platform, so a manifest means the same thing everywhere.
    """

    def __init__(self, patterns: Iterable[str] = ()):
        self.patterns: List[str] = []
        for pattern in patterns:
            cleaned = pattern.replace("\\", "/").rstrip("/")
            if cleaned.strip("/"):
                self.patterns.append(cleaned)

    def matches(self, relative: str) -> bool:
        parts = relative.split("/")
        for pattern in self.patterns:
            if "/" in pattern:
                if fnmatch.fnmatchcase(relative, pattern.lstrip("/")):
                    return True
            elif fnmatch.fnmatchcase(parts[-1], pattern):
                return True
        return False


@dataclass
class WalkResult:
    files: Dict[str, Path] = field(default_factory=dict)
    links: List[str] = field(default_factory=list)
    special: List[str] = field(default_factory=list)
    errors: List[Tuple[str, str]] = field(default_factory=list)
    excluded: List[str] = field(default_factory=list)


def _is_link(entry: "os.DirEntry[str]", info: os.stat_result) -> bool:
    if entry.is_symlink():
        return True
    tag = getattr(info, "st_reparse_tag", 0)
    return tag in _REPARSE_LINK_TAGS


def sort_key(relative: str) -> bytes:
    """A byte order that is the same on every platform and locale."""
    return relative.encode("utf-8", "surrogatepass")


def walk(root: Path, excludes: Excludes) -> WalkResult:
    """Lists every regular file under ``root``, keyed by its relative slash-separated path."""
    result = WalkResult()
    pending: List[Tuple[Path, str]] = [(Path(root), "")]
    while pending:
        folder, prefix = pending.pop()
        try:
            entries = list(os.scandir(folder))
        except OSError as exc:
            result.errors.append((prefix or ".", exc.strerror or str(exc)))
            continue
        for entry in entries:
            relative = prefix + entry.name
            try:
                if excludes.matches(relative):
                    result.excluded.append(relative)
                    continue
                info = entry.stat(follow_symlinks=False)
                if _is_link(entry, info):
                    result.links.append(relative)
                elif stat.S_ISDIR(info.st_mode):
                    pending.append((Path(entry.path), relative + "/"))
                elif stat.S_ISREG(info.st_mode):
                    result.files[relative] = Path(entry.path)
                else:
                    result.special.append(relative)
            except OSError as exc:
                result.errors.append((relative, exc.strerror or str(exc)))
    result.links.sort(key=sort_key)
    result.special.sort(key=sort_key)
    result.excluded.sort(key=sort_key)
    return result


def hash_file(path: Path, algorithm: HashAlgorithm) -> Tuple[str, int]:
    """Hex hash and byte count of the raw file content."""
    hasher = algorithm.new()
    size = 0
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(CHUNK)
            if not chunk:
                break
            hasher.update(chunk)
            size += len(chunk)
    return hasher.hexdigest(), size


def hash_all(files: Dict[str, Path], algorithm: HashAlgorithm) -> List[Tuple[str, str, int]]:
    """Hashes every file in stable order. Any file that cannot be read stops the seal."""
    rows: List[Tuple[str, str, int]] = []
    for relative in sorted(files, key=sort_key):
        try:
            digest, size = hash_file(files[relative], algorithm)
        except OSError as exc:
            raise SealError(f"cannot read {relative}: {exc.strerror or exc}") from None
        rows.append((relative, digest, size))
    return rows


def require_clean_walk(result: WalkResult) -> None:
    if result.errors:
        path, reason = result.errors[0]
        raise SealError(f"cannot read {path}: {reason}")
