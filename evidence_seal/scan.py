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
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

from .errors import SealError, UsageError
from .hashes import HashAlgorithm

CHUNK = 1024 * 1024

_REPARSE_LINK_TAGS = {0xA000000C, 0xA0000003}  # Windows symbolic link and mount point


ExcludeItem = Union[str, Tuple[str, str]]


@dataclass(frozen=True)
class ExcludeRule:
    text: str
    source: str
    negated: bool
    folder_only: bool
    segments: Tuple[str, ...]


def parse_rule(pattern: str, source: str = "") -> Optional[ExcludeRule]:
    """Reads one pattern. Returns None when nothing is left to match."""
    text = pattern.replace("\\", "/")
    negated = text.startswith("!")
    body = text[1:] if negated else text
    folder_only = body.endswith("/")
    body = body.rstrip("/")
    anchored = "/" in body
    segments = tuple(part for part in body.split("/") if part)
    if not segments:
        return None
    if not anchored:
        segments = ("**",) + segments
    return ExcludeRule(text, source, negated, folder_only, segments)


def _segments_match(pattern: Sequence[str], parts: Sequence[str]) -> bool:
    """Matches one path component at a time, so a wildcard can never cross a slash."""
    p = i = 0
    star_p = star_i = -1
    while i < len(parts):
        if p < len(pattern) and pattern[p] == "**":
            star_p, star_i = p, i
            p += 1
        elif p < len(pattern) and fnmatch.fnmatchcase(parts[i], pattern[p]):
            p += 1
            i += 1
        elif star_p >= 0:
            star_i += 1
            i = star_i
            p = star_p + 1
        else:
            return False
    while p < len(pattern) and pattern[p] == "**":
        p += 1
    return p == len(pattern)


class Excludes:
    """An ordered list of exclude rules.

    A pattern with no slash matches a name at any depth. A pattern with a slash,
    including a leading one, matches from the top of the folder, and ``**`` stands for
    any number of folders. A trailing slash limits a rule to folders. A leading ``!``
    puts back what an earlier rule left out.

    A rule that matches a folder applies to everything inside it, and when several
    rules apply the last one wins. Matching is case sensitive on every platform, so a
    manifest means the same thing everywhere.
    """

    def __init__(self, patterns: Iterable[ExcludeItem] = ()):
        self.rules: List[ExcludeRule] = []
        for item in patterns:
            pattern, source = (item, "") if isinstance(item, str) else item
            rule = parse_rule(pattern, source)
            if rule is not None:
                self.rules.append(rule)
        self.patterns: List[str] = [rule.text for rule in self.rules]
        self._folders: Dict[str, int] = {}
        self._matched: Set[int] = set()

    def _winner(self, relative: str, is_dir: bool) -> int:
        """The index of the last rule that applies, or -1."""
        parent = relative.rpartition("/")[0]
        best = self._folder_winner(parent) if parent else -1
        parts = relative.split("/")
        for index, rule in enumerate(self.rules):
            if (is_dir or not rule.folder_only) and _segments_match(rule.segments, parts):
                self._matched.add(index)
                best = max(best, index)
        return best

    def _folder_winner(self, folder: str) -> int:
        if folder not in self._folders:
            self._folders[folder] = self._winner(folder, True)
        return self._folders[folder]

    def deciding_rule(self, relative: str, is_dir: bool = False) -> Optional[ExcludeRule]:
        index = self._folder_winner(relative) if is_dir else self._winner(relative, False)
        return self.rules[index] if index >= 0 else None

    def matches(self, relative: str, is_dir: bool = False) -> bool:
        rule = self.deciding_rule(relative, is_dir)
        return rule is not None and not rule.negated

    def can_skip_folder(self, relative: str) -> bool:
        """True when the folder is left out and no later rule could put anything inside it back."""
        index = self._folder_winner(relative)
        if index < 0 or self.rules[index].negated:
            return False
        return not any(rule.negated for rule in self.rules[index + 1 :])

    def unmatched(self) -> List[ExcludeRule]:
        """Rules that matched nothing the walk looked at."""
        return [rule for index, rule in enumerate(self.rules) if index not in self._matched]


def read_exclude_file(path: Path) -> List[Tuple[str, str]]:
    """One pattern per line. Blank lines and lines starting with # are ignored."""
    try:
        text = Path(path).read_bytes().decode("utf-8-sig")
    except OSError as exc:
        raise UsageError(f"cannot read exclude file {path}: {exc.strerror or exc}") from None
    except UnicodeDecodeError:
        raise UsageError(f"exclude file {path} is not UTF-8 text") from None
    found: List[Tuple[str, str]] = []
    for number, line in enumerate(text.splitlines(), 1):
        pattern = line.strip()
        if pattern and not pattern.startswith("#"):
            found.append((pattern, f"{Path(path).name} line {number}"))
    return found


@dataclass
class WalkResult:
    files: Dict[str, Path] = field(default_factory=dict)
    links: List[str] = field(default_factory=list)
    special: List[str] = field(default_factory=list)
    errors: List[Tuple[str, str]] = field(default_factory=list)
    excluded: List[str] = field(default_factory=list)
    excluded_folders: Set[str] = field(default_factory=set)


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
                info = entry.stat(follow_symlinks=False)
            except OSError as exc:
                if excludes.matches(relative):
                    result.excluded.append(relative)
                else:
                    result.errors.append((relative, exc.strerror or str(exc)))
                continue
            link = _is_link(entry, info)
            if not link and stat.S_ISDIR(info.st_mode):
                if excludes.can_skip_folder(relative):
                    result.excluded.append(relative)
                    result.excluded_folders.add(relative)
                else:
                    pending.append((Path(entry.path), relative + "/"))
            elif excludes.matches(relative):
                result.excluded.append(relative)
            elif link:
                result.links.append(relative)
            elif stat.S_ISREG(info.st_mode):
                result.files[relative] = Path(entry.path)
            else:
                result.special.append(relative)
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
