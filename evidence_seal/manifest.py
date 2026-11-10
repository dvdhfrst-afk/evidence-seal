"""The manifest: a plain text list of hashes, sizes and paths.

Two kinds are read. A native manifest is the strict format this tool writes. A
hand-made manifest is any text with lines in the common shapes that hash tools
print, with free text around them, because the token covers the whole file
either way and the tool must not require its own format to check a real proof.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from . import hashes
from .errors import ManifestError, UsageError
from .hashes import HashAlgorithm
from .scan import sort_key

MAGIC = "evidence-seal manifest v1"
FORMAT_VERSION = 1
MAX_MANIFEST_BYTES = 2 * 1024 * 1024 * 1024
MAX_SIDE_FILE_BYTES = 64 * 1024 * 1024

NATIVE = "native"
HAND_MADE = "hand-made"

_ANY_VERSION = re.compile(rb"^evidence-seal manifest v([0-9]{1,9})(?:\r?\n|$)")
_NUMBER = re.compile(r"^[0-9]{1,20}$")
_NATIVE_LINE = re.compile(r"^([0-9a-f]{64})  ([0-9]{1,20})  (.+)$", re.DOTALL)
_HEX_START = re.compile(r"^\\?[0-9a-fA-F]{32,128}(\s|$)")
_GNU_LINE = re.compile(r"^(\\?)([0-9a-fA-F]{32,128})(?: \*| {2}| )(.+)$", re.DOTALL)
_DATE_COLUMN = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+(.*)$", re.DOTALL)
_SIZE_COLUMN = re.compile(r"^([0-9]{1,20}) {2,}(.*)$", re.DOTALL)
_TAG_LINE = re.compile(r"^(?:SHA-?(1|224|256|384|512)|SHA2-(224|256|384|512)|MD5) ?\((.+)\) ?= ?([0-9a-fA-F]{32,128})$", re.DOTALL)


@dataclass(frozen=True)
class Entry:
    path: str
    hexdigest: str
    algorithm: HashAlgorithm
    size: Optional[int] = None


@dataclass
class Manifest:
    kind: str
    raw: bytes
    entries: List[Entry] = field(default_factory=list)
    purpose: Optional[str] = None
    created: Optional[str] = None
    folder_name: Optional[str] = None
    excludes: List[str] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    special: List[str] = field(default_factory=list)
    problems: List[str] = field(default_factory=list)
    note_lines: int = 0
    unreadable_lines: int = 0
    weak_entries: int = 0
    newer_version: Optional[int] = None

    @property
    def total_bytes(self) -> Optional[int]:
        if any(entry.size is None for entry in self.entries):
            return None
        return sum(entry.size or 0 for entry in self.entries)


def escape_text(text: str) -> str:
    """Keeps every value on one line and survives names that are not valid UTF-8."""
    out: List[str] = []
    for char in text:
        code = ord(char)
        if char == "\\":
            out.append("\\\\")
        elif char == "\n":
            out.append("\\n")
        elif char == "\r":
            out.append("\\r")
        elif char == "\t":
            out.append("\\t")
        elif code < 0x20 or code == 0x7F:
            out.append(f"\\x{code:02x}")
        elif 0xDC80 <= code <= 0xDCFF:
            out.append(f"\\x{code - 0xDC00:02x}")
        elif 0xD800 <= code <= 0xDFFF:
            out.append(f"\\u{code:04x}")
        else:
            out.append(char)
    return "".join(out)


_UNESCAPE = re.compile(r"\\(\\|n|r|t|x[0-9a-f]{2}|u[0-9a-f]{4})")


def unescape_text(text: str) -> str:
    def replace(match: "re.Match[str]") -> str:
        token = match.group(1)
        if token == "\\":
            return "\\"
        if token == "n":
            return "\n"
        if token == "r":
            return "\r"
        if token == "t":
            return "\t"
        code = int(token[1:], 16)
        if token[0] == "x" and code >= 0x80:
            return chr(0xDC00 + code)
        return chr(code)

    return _UNESCAPE.sub(replace, text)


def render(
    rows: Sequence[Tuple[str, str, int]],
    purpose: str,
    created: str,
    folder_name: str,
    excludes: Iterable[str] = (),
    links: Iterable[str] = (),
    special: Iterable[str] = (),
) -> bytes:
    """The native manifest. The same folder gives the same bytes, apart from purpose and created."""
    lines: List[str] = [
        MAGIC,
        f"purpose: {escape_text(purpose)}",
        f"created: {created}",
        f"folder: {escape_text(folder_name)}",
        "algorithm: sha256",
    ]
    lines.extend(f"exclude: {escape_text(pattern)}" for pattern in excludes)
    lines.extend(f"link: {escape_text(path)}" for path in links)
    lines.extend(f"special: {escape_text(path)}" for path in special)
    ordered = sorted(rows, key=lambda row: sort_key(row[0]))
    lines.append(f"files: {len(ordered)}")
    lines.append(f"total-bytes: {sum(row[2] for row in ordered)}")
    lines.append("")
    lines.extend(f"{digest}  {size}  {escape_text(path)}" for path, digest, size in ordered)
    return ("\n".join(lines) + "\n").encode("utf-8", "surrogatepass")


def parse(raw: bytes) -> Manifest:
    """Reads manifest bytes. Native and hand-made manifests are told apart by the first line."""
    version = _ANY_VERSION.match(raw)
    if version is not None and int(version.group(1)) != FORMAT_VERSION:
        return Manifest(NATIVE, raw, newer_version=int(version.group(1)))
    if raw.startswith(MAGIC.encode("ascii") + b"\n"):
        return _parse_native(raw)
    if version is not None:
        manifest = Manifest(NATIVE, raw)
        manifest.problems.append("the native manifest does not use plain line feeds, so its bytes were altered")
        return manifest
    return _parse_hand_made(raw)


def _parse_native(raw: bytes) -> Manifest:
    manifest = Manifest(NATIVE, raw)
    try:
        text = raw.decode("utf-8", "surrogatepass")
    except UnicodeDecodeError:
        manifest.problems.append("the manifest is not valid UTF-8")
        return manifest
    if "\r" in text:
        manifest.problems.append("the native manifest contains carriage returns, so its bytes were altered")
    if not text.endswith("\n"):
        manifest.problems.append("the manifest does not end with a line feed, so it may be truncated")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    index = 1
    declared_files: Optional[int] = None
    declared_bytes: Optional[int] = None
    seen_algorithm = False
    while index < len(lines) and lines[index] != "":
        key, separator, value = lines[index].partition(": ")
        index += 1
        if not separator:
            manifest.problems.append(f"header line {index} is not understood")
        elif key == "purpose":
            manifest.purpose = unescape_text(value)
        elif key == "created":
            manifest.created = value
        elif key == "folder":
            manifest.folder_name = unescape_text(value)
        elif key == "algorithm":
            seen_algorithm = True
            if value != "sha256":
                manifest.problems.append(f"unknown algorithm in the header: {value}")
        elif key == "exclude":
            manifest.excludes.append(unescape_text(value))
        elif key == "link":
            manifest.links.append(unescape_text(value))
        elif key == "special":
            manifest.special.append(unescape_text(value))
        elif key == "files" and _NUMBER.match(value):
            declared_files = int(value)
        elif key == "total-bytes" and _NUMBER.match(value):
            declared_bytes = int(value)
        else:
            manifest.problems.append(f"header line {index} is not understood")
    if not seen_algorithm:
        manifest.problems.append("the header does not state its hash algorithm")
    index += 1
    previous: Optional[bytes] = None
    for number, line in enumerate(lines[index:], index + 1):
        match = _NATIVE_LINE.match(line)
        if match is None:
            manifest.problems.append(f"line {number} is not a valid entry")
            manifest.unreadable_lines += 1
            continue
        path = unescape_text(match.group(3))
        key_bytes = sort_key(path)
        if previous is not None and key_bytes <= previous:
            manifest.problems.append(f"line {number} is out of order or repeats a path")
        previous = key_bytes
        manifest.entries.append(Entry(path, match.group(1), hashes.SHA256, int(match.group(2))))
    if declared_files is None or declared_bytes is None:
        manifest.problems.append("the header does not state the file count and total size")
    else:
        if declared_files != len(manifest.entries):
            manifest.problems.append(
                f"the header says {declared_files} files but {len(manifest.entries)} are listed, so it was altered"
            )
        if declared_bytes != sum(entry.size or 0 for entry in manifest.entries):
            manifest.problems.append("the header's total size does not match the listed sizes, so it was altered")
    return manifest


def _clean_hand_path(path: str) -> str:
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def _add_hand_entry(manifest: Manifest, path: str, hexdigest: str, size: Optional[int], seen: Dict[str, Entry]) -> None:
    algorithm = hashes.by_hex_length(len(hexdigest))
    if algorithm is None:
        manifest.unreadable_lines += 1
        return
    if algorithm.weak:
        manifest.weak_entries += 1
    path = _clean_hand_path(path)
    entry = Entry(path, hexdigest.lower(), algorithm, size)
    earlier = seen.get(path)
    if earlier is not None:
        if earlier.hexdigest != entry.hexdigest:
            manifest.problems.append(f"the manifest lists two different hashes for {path}")
        return
    seen[path] = entry
    manifest.entries.append(entry)


def _parse_hand_made(raw: bytes) -> Manifest:
    manifest = Manifest(HAND_MADE, raw)
    start = 3 if raw.startswith(b"\xef\xbb\xbf") else 0
    try:
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            text = raw.decode("utf-16")  # What Windows PowerShell 5.1 writes when output is redirected
        else:
            text = raw[start:].decode("utf-8")
    except UnicodeDecodeError:
        text = raw[start:].decode("latin-1")
    seen: Dict[str, Entry] = {}
    for line in text.split("\n"):
        line = line[:-1] if line.endswith("\r") else line
        if not line.strip():
            continue
        tagged = _TAG_LINE.match(line)
        if tagged is not None:
            _add_hand_entry(manifest, tagged.group(3), tagged.group(4), None, seen)
            continue
        if _HEX_START.match(line):
            _read_hash_first_line(manifest, line, seen)
            continue
        manifest.note_lines += 1
    return manifest


def _read_hash_first_line(manifest: Manifest, line: str, seen: Dict[str, Entry]) -> None:
    """Handles ``HASH  path``, ``HASH *path``, and the same with date and size columns."""
    match = _GNU_LINE.match(line)
    if match is None:
        manifest.unreadable_lines += 1
        return
    escaped, hexdigest, rest = match.groups()
    size: Optional[int] = None
    rest = rest.lstrip(" ") if line[len(escaped) + len(hexdigest):].startswith("  ") else rest
    dated = _DATE_COLUMN.match(rest)
    if dated is not None:
        rest = dated.group(1)
    sized = _SIZE_COLUMN.match(rest)
    if sized is not None:
        size = int(sized.group(1))
        rest = sized.group(2)
    if not rest:
        manifest.unreadable_lines += 1
        return
    if escaped:
        rest = rest.replace("\\\\", "\0").replace("\\n", "\n").replace("\\r", "\r").replace("\0", "\\")
    _add_hand_entry(manifest, rest, hexdigest, size, seen)


def read_limited(path, what: str, limit: int = MAX_MANIFEST_BYTES) -> bytes:
    """Reads a whole file, and refuses one far larger than this kind of file can honestly be."""
    try:
        with open(path, "rb") as handle:
            if os.fstat(handle.fileno()).st_size > limit:
                raise UsageError(f"{what} {path} is too large to be one (over {limit // (1024 * 1024)} MB)")
            return handle.read()
    except OSError as exc:
        raise UsageError(f"cannot read {what} {path}: {exc.strerror or exc}") from None


def read_manifest(path) -> Manifest:
    return parse(read_limited(path, "manifest"))


def sha256_entries(data: Manifest, name: str, command: str) -> List[Entry]:
    """The entries of a manifest that a SHA-256 list can be made from, or a plain reason why there are none."""
    if data.newer_version is not None:
        raise ManifestError(
            f"{name} uses manifest format v{data.newer_version}, and this version of evidence-seal reads format"
            f" v{FORMAT_VERSION}. Nothing here is damaged; use a version that reads it"
        )
    if not data.entries:
        raise ManifestError(f"{name} lists no files in a form this tool can read")
    other = [entry for entry in data.entries if entry.algorithm is not hashes.SHA256]
    if other:
        raise ManifestError(
            f"{command} works with SHA-256 lists, and {name} lists {len(other)} of its files with"
            f" {other[0].algorithm.display} hashes, such as {other[0].path}"
        )
    return data.entries
