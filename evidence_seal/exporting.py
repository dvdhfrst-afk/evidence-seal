"""The export command: a manifest's file list in the forms other tools read.

It reads the manifest and nothing else. No file is hashed and no token is opened, so an export proves
nothing by itself: it is a convenience for checking files with other programs.

For other parts of the tool: ``render_export(data, name, format) -> bytes`` and ``EXPORT_FORMATS``.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Callable, Dict, List, Tuple

from . import manifest, sealing
from .console import deliver, out_path, say, warn
from .errors import EvidenceSealError, UsageError
from .manifest import Entry, Manifest
from .results import EXIT_VERIFIED
from .text import count_of, csv_table

EXPORT_SCHEMA_VERSION = 1
EXPORT_FORMATS = ("sha256sum", "bsd", "csv", "json")
CSV_COLUMNS = ("path", "size", "sha256")


def _file_name(path: str) -> bytes:
    """The name as the file system holds it, including bytes of a name that is not valid UTF-8."""
    try:
        return path.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError:
        raise EvidenceSealError(
            f"{path} holds a lone surrogate, which only a Windows name can, and no checksum list can name it."
            " Use --format json or csv, which write it as an escape"
        ) from None


def _gnu_escaped(name: bytes) -> Tuple[bytes, bytes]:
    """GNU's convention: a name holding a backslash, a line feed or a carriage return is escaped,
    and its line starts with a backslash so ``sha256sum -c`` knows to read it that way."""
    if not any(byte in name for byte in b"\\\n\r"):
        return b"", name
    return b"\\", name.replace(b"\\", b"\\\\").replace(b"\n", b"\\n").replace(b"\r", b"\\r")


def _escapes(path: str) -> bool:
    return any(character in path for character in "\\\n\r")


def _sha256sum(entries: List[Entry]) -> bytes:
    lines = []
    for entry in entries:
        mark, name = _gnu_escaped(_file_name(entry.path))
        # The star asks for binary mode, so no system reads the file as text and changes its bytes.
        lines.append(mark + entry.hexdigest.encode("ascii") + b" *" + name + b"\n")
    return b"".join(lines)


def _bsd(entries: List[Entry]) -> bytes:
    lines = []
    for entry in entries:
        mark, name = _gnu_escaped(_file_name(entry.path))
        lines.append(mark + b"SHA256 (" + name + b") = " + entry.hexdigest.encode("ascii") + b"\n")
    return b"".join(lines)


def _csv(entries: List[Entry]) -> bytes:
    return csv_table(
        CSV_COLUMNS,
        ((manifest.escape_text(entry.path), "" if entry.size is None else entry.size, entry.hexdigest) for entry in entries),
    )


def _json(data: Manifest, name: str, entries: List[Entry]) -> bytes:
    document = {
        "export_schema": EXPORT_SCHEMA_VERSION,
        "manifest": {"name": name, "kind": data.kind, "purpose": data.purpose, "created": data.created},
        "sizes_recorded": all(entry.size is not None for entry in entries),
        "files": [{"path": entry.path, "size": entry.size, "sha256": entry.hexdigest} for entry in entries],
    }
    return (json.dumps(document, indent=2) + "\n").encode("ascii")


def render_export(data: Manifest, name: str, form: str) -> bytes:
    entries = manifest.sha256_entries(data, name, "export")
    renderers: Dict[str, Callable[[], bytes]] = {
        "sha256sum": lambda: _sha256sum(entries),
        "bsd": lambda: _bsd(entries),
        "csv": lambda: _csv(entries),
        "json": lambda: _json(data, name, entries),
    }
    return renderers[form]()


def command_export(args: argparse.Namespace) -> int:
    if args.manifest.is_dir():
        raise UsageError(f"{args.manifest} is a folder. Give the manifest file")
    target = out_path(args.out)
    if target is not None:
        sealing.refuse_to_replace(target, sealing.files_of(args.manifest), "the export")
    data = manifest.read_manifest(args.manifest)
    name = args.manifest.name
    output = render_export(data, name, args.format)
    for problem in data.problems:
        warn(f"warning: {name} is inconsistent: {problem}. It was exported as listed")
    if data.unreadable_lines:
        warn(f"warning: {count_of(data.unreadable_lines, 'line')} of {name} could not be read as hash lines and were not exported")
    if data.links or data.special:
        warn(f"Not exported: {count_of(len(data.links) + len(data.special), 'link or special file')}, listed by name only")
    escaped = sum(1 for entry in data.entries if _escapes(entry.path)) if args.format in ("sha256sum", "bsd") else 0
    if escaped:
        warn(
            f"{count_of(escaped, 'name')} holding a backslash, a line feed or a carriage return"
            " were written escaped, the way GNU sha256sum writes them. Some other checkers skip such lines"
            " with only a warning, so make sure every file is reported OK"
        )
    if args.format in ("csv", "json") and data.total_bytes is None:
        warn(f"{name} is hand-made and does not record every size, so those sizes are left empty")
    warn("This list comes from the manifest alone. It checks no token and proves no date.")
    deliver(output, target, args.force)
    if target is not None:
        say(f"Wrote {count_of(len(data.entries), 'file')} to {target}")
    return EXIT_VERIFIED


def register(commands) -> Dict[str, Callable[[argparse.Namespace], int]]:
    parser = commands.add_parser(
        "export",
        help="write a manifest's file list for other tools, such as sha256sum -c",
        description=(
            "Write the files a manifest lists, with their SHA-256 hashes, in a form other tools read."
            " Reads only the manifest: no file is hashed and no token is checked."
        ),
        epilog=(
            "formats: sha256sum (for sha256sum -c, run inside the sealed folder), bsd (SHA256 (path) = hash),"
            " csv (path, size, sha256), json. exit codes: 0 written, 1 nothing written, 2 bad arguments"
            " or an unreadable file"
        ),
        allow_abbrev=False,
    )
    parser.add_argument("manifest", type=Path, help="the manifest file")
    parser.add_argument("--format", choices=EXPORT_FORMATS, default="sha256sum", help="list format (default: %(default)s)")
    parser.add_argument("--out", help="file to write, or - for standard output (default: standard output)")
    parser.add_argument("--force", action="store_true", help="replace an existing file; never the manifest or its companions")
    return {"export": command_export}
