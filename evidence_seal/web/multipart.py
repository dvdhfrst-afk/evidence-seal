"""A strict multipart/form-data reader (RFC 7578), for the files someone uploads to check.

The standard library's cgi module is deprecated, so this reads the whole body, which the server has
already bounded, and refuses anything unusual instead of guessing: a preamble or epilogue, a part
without a name, a header it does not know, a header line folded onto two lines, a field sent twice,
a field it was not told to expect, and anything over its limit. A file name is kept only to show it,
and is never used to open or write a file.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Mapping, Optional, Tuple

MAX_PARTS = 16
MAX_PART_HEADERS = 4
MAX_HEADER_LINE = 1024
MAX_BOUNDARY = 70
# The characters RFC 2046 allows in a boundary. A space may appear, but not at the end.
_BOUNDARY = re.compile(r"[0-9A-Za-z'()+_,\-./:=? ]{0,69}[0-9A-Za-z'()+_,\-./:=?]\Z")
_TOKEN = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_PARAMETER = re.compile(r"\s*;\s*(" + _TOKEN + r")\s*=\s*(\"(?:[^\"\\\r\n]|\\[^\r\n])*\"|" + _TOKEN + r")")
_QUOTED_PAIR = re.compile(r"\\(.)")


class MultipartError(ValueError):
    """The body is not multipart/form-data that this reader accepts. The message says why, plainly."""


@dataclass(frozen=True)
class Part:
    name: str
    filename: Optional[str]
    content_type: Optional[str]
    data: bytes

    @property
    def is_file(self) -> bool:
        return self.filename is not None


def _parameters(text: str, where: str) -> Tuple[str, Dict[str, str]]:
    """A header value such as ``form-data; name="x"``: the first word, then each parameter exactly once."""
    head, separator, rest = text.partition(";")
    rest = separator + rest
    found: Dict[str, str] = {}
    position = 0
    while position < len(rest):
        match = _PARAMETER.match(rest, position)
        if match is None:
            raise MultipartError(f"the {where} header cannot be read")
        key = match.group(1).lower()
        value = match.group(2)
        if value.startswith('"'):
            value = _QUOTED_PAIR.sub(r"\1", value[1:-1])
        if key in found:
            raise MultipartError(f"the {where} header names {key} twice")
        found[key] = value
        position = match.end()
    return head.strip().lower(), found


def boundary_of(content_type: Optional[str]) -> str:
    """The boundary from a Content-Type header, which must be multipart/form-data with one boundary."""
    if not content_type:
        raise MultipartError("the upload has no Content-Type")
    kind, parameters = _parameters(content_type, "Content-Type")
    if kind != "multipart/form-data":
        raise MultipartError("the upload must be sent as multipart/form-data")
    boundary = parameters.get("boundary")
    if boundary is None or not _BOUNDARY.match(boundary):
        raise MultipartError(f"the multipart boundary must be 1 to {MAX_BOUNDARY} plain characters")
    return boundary


def _part_headers(block: bytes) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    lines = block.split(b"\r\n")
    if len(lines) > MAX_PART_HEADERS:
        raise MultipartError("a part has too many headers")
    for line in lines:
        if len(line) > MAX_HEADER_LINE:
            raise MultipartError("a part header is too long")
        if not line or line[:1] in (b" ", b"\t"):
            raise MultipartError("a part header is empty or folded onto two lines")
        if b"\n" in line or b"\r" in line:
            raise MultipartError("a part header holds a stray line break")
        try:
            text = line.decode("utf-8")
        except UnicodeDecodeError:
            raise MultipartError("a part header is not UTF-8 text") from None
        name, colon, value = text.partition(":")
        name = name.strip().lower()
        if not colon or not name:
            raise MultipartError("a part header has no name")
        if name not in ("content-disposition", "content-type"):
            raise MultipartError(f"a part has the header {name[:40]!r}, which an upload does not use")
        if name in headers:
            raise MultipartError(f"a part has two {name} headers")
        headers[name] = value.strip()
    return headers


def _part(block: bytes, data: bytes, expected: Mapping[str, int], seen: Dict[str, "Part"]) -> "Part":
    headers = _part_headers(block)
    disposition = headers.get("content-disposition")
    if disposition is None:
        raise MultipartError("a part has no Content-Disposition header")
    kind, parameters = _parameters(disposition, "Content-Disposition")
    if kind != "form-data":
        raise MultipartError("each part must be form-data")
    unknown = set(parameters) - {"name", "filename"}
    if unknown:
        raise MultipartError(f"a part has the parameter {sorted(unknown)[0][:40]!r}, which this reader does not accept")
    name = parameters.get("name")
    if not name:
        raise MultipartError("a part has no field name")
    if name not in expected:
        raise MultipartError(f"the field {name[:40]!r} is not one this form has")
    if name in seen:
        raise MultipartError(f"the field {name[:40]!r} was sent twice")
    if len(data) > expected[name]:
        raise MultipartError(f"the field {name[:40]!r} is larger than its limit of {expected[name]} bytes")
    return Part(name, parameters.get("filename"), headers.get("content-type"), data)


def parse(body: bytes, boundary: str, expected: Mapping[str, int]) -> Dict[str, Part]:
    """Every part of ``body``, by field name. ``expected`` maps each field this form has to its size limit."""
    delimiter = b"--" + boundary.encode("ascii")
    if not body.startswith(delimiter + b"\r\n"):
        raise MultipartError("the upload does not start with its boundary")
    parts: Dict[str, Part] = {}
    position = len(delimiter) + 2
    header_room = MAX_PART_HEADERS * (MAX_HEADER_LINE + 2) + 2
    while True:
        if len(parts) >= MAX_PARTS:
            raise MultipartError(f"the upload has more than {MAX_PARTS} parts")
        end = body.find(b"\r\n\r\n", position, position + header_room)
        if end < 0:
            raise MultipartError("a part's headers do not end, or are too long")
        start = end + 4
        close = body.find(b"\r\n" + delimiter, start)
        if close < 0:
            raise MultipartError("the upload ends before its closing boundary")
        part = _part(body[position:end], body[start:close], expected, parts)
        parts[part.name] = part
        after = close + 2 + len(delimiter)
        tail = body[after : after + 2]
        if tail == b"--":
            if body[after + 2 :] not in (b"", b"\r\n"):
                raise MultipartError("the upload has data after its closing boundary")
            return parts
        if tail != b"\r\n":
            raise MultipartError("a boundary is not followed by a line break")
        position = after + 2

