"""A hand-written reader and writer for DER, the binary encoding of ASN.1.

Timestamp tokens, certificates and signed attributes are all DER. Anything a
signature covers is parsed strictly. The unsigned outer layers of a token may
be BER (some authorities emit indefinite lengths there), so the reader has a
lenient mode that accepts those forms. The signed parts are always re-parsed
strictly from their own bytes.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterable, List, Optional, Sequence, Set, Tuple

from .errors import DerError

UNIVERSAL = 0
APPLICATION = 1
CONTEXT = 2
PRIVATE = 3

BOOLEAN = 1
INTEGER = 2
BIT_STRING = 3
OCTET_STRING = 4
NULL = 5
OID = 6
UTF8_STRING = 12
SEQUENCE = 16
SET = 17
NUMERIC_STRING = 18
PRINTABLE_STRING = 19
T61_STRING = 20
IA5_STRING = 22
UTC_TIME = 23
GENERALIZED_TIME = 24
VISIBLE_STRING = 26
UNIVERSAL_STRING = 28
BMP_STRING = 30

MAX_DEPTH = 40
_PRIMITIVE_ONLY = {BOOLEAN, INTEGER, NULL, OID, UTC_TIME, GENERALIZED_TIME}
_CONSTRUCTED_ONLY = {SEQUENCE, SET}


class Node:
    """One tag, length and value, with its exact original bytes."""

    __slots__ = ("cls", "constructed", "tag", "raw", "content", "offset", "children")

    def __init__(self, cls, constructed, tag, raw, content, offset, children):
        self.cls = cls
        self.constructed = constructed
        self.tag = tag
        self.raw = raw
        self.content = content
        self.offset = offset
        self.children: Tuple["Node", ...] = children

    def is_universal(self, tag: int) -> bool:
        return self.cls == UNIVERSAL and self.tag == tag

    def is_context(self, tag: int) -> bool:
        return self.cls == CONTEXT and self.tag == tag

    def describe(self) -> str:
        names = {UNIVERSAL: "universal", APPLICATION: "application", CONTEXT: "context", PRIVATE: "private"}
        return f"{names[self.cls]} tag {self.tag} at offset {self.offset}"

    def __repr__(self) -> str:
        return f"<Node {self.describe()} length {len(self.content)}>"


def _read_header(data: bytes, pos: int, strict: bool):
    end = len(data)
    if pos >= end:
        raise DerError(f"data ends where a tag was expected at offset {pos}")
    first = data[pos]
    cls = first >> 6
    constructed = bool(first & 0x20)
    tag = first & 0x1F
    pos += 1
    if tag == 0x1F:
        tag = 0
        lead = True
        while True:
            if pos >= end:
                raise DerError("data ends inside a long form tag")
            byte = data[pos]
            pos += 1
            if lead and byte == 0x80:
                raise DerError("long form tag has a padded first byte")
            lead = False
            tag = (tag << 7) | (byte & 0x7F)
            if tag > 0xFFFFFF:
                raise DerError("tag number is too large")
            if not byte & 0x80:
                break
        if tag < 31:
            raise DerError("long form tag used for a small tag number")
    if pos >= end:
        raise DerError("data ends where a length was expected")
    byte = data[pos]
    pos += 1
    if byte < 0x80:
        return cls, constructed, tag, byte, pos
    if byte == 0x80:
        if strict:
            raise DerError("indefinite length is not allowed in DER")
        if not constructed:
            raise DerError("indefinite length on a primitive value")
        return cls, constructed, tag, None, pos
    count = byte & 0x7F
    if count == 0x7F:
        raise DerError("reserved length form")
    if count > 8:
        raise DerError("length field is too long")
    if pos + count > end:
        raise DerError("data ends inside a length field")
    length = int.from_bytes(data[pos:pos + count], "big")
    if strict and (data[pos] == 0 or length < 0x80):
        raise DerError("length is not in its shortest form")
    return cls, constructed, tag, length, pos + count


def _parse_at(data: bytes, pos: int, limit: int, strict: bool, depth: int) -> Tuple[Node, int]:
    if depth > MAX_DEPTH:
        raise DerError("structure is nested too deeply")
    start = pos
    window = data if limit == len(data) else data[:limit]
    cls, constructed, tag, length, body = _read_header(window, pos, strict)
    if cls == UNIVERSAL:
        if tag == 0:
            raise DerError(f"unexpected end-of-contents marker at offset {start}")
        if constructed and tag in _PRIMITIVE_ONLY:
            raise DerError(f"universal tag {tag} must be primitive")
        if not constructed and tag in _CONSTRUCTED_ONLY:
            raise DerError(f"universal tag {tag} must be constructed")
        if strict and constructed and tag in (BIT_STRING, OCTET_STRING):
            raise DerError("constructed strings are not allowed in DER")
    if length is None:
        children: List[Node] = []
        pos = body
        while True:
            if pos >= limit:
                raise DerError("data ends inside an indefinite length value")
            if data[pos:min(pos + 2, limit)] == b"\x00\x00":
                break
            child, pos = _parse_at(data, pos, limit, strict, depth + 1)
            children.append(child)
        return Node(cls, True, tag, data[start:pos + 2], data[body:pos], start, tuple(children)), pos + 2
    stop = body + length
    if stop > limit:
        raise DerError(f"value at offset {start} runs past the end of its container")
    kids: Tuple[Node, ...] = ()
    if constructed:
        found: List[Node] = []
        pos = body
        while pos < stop:
            child, pos = _parse_at(data, pos, stop, strict, depth + 1)
            found.append(child)
        kids = tuple(found)
    return Node(cls, constructed, tag, data[start:stop], data[body:stop], start, kids), stop


def parse(data: bytes, strict: bool = True) -> Node:
    """Parse exactly one value. Trailing bytes are an error."""
    data = bytes(data)
    node, stop = _parse_at(data, 0, len(data), strict, 0)
    if stop != len(data):
        raise DerError(f"{len(data) - stop} unexpected bytes after the end of the structure")
    return node


class Cursor:
    """Walks the children of a constructed value in order."""

    def __init__(self, node: Node, what: str):
        if not node.constructed:
            raise DerError(f"{what} should be a constructed value, found {node.describe()}")
        self._children: Sequence[Node] = node.children
        self._index = 0
        self._what = what

    def peek(self) -> Optional[Node]:
        if self._index < len(self._children):
            return self._children[self._index]
        return None

    def next(self, field: str) -> Node:
        node = self.peek()
        if node is None:
            raise DerError(f"{self._what} is missing {field}")
        self._index += 1
        return node

    def universal(self, tag: int, field: str) -> Node:
        node = self.next(field)
        if not node.is_universal(tag):
            raise DerError(f"{self._what}: {field} has the wrong type ({node.describe()})")
        return node

    def optional_universal(self, tag: int) -> Optional[Node]:
        node = self.peek()
        if node is not None and node.is_universal(tag):
            self._index += 1
            return node
        return None

    def optional_context(self, tag: int) -> Optional[Node]:
        node = self.peek()
        if node is not None and node.is_context(tag):
            self._index += 1
            return node
        return None

    def finish(self) -> None:
        node = self.peek()
        if node is not None:
            raise DerError(f"{self._what} has an unexpected extra field ({node.describe()})")


def int_value(node: Node) -> int:
    content = node.content
    if node.constructed or not content:
        raise DerError(f"bad integer at offset {node.offset}")
    if len(content) > 1 and (
        (content[0] == 0x00 and content[1] < 0x80) or (content[0] == 0xFF and content[1] >= 0x80)
    ):
        raise DerError(f"integer at offset {node.offset} is not in its shortest form")
    return int.from_bytes(content, "big", signed=True)


def bool_value(node: Node) -> bool:
    if node.constructed or len(node.content) != 1 or node.content[0] not in (0x00, 0xFF):
        raise DerError(f"bad boolean at offset {node.offset}")
    return node.content[0] == 0xFF


def oid_value(node: Node) -> str:
    content = node.content
    if node.constructed or not content or content[-1] & 0x80:
        raise DerError(f"bad object identifier at offset {node.offset}")
    arcs: List[int] = []
    value = 0
    fresh = True
    for byte in content:
        if fresh and byte == 0x80:
            raise DerError(f"padded object identifier at offset {node.offset}")
        value = (value << 7) | (byte & 0x7F)
        fresh = not byte & 0x80
        if fresh:
            arcs.append(value)
            value = 0
    first = arcs[0]
    if first < 40:
        head = [0, first]
    elif first < 80:
        head = [1, first - 40]
    else:
        head = [2, first - 80]
    return ".".join(str(arc) for arc in head + arcs[1:])


def octets(node: Node) -> bytes:
    """Contents of an OCTET STRING, joining the segments of the BER constructed form."""
    if not node.constructed:
        return node.content
    return b"".join(octets(child) for child in node.children)


def bit_octets(node: Node) -> bytes:
    """Contents of a BIT STRING that must hold a whole number of bytes."""
    content = node.content
    if node.constructed or not content or content[0] != 0:
        raise DerError(f"bad bit string at offset {node.offset}")
    return content[1:]


def bit_flags(node: Node) -> Set[int]:
    """Set bit numbers of a named-bit BIT STRING, with bit 0 the most significant."""
    content = node.content
    if node.constructed or not content or content[0] > 7 or (len(content) == 1 and content[0] != 0):
        raise DerError(f"bad bit string at offset {node.offset}")
    flags: Set[int] = set()
    total = (len(content) - 1) * 8 - content[0]
    for bit in range(total):
        if content[1 + bit // 8] & (0x80 >> (bit % 8)):
            flags.add(bit)
    return flags


def text_value(node: Node) -> str:
    """Any of the ASN.1 string types, as text."""
    if node.constructed or node.cls != UNIVERSAL:
        raise DerError(f"expected a text value at offset {node.offset}")
    decoders = {
        UTF8_STRING: "utf-8",
        NUMERIC_STRING: "ascii",
        PRINTABLE_STRING: "ascii",
        IA5_STRING: "ascii",
        VISIBLE_STRING: "ascii",
        T61_STRING: "latin-1",
        BMP_STRING: "utf-16-be",
        UNIVERSAL_STRING: "utf-32-be",
    }
    codec = decoders.get(node.tag)
    if codec is None:
        raise DerError(f"universal tag {node.tag} at offset {node.offset} is not a text type")
    try:
        return node.content.decode(codec)
    except (UnicodeDecodeError, ValueError):
        raise DerError(f"undecodable text at offset {node.offset}") from None


def time_value(node: Node) -> datetime:
    """UTCTime or GeneralizedTime as an aware UTC datetime. Only the Z form is valid in DER."""
    if node.is_universal(UTC_TIME):
        text = _ascii(node)
        if len(text) != 13 or not text.endswith("Z") or not text[:12].isdigit():
            raise DerError(f"bad UTCTime at offset {node.offset}")
        year = int(text[:2])
        year += 1900 if year >= 50 else 2000
        return _build_time(year, text[2:12], 0, node)
    if node.is_universal(GENERALIZED_TIME):
        text = _ascii(node)
        if not text.endswith("Z") or len(text) < 15 or not text[:14].isdigit():
            raise DerError(f"bad GeneralizedTime at offset {node.offset}")
        fraction = text[14:-1]
        micro = 0
        if fraction:
            digits = fraction[1:]
            if fraction[0] != "." or not digits.isdigit():
                raise DerError(f"bad GeneralizedTime at offset {node.offset}")
            micro = int(digits[:6].ljust(6, "0"))
        return _build_time(int(text[:4]), text[4:14], micro, node)
    raise DerError(f"expected a time at offset {node.offset}, found {node.describe()}")


def _ascii(node: Node) -> str:
    try:
        return node.content.decode("ascii")
    except UnicodeDecodeError:
        raise DerError(f"bad time text at offset {node.offset}") from None


def _build_time(year: int, rest: str, micro: int, node: Node) -> datetime:
    try:
        return datetime(
            year,
            int(rest[0:2]),
            int(rest[2:4]),
            int(rest[4:6]),
            int(rest[6:8]),
            int(rest[8:10]),
            micro,
            tzinfo=timezone.utc,
        )
    except ValueError:
        raise DerError(f"impossible date or time at offset {node.offset}") from None


def encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def encode_tlv(identifier: int, content: bytes) -> bytes:
    return bytes([identifier]) + encode_length(len(content)) + content


def encode_int(value: int) -> bytes:
    size = (value.bit_length() + 8) // 8 if value >= 0 else ((-value - 1).bit_length() + 8) // 8
    return encode_tlv(INTEGER, value.to_bytes(max(size, 1), "big", signed=True))


def encode_bool(value: bool) -> bytes:
    return encode_tlv(BOOLEAN, b"\xff" if value else b"\x00")


def encode_null() -> bytes:
    return encode_tlv(NULL, b"")


def encode_oid(dotted: str) -> bytes:
    arcs = [int(part) for part in dotted.split(".")]
    if len(arcs) < 2 or arcs[0] > 2 or (arcs[0] < 2 and arcs[1] >= 40):
        raise ValueError(f"invalid object identifier: {dotted}")
    body = bytearray()
    for arc in [arcs[0] * 40 + arcs[1]] + arcs[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        body.extend(reversed(chunk))
    return encode_tlv(OID, bytes(body))


def encode_octets(value: bytes) -> bytes:
    return encode_tlv(OCTET_STRING, value)


def encode_bits(value: bytes) -> bytes:
    return encode_tlv(BIT_STRING, b"\x00" + value)


def encode_seq(*parts: bytes) -> bytes:
    return encode_tlv(0x20 | SEQUENCE, b"".join(parts))


def encode_set(parts: Iterable[bytes]) -> bytes:
    """A SET OF with its members in the sorted order DER requires."""
    return encode_tlv(0x20 | SET, b"".join(sorted(parts)))


def encode_context(tag: int, content: bytes, constructed: bool = True) -> bytes:
    return encode_tlv(0x80 | (0x20 if constructed else 0) | tag, content)


def encode_utf8(text: str) -> bytes:
    return encode_tlv(UTF8_STRING, text.encode("utf-8"))


def encode_time(moment: datetime) -> bytes:
    """GeneralizedTime with whole seconds."""
    moment = moment.astimezone(timezone.utc)
    return encode_tlv(GENERALIZED_TIME, moment.strftime("%Y%m%d%H%M%SZ").encode("ascii"))


def encode_utc_time(moment: datetime) -> bytes:
    moment = moment.astimezone(timezone.utc)
    return encode_tlv(UTC_TIME, moment.strftime("%y%m%d%H%M%SZ").encode("ascii"))


def epoch_seconds(moment: datetime) -> int:
    """Seconds since 1970 as a whole number, rounded down."""
    return (moment - datetime(1970, 1, 1, tzinfo=timezone.utc)) // timedelta(seconds=1)
