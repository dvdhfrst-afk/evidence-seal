"""A small PDF writer, enough for a report a reviewer can read and print.

It writes PDF 1.4 using three of the standard fonts every PDF reader has (Helvetica, Helvetica-Bold
and Courier), so no font is embedded. Those fonts cover the WinAnsi character set. Any other character
is written as a visible escape such as ``\\u4e2d``, and ``Document.substituted`` says that it happened,
so the page can say so too.

Text flows down the page with word wrapping, tables wrap inside their cells, and a new page starts
when one is full. Every page gets a footer with its number. The output depends only on what was added,
so the same content always gives the same bytes.
"""

from __future__ import annotations

import hashlib
import unicodedata
from datetime import datetime
from typing import List, Optional, Sequence, Tuple

A4 = (595.0, 842.0)
HELVETICA = "Helvetica"
BOLD = "Helvetica-Bold"
COURIER = "Courier"
FONTS = (HELVETICA, BOLD, COURIER)
_FONT_NAMES = {HELVETICA: "F1", BOLD: "F2", COURIER: "F3"}

# Advance widths in thousandths of the font size, from the fonts' published metrics, for space to tilde.
_ASCII_WIDTHS = {
    HELVETICA: (
        278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
        556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
        1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
        667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
        333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
        556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
    ),
    BOLD: (
        278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278,
        556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611,
        975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778,
        667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556,
        333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611,
        611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584,
    ),
}
# The rest of WinAnsi that is not an accented letter, at the wider of the two Helvetica weights.
_OTHER_WIDTHS = {
    "\u20ac": 556, "\u201a": 278, "\u0192": 556, "\u201e": 500, "\u2026": 1000, "\u2020": 556, "\u2021": 556,
    "\u02c6": 333, "\u2030": 1000, "\u2039": 333, "\u0152": 1000, "\u2018": 278, "\u2019": 278, "\u201c": 500,
    "\u201d": 500, "\u2022": 350, "\u2013": 556, "\u2014": 1000, "\u02dc": 333, "\u2122": 1000, "\u203a": 333,
    "\u0153": 944, "\xa0": 278, "\xa1": 333, "\xa2": 556, "\xa3": 556, "\xa4": 556, "\xa5": 556, "\xa6": 280,
    "\xa7": 556, "\xa8": 333, "\xa9": 737, "\xaa": 370, "\xab": 556, "\xac": 584, "\xae": 737, "\xaf": 333,
    "\xb0": 400, "\xb1": 584, "\xb2": 333, "\xb3": 333, "\xb4": 333, "\xb5": 611, "\xb6": 556, "\xb7": 278,
    "\xb8": 333, "\xb9": 333, "\xba": 365, "\xbb": 556, "\xbc": 834, "\xbd": 834, "\xbe": 834, "\xbf": 611,
    "\xc6": 1000, "\xd0": 722, "\xd7": 584, "\xd8": 778, "\xde": 667, "\xdf": 611, "\xe6": 889, "\xf0": 611,
    "\xf7": 584, "\xf8": 611, "\xfe": 611,
}
_WIDEST = 1000
_LINE_COLOR = "0.7 G"


def char_width(char: str, font: str) -> int:
    """The width of one character that ``to_winansi`` let through, in thousandths of the font size."""
    if font == COURIER:
        return 600
    code = ord(char)
    if 0x20 <= code <= 0x7E:
        return _ASCII_WIDTHS[font][code - 0x20]
    if char in _OTHER_WIDTHS:
        return _OTHER_WIDTHS[char]
    base = unicodedata.normalize("NFD", char)[0]
    if base.isascii() and base.isalpha():
        # An accented letter is as wide as its letter, except that an accented i is wider than a plain one.
        return max(_ASCII_WIDTHS[font][ord(base) - 0x20], 278 if base in "iI" else 0)
    return _WIDEST


def text_width(text: str, font: str, size: float) -> float:
    return sum(char_width(char, font) for char in text) * size / 1000


def to_winansi(text: str) -> Tuple[str, bool]:
    """The text with every character these fonts cannot show written as an escape, and whether any was."""
    if text.isascii() and text.isprintable():
        return text, False
    out: List[str] = []
    changed = False
    for char in text:
        code = ord(char)
        if 0x20 <= code <= 0x7E:
            out.append(char)
            continue
        if code >= 0xA0 and unicodedata.category(char) not in ("Cf", "Cs", "Co", "Cn", "Zl", "Zp"):
            try:
                char.encode("cp1252")
                out.append(char)
                continue
            except UnicodeEncodeError:
                pass
        changed = True
        if code <= 0xFF:
            out.append(f"\\x{code:02x}")
        elif code <= 0xFFFF:
            out.append(f"\\u{code:04x}")
        else:
            out.append(f"\\U{code:08x}")
    return "".join(out), changed


def _literal(data: bytes) -> bytes:
    """A PDF literal string. Bytes outside printable ASCII are written in octal, so the file stays plain."""
    out = bytearray(b"(")
    for byte in data:
        if byte in b"()\\":
            out += b"\\" + bytes([byte])
        elif 0x20 <= byte <= 0x7E:
            out.append(byte)
        else:
            out += b"\\%03o" % byte
    out += b")"
    return bytes(out)


def _info_string(text: str) -> bytes:
    """A document information string: plain ASCII as it is, anything else as UTF-16 with a byte order mark."""
    if text.isascii() and text.isprintable():
        return _literal(text.encode("ascii"))
    encoded = "".join(char for char in text if not 0xD800 <= ord(char) <= 0xDFFF).encode("utf-16-be")
    return b"<FEFF" + encoded.hex().upper().encode("ascii") + b">"


def _number(value: float) -> str:
    text = f"{value:.2f}".rstrip("0").rstrip(".")
    return "0" if text in ("", "-0") else text


def pdf_date(moment: datetime) -> str:
    return moment.strftime("D:%Y%m%d%H%M%SZ")


class Document:
    """Pages built from top to bottom. Add paragraphs and tables, then call ``to_bytes``."""

    def __init__(
        self,
        title: str,
        subject: str = "",
        producer: str = "",
        created: Optional[datetime] = None,
        footer: str = "",
        page_size: Tuple[float, float] = A4,
        margin: float = 54.0,
    ):
        self.title = title
        self.subject = subject
        self.producer = producer
        self.created = created
        self.footer = footer
        self.width, self.height = page_size
        self.margin = margin
        self.substituted = False
        self.pages: List[List[str]] = []
        self.y = 0.0
        self._new_page()

    @property
    def text_width(self) -> float:
        return self.width - 2 * self.margin

    @property
    def _bottom(self) -> float:
        return self.margin + 18

    def _new_page(self) -> None:
        self.pages.append([])
        self.y = self.height - self.margin

    def _room_for(self, height: float) -> None:
        if self.y - height < self._bottom and self.pages[-1]:
            self._new_page()

    def _draw(self, x: float, baseline: float, text: str, font: str, size: float) -> None:
        if not text:
            return
        encoded = _literal(text.encode("cp1252"))
        self.pages[-1].append(
            f"BT /{_FONT_NAMES[font]} {_number(size)} Tf {_number(x)} {_number(baseline)} Td "
            + encoded.decode("ascii")
            + " Tj ET"
        )

    def _rule(self, y: float) -> None:
        self.pages[-1].append(
            f"{_LINE_COLOR} 0.5 w {_number(self.margin)} {_number(y)} m {_number(self.width - self.margin)} {_number(y)} l S 0 G"
        )

    def wrap(self, text: str, font: str, size: float, width: float) -> List[str]:
        """Splits text into lines that fit the width, breaking inside a word only when it is wider than a line."""
        shown, changed = to_winansi(text)
        self.substituted = self.substituted or changed
        lines: List[str] = []
        space = char_width(" ", font) * size / 1000
        for piece in shown.split("\n"):
            current: List[str] = []
            current_width = 0.0
            for word in piece.split(" "):
                word_width = text_width(word, font, size)
                extra = (space if current else 0.0) + word_width
                if current_width + extra <= width:
                    current.append(word)
                    current_width += extra
                    continue
                if current:
                    lines.append(" ".join(current))
                current, current_width = [], 0.0
                if word_width <= width:
                    current, current_width = [word], word_width
                    continue
                chunk = ""
                chunk_width = 0.0
                for char in word:
                    char_size = char_width(char, font) * size / 1000
                    if chunk and chunk_width + char_size > width:
                        lines.append(chunk)
                        chunk, chunk_width = "", 0.0
                    chunk += char
                    chunk_width += char_size
                current, current_width = [chunk], chunk_width
            lines.append(" ".join(current))
        return lines

    def space(self, points: float) -> None:
        self.y -= points

    def keep(self, height: float) -> None:
        """Starts a new page now unless this much room is left, so short parts that belong together stay together."""
        self._room_for(height)

    def paragraph(
        self,
        text: str,
        font: str = HELVETICA,
        size: float = 9.5,
        indent: float = 0.0,
        after: float = 3.0,
        marker: str = "",
    ) -> None:
        """Wrapped text. A marker, such as a bullet or a step number, hangs to the left of the first line."""
        leading = size * 1.3
        for number, line in enumerate(self.wrap(text, font, size, self.text_width - indent)):
            self._room_for(leading)
            if number == 0 and marker:
                self._draw(self.margin + indent - text_width(marker, HELVETICA, size) - 4, self.y - size, marker, HELVETICA, size)
            self._draw(self.margin + indent, self.y - size, line, font, size)
            self.y -= leading
        self.y -= after

    def bullet(self, text: str, size: float = 9.5) -> None:
        self.paragraph(text, size=size, indent=12.0, after=1.5, marker="\u2022")

    def heading(self, text: str, size: float = 11.0) -> None:
        self._room_for(size * 4)
        self.y -= size * 0.6
        self.paragraph(text, BOLD, size, after=1.0)
        self._rule(self.y + 0.5)
        self.y -= 4

    def table(
        self,
        rows: Sequence[Sequence[Tuple[str, str]]],
        widths: Sequence[float],
        size: float = 9.0,
        header: Optional[Sequence[str]] = None,
    ) -> None:
        """Rows of (text, font) cells. Widths are shares of the line. A row taller than a page carries on onto the next."""
        leading = size * 1.3
        gutter = 8.0
        total = sum(widths)
        columns = [self.text_width * share / total for share in widths]
        starts = [self.margin + sum(columns[:index]) for index in range(len(columns))]
        everything = ([[(name, BOLD) for name in header]] if header else []) + [list(row) for row in rows]
        for number, row in enumerate(everything):
            cells = [
                self.wrap(text, font, size, columns[index] - gutter) for index, (text, font) in enumerate(row)
            ]
            self._room_for(leading * min(2, max(len(lines) for lines in cells)))
            for line_number in range(max(len(lines) for lines in cells)):
                self._room_for(leading)
                for index, lines in enumerate(cells):
                    if line_number < len(lines):
                        self._draw(starts[index], self.y - size, lines[line_number], row[index][1], size)
                self.y -= leading
            self.y -= 2
            if number < len(everything) - 1:
                self._rule(self.y + 1)
                self.y -= 3
        self.y -= 4

    def _footer(self, number: int, count: int) -> str:
        size = 8.0
        baseline = self.margin - 20
        parts: List[str] = []
        label = f"Page {number} of {count}"
        right = self.width - self.margin - text_width(label, HELVETICA, size)
        for x, text in ((self.margin, to_winansi(self.footer)[0]), (right, label)):
            parts.append(
                f"BT /F1 {_number(size)} Tf {_number(x)} {_number(baseline)} Td "
                + _literal(text.encode("cp1252")).decode("ascii")
                + " Tj ET"
            )
        return "\n".join(parts)

    def to_bytes(self) -> bytes:
        count = len(self.pages)
        first_page = 7
        kids = " ".join(f"{first_page + 2 * index} 0 R" for index in range(count))
        info = [b"/Title " + _info_string(self.title)]
        if self.subject:
            info.append(b"/Subject " + _info_string(self.subject))
        if self.producer:
            info.append(b"/Producer " + _info_string(self.producer) + b" /Creator " + _info_string(self.producer))
        if self.created is not None:
            info.append(b"/CreationDate " + _literal(pdf_date(self.created).encode("ascii")))
        objects: List[bytes] = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            f"<< /Type /Pages /Kids [{kids}] /Count {count} >>".encode("ascii"),
            b"<< " + b" ".join(info) + b" >>",
        ]
        for font in FONTS:
            objects.append(f"<< /Type /Font /Subtype /Type1 /BaseFont /{font} /Encoding /WinAnsiEncoding >>".encode("ascii"))
        fonts = " ".join(f"/{_FONT_NAMES[font]} {4 + index} 0 R" for index, font in enumerate(FONTS))
        for index, operations in enumerate(self.pages):
            content = "\n".join(operations + [self._footer(index + 1, count)]).encode("ascii")
            objects.append(
                (
                    f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {_number(self.width)} {_number(self.height)}]"
                    f" /Resources << /Font << {fonts} >> >> /Contents {first_page + 2 * index + 1} 0 R >>"
                ).encode("ascii")
            )
            objects.append(
                f"<< /Length {len(content)} >>\nstream\n".encode("ascii") + content + b"\nendstream"
            )
        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets: List[int] = []
        for number, body in enumerate(objects, 1):
            offsets.append(len(out))
            out += f"{number} 0 obj\n".encode("ascii") + body + b"\nendobj\n"
        identifier = hashlib.sha256(bytes(out)).hexdigest()[:32].upper()
        start = len(out)
        out += f"xref\n0 {len(objects) + 1}\n".encode("ascii")
        out += b"0000000000 65535 f\r\n"
        for offset in offsets:
            out += f"{offset:010d} 00000 n\r\n".encode("ascii")
        out += (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R /Info 3 0 R /ID [<{identifier}> <{identifier}>] >>\n"
            f"startxref\n{start}\n%%EOF\n"
        ).encode("ascii")
        return bytes(out)
