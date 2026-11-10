"""Keeps text from files, tokens and folders from acting on the reader's screen.

A manifest, a certificate or a file name can hold anything, including line feeds
that would fake a result line, terminal escape codes, and characters that reverse
how a line displays. Everything shown to a person passes through ``printable``,
one line at a time, so a value can never start a line of its own.

The other helpers here do the same job for formats that give characters a meaning of their own:
Markdown, XML and spreadsheets.
"""

from __future__ import annotations

import csv
import io
import re
import unicodedata
from typing import Iterable, List, Sequence

_KEPT_FORMAT_CHARACTERS = {chr(0x200C), chr(0x200D)}  # Joiners that some scripts and emoji need to display correctly
_ESCAPED_CATEGORIES = {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}


def _escape(char: str) -> str:
    code = ord(char)
    if 0xDC80 <= code <= 0xDCFF:
        return f"\\x{code - 0xDC00:02x}"
    if code <= 0xFF:
        return f"\\x{code:02x}"
    if code <= 0xFFFF:
        return f"\\u{code:04x}"
    return f"\\U{code:08x}"


def printable(text: object) -> str:
    """The same text with every control, formatting and unassigned character written as an escape."""
    value = str(text)
    if value.isascii() and value.isprintable():
        return value
    return "".join(
        _escape(char)
        if unicodedata.category(char) in _ESCAPED_CATEGORIES and char not in _KEPT_FORMAT_CHARACTERS
        else char
        for char in value
    )


def printable_block(lines) -> str:
    """Joins lines for output. The line feeds in the result are only the ones between items."""
    return "\n".join(printable(line) for line in lines) + "\n"


def count_of(count: int, noun: str) -> str:
    """``1 file`` and ``2 files``."""
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def same_text_form(text: str) -> str:
    """The form used to compare names, since macOS and Linux can store the same name differently."""
    return text if text.isascii() else unicodedata.normalize("NFC", text)


# Characters that mean nothing to Markdown in the middle of a line, so plain text made of them shows as written.
_MARKDOWN_PLAIN = set(" ,.;:'\"()/?=%!+>-")
# Turned into links or pictures by code hosting sites even with no markup: web addresses and emoji names.
_MARKDOWN_AUTOLINKED = re.compile(r"www\.|://|:(?:[A-Za-z0-9_+-]*[A-Za-z_+-][A-Za-z0-9_+-]*|100|1234):", re.IGNORECASE)
_MARKDOWN_LIST_START = re.compile(r"^[0-9]{1,9}[.)](?:\s|$)")


def _longest_backtick_run(text: str) -> int:
    return max((len(run) for run in re.findall(r"`+", text)), default=0)


def markdown_code(text: str, in_table: bool = False) -> str:
    """An inline code span, inside which Markdown reads no markup, links, entities or HTML at all."""
    fence = "`" * (_longest_backtick_run(text) + 1)
    if in_table:
        text = text.replace("|", "\\|")
    return f"{fence} {text} {fence}"


def markdown_text(value: object, in_table: bool = False) -> str:
    """Outside text for a Markdown page. Plain words stay as they are, and anything else becomes a code span."""
    text = printable(value)
    if not text:
        return ""
    plain = (
        text[0].isalnum()
        and all(char.isalnum() or char in _MARKDOWN_PLAIN for char in text)
        and not _MARKDOWN_AUTOLINKED.search(text)
        and not _MARKDOWN_LIST_START.match(text)
    )
    return text if plain else markdown_code(text, in_table)


def markdown_block(value: object, indent: str = "") -> List[str]:
    """A fenced code block, with a fence longer than any run of backticks inside, so nothing can close it early."""
    text = printable(value)
    fence = "`" * max(3, _longest_backtick_run(text) + 1)
    return [indent + fence, indent + text, indent + fence]


def xml_text(value: object) -> str:
    """Text for an XML element or attribute. Characters XML 1.0 cannot hold are already escaped by ``printable``."""
    text = printable(value)
    for char, entity in (("&", "&amp;"), ("<", "&lt;"), (">", "&gt;"), ('"', "&quot;"), ("'", "&apos;")):
        text = text.replace(char, entity)
    return text


# A spreadsheet runs a cell that starts with one of these as a formula. Full-width forms count in some of them.
_FORMULA_STARTS = ("=", "+", "-", "@", "\t", "\r", "\n", "'", "\uff1d", "\uff0b", "\uff0d", "\uff20")


def spreadsheet_cell(value: object) -> str:
    """A CSV cell no spreadsheet will run. One leading apostrophe is added to any cell that starts like a formula,
    or with an apostrophe, so removing one leading apostrophe always gives the value back."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_FORMULA_STARTS) else text


def csv_table(header: Sequence[str], rows: Iterable[Sequence[object]]) -> bytes:
    """UTF-8 CSV with CRLF line ends, as RFC 4180 has it, and every cell made safe for spreadsheets.

    Text from outside must already be escaped so it holds no control characters, as the manifest writes it."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(header)
    for row in rows:
        writer.writerow([spreadsheet_cell(cell) for cell in row])
    return buffer.getvalue().encode("utf-8")
