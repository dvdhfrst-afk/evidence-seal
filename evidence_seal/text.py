"""Keeps text from files, tokens and folders from acting on the reader's screen.

A manifest, a certificate or a file name can hold anything, including line feeds
that would fake a result line, terminal escape codes, and characters that reverse
how a line displays. Everything shown to a person passes through ``printable``,
one line at a time, so a value can never start a line of its own.
"""

from __future__ import annotations

import unicodedata

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
