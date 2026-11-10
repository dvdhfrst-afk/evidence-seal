"""Printing for every command: safe text, progress lines, and commands a user can paste."""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Callable, Optional

from . import reporting, scan
from .text import printable

_PROGRESS_SECONDS = 1.0


def say(text: str = "") -> None:
    print(printable(text))


def warn(text: str) -> None:
    print(printable(text), file=sys.stderr)


def size_text(count: float) -> str:
    for unit in ("bytes", "KB", "MB", "GB"):
        if count < 1024:
            return f"{count:.0f} {unit}" if unit == "bytes" else f"{count:.1f} {unit}"
        count /= 1024
    return f"{count:.1f} TB"


def progress(verb: str) -> Optional[Callable[[scan.Meter], None]]:
    """A line that updates on a terminal, so a long run does not look stuck. Never written into pipes or files."""
    try:
        if not sys.stderr.isatty():
            return None
    except (AttributeError, ValueError):
        return None
    last = [time.monotonic()]

    def show(meter: scan.Meter) -> None:
        now = time.monotonic()
        if now - last[0] < _PROGRESS_SECONDS:
            return
        last[0] = now
        sys.stderr.write(
            f"\r{verb} {meter.files} of {meter.total_files} files,"
            f" {size_text(meter.bytes)} of {size_text(meter.total_bytes)}   "
        )
        sys.stderr.flush()

    return show


def clear_progress(report: Optional[Callable[[scan.Meter], None]]) -> None:
    if report is not None:
        sys.stderr.write("\r" + " " * 70 + "\r")
        sys.stderr.flush()


def self_command() -> str:
    """How this copy was started, so a suggested command works when pasted."""
    name = Path(sys.argv[0]).name if sys.argv and sys.argv[0] else ""
    return "python -m evidence_seal" if name in ("__main__.py", "-m") else "evidence-seal"


def shown(path: Path) -> str:
    return reporting.quote_argument(str(path))


def write_utf8(text: str) -> None:
    """Sends UTF-8 whatever this console uses, because an HTML report says that is what it holds."""
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is None:
        sys.stdout.write(text)
        return
    sys.stdout.flush()
    buffer.write(text.encode("utf-8"))
    buffer.flush()
