"""Every report format, in the one table that the report command, file names and companion files all use.

For other parts of the tool:

- ``REPORT_FORMATS``: each ``ReportFormat`` has a name, a file suffix, a media type, whether it is binary,
  a one-line description, and ``render(verification, context) -> bytes``.
- ``by_name(name)``, ``FORMAT_NAMES`` and ``REPORT_SUFFIXES`` look them up.
- ``default_report_path(manifest_path, name)`` is where a report goes when no ``--out`` is given.
- ``REPORT_SCHEMA_VERSION`` is the number in the JSON report, with the promise in docs/REPORTS.md.

Every format says the same things as the text report, and shows text from outside (file names, the
purpose, certificate names) only in a form that format cannot act on.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import manifest, pdf, render
from .reporting import (
    DEPENDS_ON,
    DOES_NOT_SHOW,
    SHOWS,
    ReportContext,
    claim_rows,
    openssl_commands,
    render_report_html,
    render_report_text,
    result_rows,
)
from .results import Status, Verification
from .text import csv_table, markdown_block, markdown_text, printable, xml_text

REPORT_SCHEMA_VERSION = 1

NOT_FROM_THIS_FILE = (
    "This file is a summary and proves nothing by itself, since anyone could edit it. The results come from"
    " checking the manifest and the token, and the commands above let anyone repeat those checks."
)
SUBSTITUTED_NOTE = (
    "Some characters cannot be shown with this PDF's fonts. They are written as a backslash code such as"
    " \\u4e2d, the character's Unicode number. The text and HTML reports show them as they are."
)
FILE_COLUMNS = (
    "path",
    "outcome",
    "found_path",
    "algorithm",
    "expected_hash",
    "found_hash",
    "expected_size",
    "found_size",
)


@dataclass(frozen=True)
class ReportFormat:
    name: str
    suffix: str
    media_type: str
    binary: bool
    description: str
    render: Callable[[Verification, ReportContext], bytes]


def _text(verification: Verification, context: ReportContext) -> bytes:
    return render_report_text(verification, context).encode("utf-8")


def _html(verification: Verification, context: ReportContext) -> bytes:
    return render_report_html(verification, context).encode("utf-8")


def report_dict(verification: Verification, context: ReportContext) -> Dict[str, Any]:
    """The JSON report: the whole verify JSON, plus what the page says and the commands to repeat the checks."""
    return {
        "report_schema": REPORT_SCHEMA_VERSION,
        "result": verification.overall,
        "summary": render.summary_sentence(verification),
        "claims": [{"label": label, "value": value} for label, value in claim_rows(verification, context)],
        "commands": [
            {"step": number, "explanation": explanation, "command": command or None}
            for number, (explanation, command) in enumerate(openssl_commands(verification, context), 1)
        ],
        "shows": list(SHOWS),
        "does_not_show": list(DOES_NOT_SHOW) + verification.limits[:1],
        "depends_on": list(DEPENDS_ON),
        "verification": verification.to_dict(),
    }


def _json(verification: Verification, context: ReportContext) -> bytes:
    return (json.dumps(report_dict(verification, context), indent=2) + "\n").encode("ascii")


def _markdown(verification: Verification, context: ReportContext) -> bytes:
    m = markdown_text
    lines: List[str] = [
        "# Evidence seal report",
        "",
        f"Checked {m(verification.checked_at)} by evidence-seal {m(verification.tool_version)}",
        "",
        f"**Result: {m(verification.overall)}**",
        "",
        m(render.summary_sentence(verification)),
        "",
        "## What is claimed",
        "",
    ]
    lines.extend(f"- {m(label)}: {m(value)}" for label, value in claim_rows(verification, context))
    lines.extend(["", "## Results of this check (each one separate)", "", "| Check | Result | Detail |", "| --- | --- | --- |"])
    for title, word, detail in result_rows(verification):
        lines.append(f"| {m(title, True)} | {m(word, True)} | {m(detail, True)} |")
    if verification.notes:
        lines.extend(["", "## Notes", ""])
        lines.extend(f"- {m(note)}" for note in verification.notes)
    steps = openssl_commands(verification, context)
    if steps:
        lines.extend(["", "## Check it yourself, without trusting this tool", ""])
        lines.extend(["Run these in the folder holding the manifest and token:", ""])
        for number, (explanation, command) in enumerate(steps, 1):
            marker = f"{number}. "
            lines.append(marker + m(explanation))
            if command:
                lines.append("")
                lines.extend(markdown_block(command, " " * len(marker)))
            lines.append("")
        lines.pop()
    for heading, items in (
        ("What this shows", list(SHOWS)),
        ("What this does not show", list(DOES_NOT_SHOW) + verification.limits[:1]),
        ("What it depends on", list(DEPENDS_ON)),
    ):
        lines.extend(["", f"## {heading}", ""])
        lines.extend(f"- {m(item)}" for item in items)
    lines.extend(["", m(NOT_FROM_THIS_FILE)])
    return ("\n".join(lines) + "\n").encode("utf-8")


def file_cells(row) -> Tuple[object, ...]:
    """One CSV row for a file. Paths are written as the manifest writes them, with backslash escapes."""
    return (
        manifest.escape_text(row.path),
        row.outcome,
        manifest.escape_text(row.found_path) if row.found_path is not None else "",
        row.algorithm or "",
        row.expected_hash or "",
        row.found_hash or "",
        "" if row.expected_size is None else row.expected_size,
        "" if row.found_size is None else row.found_size,
    )


def _csv(verification: Verification, context: ReportContext) -> bytes:
    return csv_table(FILE_COLUMNS, (file_cells(row) for row in verification.file_rows))


def _junit(verification: Verification, context: ReportContext) -> bytes:
    x = xml_text
    checks = verification.checks
    failed = sum(1 for check in checks if check.status is not Status.PASS)
    suite = f"evidence-seal report for {context.manifest_file}"
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<testsuites name="evidence-seal" tests="{len(checks)}" failures="{failed}" errors="0" skipped="0">',
        f'  <testsuite name="{x(suite)}" tests="{len(checks)}" failures="{failed}" errors="0" skipped="0">',
        "    <properties>",
    ]
    properties = [
        ("result", verification.overall),
        ("manifest", context.manifest_file),
        ("manifest_sha256", verification.manifest_sha256),
        ("token", context.token_file or ""),
        ("checked_at", verification.checked_at),
        ("tool_version", verification.tool_version),
    ]
    lines.extend(f'      <property name="{x(name)}" value="{x(value)}"/>' for name, value in properties)
    lines.append("    </properties>")
    for check, (title, word, detail) in zip(checks, result_rows(verification)):
        opening = f'    <testcase classname="evidence-seal.{x(check.key)}" name="{x(title)}" time="0"'
        if check.status is Status.PASS:
            lines.append(opening + "/>")
            continue
        message = detail if check.status is Status.FAIL else f"not checked: {detail}"
        lines.append(opening + ">")
        lines.append(f'      <failure type="{x(word)}" message="{x(message)}">{x(message)}</failure>')
        lines.append("    </testcase>")
    out = [render.summary_sentence(verification)] + verification.notes
    lines.append(f"    <system-out>{x(' '.join(out))}</system-out>")
    lines.extend(["  </testsuite>", "</testsuites>"])
    return ("\n".join(lines) + "\n").encode("utf-8")


def _checked_moment(verification: Verification) -> Optional[datetime]:
    try:
        return datetime.strptime(verification.checked_at[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _pdf(verification: Verification, context: ReportContext) -> bytes:
    p = printable
    doc = pdf.Document(
        title="Evidence seal report",
        subject=p(context.manifest_file),
        producer=f"evidence-seal {p(verification.tool_version)}",
        created=_checked_moment(verification),
        footer=f"Evidence seal report, checked {p(verification.checked_at)}",
    )
    doc.paragraph("Evidence seal report", pdf.BOLD, 16, after=2)
    doc.paragraph(f"Checked {p(verification.checked_at)} by evidence-seal {p(verification.tool_version)}")
    doc.space(4)
    doc.paragraph(f"RESULT: {verification.overall}", pdf.BOLD, 13, after=2)
    doc.paragraph(p(render.summary_sentence(verification)))
    doc.heading("What is claimed")
    doc.table([[(p(label), pdf.BOLD), (p(value), pdf.HELVETICA)] for label, value in claim_rows(verification, context)], (34, 66))
    doc.heading("Results of this check (each one separate)")
    doc.table(
        [[(p(title), pdf.BOLD), (word, pdf.BOLD), (p(detail), pdf.HELVETICA)] for title, word, detail in result_rows(verification)],
        (30, 13, 57),
        header=("Check", "Result", "Detail"),
    )
    if verification.notes:
        doc.heading("Notes")
        for note in verification.notes:
            doc.bullet(p(note))
    steps = openssl_commands(verification, context)
    if steps:
        doc.heading("Check it yourself, without trusting this tool")
        doc.paragraph("Run these in the folder holding the manifest and token:")
        for number, (explanation, command) in enumerate(steps, 1):
            doc.keep(40)
            doc.paragraph(p(explanation), indent=16, after=1.5, marker=f"{number}.")
            if command:
                doc.paragraph(p(command), pdf.COURIER, 7.5, indent=16, after=4)
    for heading, items in (
        ("What this shows", list(SHOWS)),
        ("What this does not show", list(DOES_NOT_SHOW) + verification.limits[:1]),
        ("What it depends on", list(DEPENDS_ON)),
    ):
        doc.heading(heading)
        for item in items:
            doc.bullet(p(item))
    doc.heading("About this file")
    doc.paragraph(NOT_FROM_THIS_FILE)
    if doc.substituted:
        doc.paragraph(SUBSTITUTED_NOTE)
    return doc.to_bytes()


REPORT_FORMATS: Tuple[ReportFormat, ...] = (
    ReportFormat("text", ".report.txt", "text/plain; charset=utf-8", False, "one page of plain text", _text),
    ReportFormat("html", ".report.html", "text/html; charset=utf-8", False, "one web page, also for printing", _html),
    ReportFormat(
        "json", ".report.json", "application/json", False, "the verify JSON plus the claims and commands", _json
    ),
    ReportFormat(
        "markdown", ".report.md", "text/markdown; charset=utf-8", False, "for a code hosting site or a ticket", _markdown
    ),
    ReportFormat("csv", ".report.csv", "text/csv; charset=utf-8", False, "one row per file, for a spreadsheet", _csv),
    ReportFormat("junit", ".report.junit.xml", "application/xml", False, "JUnit XML, one test per check, for CI", _junit),
    ReportFormat("pdf", ".report.pdf", "application/pdf", True, "a PDF to print or attach", _pdf),
)
_BY_NAME = {item.name: item for item in REPORT_FORMATS}
FORMAT_NAMES: Tuple[str, ...] = tuple(item.name for item in REPORT_FORMATS)
REPORT_SUFFIXES: Tuple[str, ...] = tuple(item.suffix for item in REPORT_FORMATS)


def by_name(name: str) -> ReportFormat:
    try:
        return _BY_NAME[name]
    except KeyError:
        raise ValueError(f"unknown report format {name!r}; choose one of {', '.join(FORMAT_NAMES)}") from None


def default_report_path(manifest_path: Path, name: str) -> Path:
    return Path(manifest_path).with_suffix(by_name(name).suffix)
