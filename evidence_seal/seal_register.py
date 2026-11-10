"""The evidence register: one document listing the seals in this computer's library.

The register is an index made from the library alone. It checks nothing and proves nothing by itself,
and says so in every format, together with how each seal can be checked without it.

For other parts of the tool:

- ``REGISTER_FORMATS``: the format names, the default first.
- ``build_register(library, tag, folder, since, until) -> Register``: the chosen seals in register order,
  each as plain data (the ``seals`` list of the JSON register). ``library`` may be None.
- ``render_register(register, name) -> bytes``: one format. The same library gives the same bytes.
- ``note_heading(note)`` and ``note_lines(note)``: how a note reads, for anything that shows notes.

Order: by the seal's date (the time in its current token, or the created claim when it has no token),
oldest first, then by the full ID. A seal with no date of either kind comes last.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import __version__, pdf
from . import library as lib
from .reporting import HTML_STYLE
from .text import count_of, csv_table, markdown_block, markdown_text, printable, printable_block, xml_text

REGISTER_SCHEMA_VERSION = 1
REGISTER_FORMATS = ("text", "csv", "json", "markdown", "html", "pdf")

ORDER = (
    "Seals are listed by their date, oldest first: the time in the current timestamp token, or the created"
    " claim for a seal with no token. Seals with the same date are listed by full ID, and a seal with no date"
    " comes last."
)
WHAT_IT_IS = (
    "This register is an index made from the seal library on the computer that wrote it. It proves nothing by"
    " itself, since anyone could edit it.",
    "Each seal's proof is its manifest and its timestamp token. The full ID of each entry is the SHA-256 of its"
    " manifest, so anyone can match a manifest file to its entry without trusting this register.",
    "The last verification is what that computer recorded when it last checked the seal, not a check made now.",
    "Purposes, created dates, folder names, tags and notes were written by people. They are claims, not proof.",
    "A withdrawn note is kept and marked withdrawn, because a record of evidence is never quietly rewritten.",
)
PLACEHOLDERS = (
    "In these commands MANIFEST is the seal's manifest file, TOKEN its timestamp token (the .tsr file beside it),"
    " ROOT the authority's root certificate and FOLDER the sealed folder. For a bare token (a .tst file), add"
    " -token_in after TOKEN in the two openssl ts commands."
)
CHECKS = (
    ("Match the manifest to its entry. The hash this prints must be the entry's full ID:", "openssl dgst -sha256 MANIFEST"),
    ("Check the seal, every file included, with evidence-seal:", "evidence-seal verify MANIFEST --folder FOLDER --ca ROOT"),
    (
        "Or check it without trusting evidence-seal. Get the authority's root certificate from the authority itself,"
        " and compare its fingerprint with what the authority publishes:",
        "openssl x509 -in ROOT -noout -fingerprint -sha256",
    ),
    ("Check the token against the manifest and that root. A good token prints Verification: OK.", "openssl ts -verify -data MANIFEST -in TOKEN -CAfile ROOT"),
    ("Read what the token says. Its time, authority and serial should be the ones in the entry:", "openssl ts -reply -in TOKEN -text"),
    ("Check any file against its line in the manifest. Run it inside the sealed folder:", "openssl dgst -sha256 FILE"),
)
NOT_PROOF = "This register is an index made from this computer's seal library. It proves nothing by itself."
SUBSTITUTED_NOTE = (
    "Some characters cannot be shown with this PDF's fonts. They are written as a backslash code such as"
    " \\u4e2d, the character's Unicode number. The text and HTML registers show them as they are."
)
CSV_COLUMNS = (
    "number",
    "id",
    "manifest_sha256",
    "purpose",
    "created",
    "folder_name",
    "folder_path",
    "manifest_path",
    "file_count",
    "total_bytes",
    "token_time",
    "authority",
    "serial",
    "replaced_tokens",
    "last_result",
    "last_checked",
    "tags",
    "notes",
)
JOIN = " | "
_MOMENT = re.compile(r"^([0-9]{4}-[0-9]{2}-[0-9]{2})(?:[T ]([0-9]{2}:[0-9]{2}:[0-9]{2}))?")


@dataclass
class Register:
    seals: List[Dict[str, Any]]
    as_of: Optional[str]
    chosen: Dict[str, Optional[str]]
    tool_version: str = __version__


def moment_key(text: Optional[str]) -> Optional[str]:
    """``YYYY-MM-DD HH:MM:SS`` from a token time or a created claim, or None when it holds no date."""
    found = _MOMENT.match(str(text)) if text else None
    if found is None:
        return None
    return f"{found.group(1)} {found.group(2) or '00:00:00'}"


def _token(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "time": row["token_time"],
        "authority": row["authority"],
        "serial": row["serial"],
        "token_sha256": row["token_sha256"],
        "token_path": row["token_path"],
    }


def _entry(library: lib.Library, row: Dict[str, Any]) -> Dict[str, Any]:
    sha = row["manifest_sha256"]
    current = library.current_token(sha)
    replaced = sorted(
        (token for token in library.tokens(sha) if not token["is_current"]),
        key=lambda token: (str(token["token_time"] or ""), token["token_sha256"]),
    )
    runs = library.runs(sha, 1)
    last = {"result": runs[0]["overall"], "at": runs[0]["run_at"], "command": runs[0]["command"]} if runs else None
    notes = [
        {key: note[key] for key in ("number", "at", "tool_version", "text", "withdraws", "withdrawn_by")}
        for note in library.notes(sha)
    ]
    return {
        "number": 0,
        "id": lib.short_id(sha),
        "manifest_sha256": sha,
        "purpose": row["purpose"],
        "created": row["created"],
        "folder_name": row["folder_name"],
        "folder_path": row["folder_path"],
        "manifest_path": row["manifest_path"],
        "manifest_kind": row["manifest_kind"],
        "file_count": row["file_count"],
        "total_bytes": row["total_bytes"],
        "token": _token(current) if current else None,
        "replaced_tokens": [_token(token) for token in replaced],
        "last_verification": last,
        "tags": list(row["tags"]),
        "notes": notes,
    }


def seal_date(entry: Dict[str, Any]) -> Optional[str]:
    """The date a seal is ordered and chosen by: its current token's time, or its created claim without one."""
    token = entry["token"]
    return moment_key(token["time"]) if token else moment_key(entry["created"])


def build_register(
    library: Optional[lib.Library],
    tag: Optional[str] = None,
    folder: Optional[Path] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
) -> Register:
    """The chosen seals. ``since`` and ``until`` are days (YYYY-MM-DD), both included, matched against ``seal_date``."""
    chosen = {
        "tag": tag,
        "folder": str(folder) if folder is not None else None,
        "since": since,
        "until": until,
    }
    if library is None:
        return Register([], None, chosen)
    entries = [_entry(library, row) for row in lib.matching(library.seals(), folder, tag)]
    if since is not None or until is not None:
        entries = [
            entry
            for entry in entries
            if seal_date(entry) is not None
            and (since is None or seal_date(entry)[:10] >= since)
            and (until is None or seal_date(entry)[:10] <= until)
        ]
    entries.sort(key=lambda entry: (seal_date(entry) is None, seal_date(entry) or "", entry["manifest_sha256"]))
    for number, entry in enumerate(entries, 1):
        entry["number"] = number
    return Register(entries, library.last_change(), chosen)


# Wording every format shares ----------------------------------------------------------------------


def _same(text: str) -> str:
    return text


def _made_line(register: Register, quote: Callable[[str], str] = _same) -> str:
    """Who made the register and how current the library was. ``quote`` makes each value safe for a format."""
    when = f" The newest entry in the library is from {quote(register.as_of)}." if register.as_of else " The library was empty."
    return f"Made by evidence-seal {quote(register.tool_version)} from the seal library on this computer.{when}"


def _chosen_line(register: Register, quote: Callable[[str], str] = _same) -> str:
    parts = []
    chosen = register.chosen
    if chosen["tag"] is not None:
        parts.append(f"with the tag {quote(chosen['tag'])}")
    if chosen["folder"] is not None:
        parts.append(f"whose folder was last seen at {quote(chosen['folder'])}")
    if chosen["since"] is not None:
        parts.append(f"dated {quote(chosen['since'])} or later")
    if chosen["until"] is not None:
        parts.append(f"dated {quote(chosen['until'])} or earlier")
    which = "every seal in the library" if not parts else "the seals " + ", ".join(parts)
    return f"Chosen: {which}. {count_of(len(register.seals), 'seal')}."


def _token_text(token: Dict[str, Any]) -> str:
    who = token["authority"] or "an authority that is not named"
    return f"{token['time'] or 'no time'}, from {who}, serial {token['serial'] or 'not stated'}"


def _files_text(entry: Dict[str, Any]) -> str:
    size = f", {count_of(entry['total_bytes'], 'byte')}" if entry["total_bytes"] is not None else ""
    return f"{count_of(entry['file_count'], 'file')}{size}"


def _last_text(entry: Dict[str, Any]) -> str:
    last = entry["last_verification"]
    return f"{last['result']} on {last['at']}, by {last['command']}" if last else "never verified on this computer"


def fields(entry: Dict[str, Any]) -> List[Tuple[str, str]]:
    """The label and value of everything about one seal except its notes."""
    return [
        ("Full ID (the manifest's SHA-256)", entry["manifest_sha256"]),
        ("Purpose stated by the sealer", entry["purpose"] or "not stated"),
        ("Created (a claim, not proof)", entry["created"] or "not stated"),
        ("Folder name", entry["folder_name"] or "not stated"),
        ("Folder last seen at", entry["folder_path"] or "not known"),
        ("Manifest last seen at", entry["manifest_path"] or "not known"),
        ("Files", _files_text(entry)),
        ("Current token", _token_text(entry["token"]) if entry["token"] else "none"),
        ("Replaced tokens", "; ".join(_token_text(token) for token in entry["replaced_tokens"]) or "none"),
        ("Last verification", _last_text(entry)),
        ("Tags", ", ".join(entry["tags"]) or "none"),
    ]


def note_heading(note: Dict[str, Any]) -> str:
    """``Note 2, 2026-11-09T12:00:00Z, evidence-seal 0.3.0, WITHDRAWN by note 3``, for example."""
    heading = f"Note {note['number']}, {note['at']}, evidence-seal {note['tool_version']}"
    if note["withdraws"] is not None:
        return heading + f", withdrawing note {note['withdraws']}"
    if note["withdrawn_by"] is not None:
        return heading + f", WITHDRAWN by note {note['withdrawn_by']}"
    return heading


def note_lines(note: Dict[str, Any]) -> List[str]:
    return str(note["text"]).split("\n")


def _note_cell(note: Dict[str, Any]) -> str:
    return f"{note_heading(note)}: {printable(note['text'])}"


# Formats ------------------------------------------------------------------------------------------


def _text(register: Register) -> bytes:
    lines = ["EVIDENCE REGISTER", _made_line(register), _chosen_line(register), ORDER, "", "WHAT THIS REGISTER IS"]
    lines.extend(f"  {item}" for item in WHAT_IT_IS)
    for entry in register.seals:
        lines.extend(["", f"{entry['number']}. SEAL {entry['id']}"])
        lines.extend(f"  {label}: {value}" for label, value in fields(entry))
        lines.append(f"  Notes: {count_of(len(entry['notes']), 'note') if entry['notes'] else 'none'}")
        for note in entry["notes"]:
            lines.append(f"    {note_heading(note)}")
            lines.extend(f"      {line}".rstrip() for line in note_lines(note))
    if not register.seals:
        lines.extend(["", "No seal in the library matches."])
    lines.extend(["", "CHECK EACH SEAL YOURSELF", f"  {PLACEHOLDERS}"])
    for number, (explanation, command) in enumerate(CHECKS, 1):
        lines.extend([f"  {number}. {explanation}", f"     {command}"])
    return printable_block(lines).encode("utf-8")


def _json(register: Register) -> bytes:
    document = {
        "register_schema": REGISTER_SCHEMA_VERSION,
        "tool_version": register.tool_version,
        "library_as_of": register.as_of,
        "chosen": register.chosen,
        "count": len(register.seals),
        "order": ORDER,
        "what_this_is": list(WHAT_IT_IS),
        "check_each_seal": {
            "placeholders": PLACEHOLDERS,
            "steps": [
                {"step": number, "explanation": explanation, "command": command}
                for number, (explanation, command) in enumerate(CHECKS, 1)
            ],
        },
        "seals": register.seals,
    }
    return (json.dumps(document, indent=2) + "\n").encode("ascii")


def _csv(register: Register) -> bytes:
    rows = []
    for entry in register.seals:
        token = entry["token"] or {}
        last = entry["last_verification"] or {}
        rows.append(
            [
                entry["number"],
                entry["id"],
                entry["manifest_sha256"],
                printable(entry["purpose"] or ""),
                printable(entry["created"] or ""),
                printable(entry["folder_name"] or ""),
                printable(entry["folder_path"] or ""),
                printable(entry["manifest_path"] or ""),
                entry["file_count"],
                "" if entry["total_bytes"] is None else entry["total_bytes"],
                printable(token.get("time") or ""),
                printable(token.get("authority") or ""),
                printable(token.get("serial") or ""),
                printable(JOIN.join(_token_text(item) for item in entry["replaced_tokens"])),
                printable(last.get("result") or ""),
                printable(last.get("at") or ""),
                printable(JOIN.join(entry["tags"])),
                printable(JOIN.join(_note_cell(note) for note in entry["notes"])),
            ]
        )
    return csv_table(CSV_COLUMNS, rows)


def _markdown(register: Register) -> bytes:
    m = markdown_text
    lines = ["# Evidence register", "", _made_line(register, m), "", _chosen_line(register, m), "", m(ORDER)]
    lines.extend(["", "## What this register is", ""])
    lines.extend(f"- {m(item)}" for item in WHAT_IT_IS)
    for entry in register.seals:
        lines.extend(["", f"## {entry['number']}. Seal {m(entry['id'])}", ""])
        lines.extend(f"- {m(label)}: {m(value)}" for label, value in fields(entry))
        if entry["notes"]:
            lines.extend(["", f"### Notes on seal {m(entry['id'])}", ""])
        for note in entry["notes"]:
            lines.append(f"- {m(note_heading(note))}")
            for line in note_lines(note):
                if line.strip():
                    lines.extend(["", "  " + m(line)])
            lines.append("")
    if not register.seals:
        lines.extend(["", "No seal in the library matches."])
    # This sentence is the tool's own, so only the option in it needs marking as code.
    lines.extend(["", "## Check each seal yourself", "", PLACEHOLDERS.replace("-token_in", "`-token_in`"), ""])
    for number, (explanation, command) in enumerate(CHECKS, 1):
        marker = f"{number}. "
        lines.extend([marker + m(explanation), ""])
        lines.extend(markdown_block(command, " " * len(marker)))
        lines.append("")
    return ("\n".join(lines).rstrip("\n") + "\n").encode("utf-8")


_REGISTER_STYLE = (
    HTML_STYLE
    + "h3 { font-size: 0.9rem; margin: 0.6rem 0 0.2rem; }\n"
    + ".note { margin: 0.3rem 0 0.5rem; } .note p { margin: 0.1rem 0 0 1rem; }\n"
    + ".withdrawn { color: #5a574f; }\n"
)


def _html(register: Register) -> bytes:
    e = xml_text
    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>Evidence Register</title>",
        f"<style>{_REGISTER_STYLE}</style></head><body>",
        "<h1>Evidence register</h1>",
        f"<p>{e(_made_line(register))}</p>",
        f"<p>{e(_chosen_line(register))}</p>",
        f"<p>{e(ORDER)}</p>",
        "<h2>What this register is</h2><ul>",
    ]
    parts.extend(f"<li>{e(item)}</li>" for item in WHAT_IT_IS)
    parts.append("</ul>")
    for entry in register.seals:
        parts.append(f"<h2>{entry['number']}. Seal {e(entry['id'])}</h2><table>")
        parts.extend(f"<tr><th>{e(label)}</th><td>{e(value)}</td></tr>" for label, value in fields(entry))
        parts.append("</table>")
        if entry["notes"]:
            parts.append("<h3>Notes</h3>")
        for note in entry["notes"]:
            css = "note withdrawn" if note["withdrawn_by"] is not None else "note"
            body = "<br>".join(e(line) for line in note_lines(note))
            parts.append(f'<div class="{css}"><strong>{e(note_heading(note))}</strong><p>{body}</p></div>')
    if not register.seals:
        parts.append("<p>No seal in the library matches.</p>")
    parts.append(f"<h2>Check each seal yourself</h2><p>{e(PLACEHOLDERS)}</p><ol>")
    parts.extend(f"<li>{e(explanation)}<code>{e(command)}</code></li>" for explanation, command in CHECKS)
    parts.append("</ol></body></html>")
    return ("\n".join(parts) + "\n").encode("utf-8")


def _moment(text: Optional[str]) -> Optional[datetime]:
    """The PDF's creation date, from the library's newest entry. None when that is not a real date."""
    key = moment_key(text)
    try:
        return datetime.strptime(key, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc) if key else None
    except ValueError:
        return None


def _pdf(register: Register) -> bytes:
    p = printable
    as_of = p(register.as_of) if register.as_of else "an empty library"
    doc = pdf.Document(
        title="Evidence register",
        subject=count_of(len(register.seals), "seal"),
        producer=f"evidence-seal {p(register.tool_version)}",
        created=_moment(register.as_of),
        footer=f"Evidence register, from {as_of}",
    )
    doc.paragraph("Evidence register", pdf.BOLD, 16, after=2)
    for line in (_made_line(register), _chosen_line(register), ORDER):
        doc.paragraph(p(line))
    doc.heading("What this register is")
    for item in WHAT_IT_IS:
        doc.bullet(item)
    for entry in register.seals:
        doc.heading(f"{entry['number']}. Seal {entry['id']}")
        doc.table([[(p(label), pdf.BOLD), (p(value), pdf.HELVETICA)] for label, value in fields(entry)], (34, 66))
        if entry["notes"]:
            doc.keep(40)
            doc.paragraph(f"Notes on seal {entry['id']}", pdf.BOLD, after=2)
        for note in entry["notes"]:
            doc.keep(30)
            doc.paragraph(p(note_heading(note)), pdf.BOLD, 9, after=1)
            for line in note_lines(note):
                doc.paragraph(p(line), indent=12, after=1)
            doc.space(3)
    if not register.seals:
        doc.paragraph("No seal in the library matches.")
    doc.heading("Check each seal yourself")
    doc.paragraph(PLACEHOLDERS)
    for number, (explanation, command) in enumerate(CHECKS, 1):
        doc.keep(40)
        doc.paragraph(explanation, indent=16, after=1.5, marker=f"{number}.")
        doc.paragraph(command, pdf.COURIER, 7.5, indent=16, after=4)
    if doc.substituted:
        doc.heading("About this file")
        doc.paragraph(SUBSTITUTED_NOTE)
    return doc.to_bytes()


_RENDERERS = {"text": _text, "csv": _csv, "json": _json, "markdown": _markdown, "html": _html, "pdf": _pdf}


BINARY_FORMATS = ("pdf",)


def render_register(register: Register, name: str) -> bytes:
    if name not in _RENDERERS:
        raise ValueError(f"unknown register format {name!r}; choose one of {', '.join(REGISTER_FORMATS)}")
    return _RENDERERS[name](register)
