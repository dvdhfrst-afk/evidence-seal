"""The report command: one page a lawyer or reviewer can read and check independently."""

from __future__ import annotations

import html
import os
import re
import shlex
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from . import der, render
from .results import Verification
from .sealing import REPORT_HTML_SUFFIX, REPORT_TEXT_SUFFIX
from .text import printable, printable_block
from .trust import authority_for_root
from .x509 import Certificate

SHOWS = (
    "The exact bytes of the manifest existed by the time in the token, according to the authority that signed it.",
    "Every file whose current hash matches the manifest therefore has the same content as a file that existed by then.",
)
DOES_NOT_SHOW = (
    "Who wrote the files, who owned them, or that they were created by the person presenting them.",
    "That the files did not exist earlier, or that the purpose statement and created field are true.",
    "Anything about files outside the manifest, or about excluded files.",
)
DEPENDS_ON = (
    "The authority's continued credibility: that its clock was right and its signing key was not misused.",
    "The continued strength of SHA-256 and of the signature algorithm.",
    "This is a technical summary and not legal advice. Whether it is admissible or persuasive is for a lawyer to judge.",
)
# Safe bare in sh, cmd.exe and PowerShell alike. A backslash only counts as plain where it separates folders.
_PLAIN_ARGUMENT = re.compile(r"^[A-Za-z0-9_./:=+\\-]+$" if os.name == "nt" else r"^[A-Za-z0-9_./:=+-]+$")
# Safe inside double quotes in all three. Letters and digits of any script, plus a few marks.
_QUOTABLE_ARGUMENT = re.compile(r"^(?:\w|[ ./:=+,@()\\-])+$" if os.name == "nt" else r"^(?:\w|[ ./:=+,@()-])+$")


@dataclass
class ReportContext:
    manifest_file: str
    token_file: Optional[str]
    root_file: Optional[str]
    untrusted_files: Tuple[str, ...] = ()


def quote_argument(argument: str) -> str:
    if _PLAIN_ARGUMENT.match(argument):
        return argument
    if _QUOTABLE_ARGUMENT.match(argument):
        return f'"{argument}"'
    return shlex.quote(argument)


def _is_safe_everywhere(name: str) -> bool:
    return bool(_PLAIN_ARGUMENT.match(name) or _QUOTABLE_ARGUMENT.match(name))


def _root_certificate(verification: Verification) -> Optional[Certificate]:
    for cert in verification.anchor_certificates:
        if cert.self_issued:
            return cert
    return None


def openssl_commands(verification: Verification, context: ReportContext) -> List[Tuple[str, str]]:
    """Each step as (explanation, command). One command per step, with nothing chained."""
    steps: List[Tuple[str, str]] = []
    if context.token_file is None:
        return steps
    # A name came from whoever sent these files, and a reader may paste these commands into any shell.
    copies: List[str] = []

    def safe(name: str, plain: str) -> str:
        if _is_safe_everywhere(name):
            return name
        copies.append(f"{name} to {plain}")
        return plain

    manifest_file = safe(context.manifest_file, "manifest.txt")
    token = safe(context.token_file, "token.tsr")
    root_name = safe(context.root_file or "authority-root.crt", "authority-root.crt")
    if copies:
        steps.append(
            (
                "These names hold characters a command prompt could act on, so copy each one to a plain name first: "
                + "; ".join(copies)
                + ".",
                "",
            )
        )
    root = _root_certificate(verification)
    if root is not None:
        known = authority_for_root(root.sha256)
        source = "Get the authority's root certificate yourself" + (f" from {known.root_url}" if known else "")
        steps.append(
            (
                f"{source} and save it as {root_name}. Its SHA-256 fingerprint should be {root.sha256}."
                " Compare with this command:",
                f"openssl x509 -in {quote_argument(root_name)} -noout -fingerprint -sha256",
            )
        )
    else:
        steps.append(
            (
                f"Get the root certificate of the authority named above from that authority, and save it as {root_name}."
                " This run did not establish which root is the right one. Compare its fingerprint with what the"
                " authority publishes:",
                f"openssl x509 -in {quote_argument(root_name)} -noout -fingerprint -sha256",
            )
        )
    command = f"openssl ts -verify -data {quote_argument(manifest_file)} -in {quote_argument(token)}"
    if verification.facts is not None and verification.facts.is_bare_token:
        command += " -token_in"
    command += f" -CAfile {quote_argument(root_name)}"
    explanation = "Check the token against the manifest and that root. A good token prints Verification: OK."
    for number, extra in enumerate(context.untrusted_files, 1):
        usable = extra
        if not _PLAIN_ARGUMENT.match(extra):
            # Openssl reads -untrusted as a list split on spaces and commas, and no quoting gets past that.
            usable = f"extra-{number}.crt"
            explanation += f" First copy {extra} to {usable}, because openssl cannot read that name here."
        command += f" -untrusted {usable}"
    steps.append((explanation, command))
    epoch = _token_epoch(verification)
    if epoch is not None:
        steps.append(
            (
                "If a certificate has expired since the token was issued, openssl needs to be told to check at the"
                " token's time:",
                command + f" -attime {epoch}",
            )
        )
    steps.append(
        (
            "Read what the token says, with no help from this tool:",
            f"openssl ts -reply -in {quote_argument(token)}" + (" -token_in" if _bare(verification) else "") + " -text",
        )
    )
    steps.append(
        (
            "Check any file against its line in the manifest. Run it inside the sealed folder, with the file's own name:",
            "openssl dgst -sha256 FILE",
        )
    )
    return steps


def _bare(verification: Verification) -> bool:
    return verification.facts is not None and verification.facts.is_bare_token


def _token_epoch(verification: Verification) -> Optional[int]:
    time_text = verification.facts.time if verification.facts else None
    if not time_text:
        return None
    moment = datetime.strptime(time_text[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    return der.epoch_seconds(moment)


def _result_rows(verification: Verification) -> List[Tuple[str, str, str]]:
    rows = []
    for check in verification.checks:
        detail = check.detail
        if check.method:
            detail += f" (checked with: {check.method})"
        rows.append((check.title, render.status_word(check.status), detail))
    return rows


def _claim_rows(verification: Verification, context: ReportContext) -> List[Tuple[str, str]]:
    rows: List[Tuple[str, str]] = [("Manifest", f"{context.manifest_file}, {verification.manifest_kind} format")]
    rows.append(("Manifest SHA-256", verification.manifest_sha256))
    if verification.purpose:
        rows.append(("Purpose stated by the sealer", verification.purpose))
    if verification.created:
        rows.append(("Created field (a claim, not proof)", verification.created))
    size = "" if verification.total_bytes is None else f", {verification.total_bytes} bytes"
    rows.append(("Files listed", f"{verification.file_count}{size}"))
    rows.append(("Token", context.token_file or "none found"))
    facts = verification.facts
    if facts is not None and facts.time:
        rows.append(("Time in token", f"{facts.time} ({facts.accuracy})"))
        rows.append(("Authority", facts.authority or facts.signer or "not stated"))
        rows.append(("Authority's answer", facts.status))
        rows.append(("Policy", facts.policy or "not stated"))
        rows.append(("Hash algorithm", facts.hash_algorithm or "not stated"))
        rows.append(("Serial number", facts.serial or "not stated"))
    return rows


def render_report_text(verification: Verification, context: ReportContext) -> str:
    lines: List[str] = ["EVIDENCE SEAL REPORT", f"Checked {verification.checked_at} by evidence-seal {verification.tool_version}"]
    lines.extend(["", f"RESULT: {verification.overall}", render.summary_sentence(verification)])
    if verification.test_authority_warning():
        lines.append(verification.test_authority_warning())
    lines.extend(["", "WHAT IS CLAIMED"])
    lines.extend(f"  {label}: {value}" for label, value in _claim_rows(verification, context))
    lines.extend(["", "RESULTS OF THIS CHECK (each one separate)"])
    for title, word, detail in _result_rows(verification):
        lines.append(f"  [{word}] {title}: {detail}")
    if verification.notes:
        lines.extend(["", "NOTES"])
        lines.extend(f"  {note}" for note in verification.notes)
    steps = openssl_commands(verification, context)
    if steps:
        lines.extend(["", "CHECK IT YOURSELF, WITHOUT TRUSTING THIS TOOL", "Run these in the folder holding the manifest and token:"])
        for number, (explanation, command) in enumerate(steps, 1):
            lines.append(f"  {number}. {explanation}")
            if command:
                lines.append(f"     {command}")
    lines.extend(["", "WHAT THIS SHOWS"])
    lines.extend(f"  {item}" for item in SHOWS)
    lines.extend(["WHAT THIS DOES NOT SHOW"])
    lines.extend(f"  {item}" for item in DOES_NOT_SHOW)
    lines.extend(f"  {limit}" for limit in verification.limits[:1])
    lines.extend(["WHAT IT DEPENDS ON"])
    lines.extend(f"  {item}" for item in DEPENDS_ON)
    return printable_block(lines)


_HTML_STYLE = """
:root { color-scheme: light; }
body { font: 14px/1.4 Georgia, "Times New Roman", serif; color: #1c1b19; background: #fbfaf7;
       max-width: 46rem; margin: 1.5rem auto; padding: 0 1rem; }
h1 { font-size: 1.3rem; margin: 0; }
h2 { font-size: 0.95rem; margin: 1.1rem 0 0.3rem; border-bottom: 1px solid #c9c5bb; }
table { border-collapse: collapse; width: 100%; }
td, th { text-align: left; vertical-align: top; padding: 0.15rem 0.5rem 0.15rem 0; overflow-wrap: anywhere; }
th { font-weight: normal; color: #5a574f; width: 34%; }
code { font: 12px/1.35 Consolas, Menlo, monospace; display: block; background: #f0eee8; padding: 0.3rem 0.4rem;
       overflow-wrap: anywhere; }
ol, ul { margin: 0.2rem 0; padding-left: 1.2rem; }
.result { font-weight: bold; }
.PASS { color: #1d6b3a; } .FAIL { color: #a3201d; } .NOT-CHECKED { color: #8a5a00; }
@media print { body { margin: 0; background: none; font-size: 11.5px; } code { background: none; padding: 0; } }
"""


def _safe_html(text: object) -> str:
    return html.escape(printable(text))


def _html_list(items) -> str:
    return "<ul>" + "".join(f"<li>{_safe_html(item)}</li>" for item in items) + "</ul>"


def render_report_html(verification: Verification, context: ReportContext) -> str:
    e = _safe_html
    overall = verification.overall
    parts: List[str] = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>Evidence Seal Report</title>",
        f"<style>{_HTML_STYLE}</style></head><body>",
        "<h1>Evidence seal report</h1>",
        f"<p>Checked {e(verification.checked_at)} by evidence-seal {e(verification.tool_version)}</p>",
        f'<p class="result">Result: {e(overall)}</p>',
        f"<p>{e(render.summary_sentence(verification))}</p>",
    ]
    if verification.test_authority_warning():
        parts.append(f'<p class="result">{e(verification.test_authority_warning())}</p>')
    parts += [
        "<h2>What is claimed</h2><table>",
    ]
    for label, value in _claim_rows(verification, context):
        parts.append(f"<tr><th>{e(label)}</th><td>{e(value)}</td></tr>")
    parts.append("</table><h2>Results of this check (each one separate)</h2><table>")
    for title, word, detail in _result_rows(verification):
        css = word.replace(" ", "-")
        parts.append(f'<tr><th>{e(title)}</th><td><span class="{css}">{e(word)}</span>: {e(detail)}</td></tr>')
    parts.append("</table>")
    if verification.notes:
        parts.append("<h2>Notes</h2>" + _html_list(verification.notes))
    steps = openssl_commands(verification, context)
    if steps:
        parts.append("<h2>Check it yourself, without trusting this tool</h2>")
        parts.append("<p>Run these in the folder holding the manifest and token:</p><ol>")
        for explanation, command in steps:
            shown = f"<code>{e(command)}</code>" if command else ""
            parts.append(f"<li>{e(explanation)}{shown}</li>")
        parts.append("</ol>")
    parts.append("<h2>What this shows</h2>" + _html_list(SHOWS))
    parts.append("<h2>What this does not show</h2>" + _html_list(tuple(DOES_NOT_SHOW) + tuple(verification.limits[:1])))
    parts.append("<h2>What it depends on</h2>" + _html_list(DEPENDS_ON))
    parts.append("</body></html>")
    return "\n".join(parts) + "\n"


def default_report_path(manifest_path: Path, fmt: str) -> Path:
    suffix = REPORT_HTML_SUFFIX if fmt == "html" else REPORT_TEXT_SUFFIX
    return Path(manifest_path).with_suffix(suffix)
