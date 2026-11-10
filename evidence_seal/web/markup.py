"""Building HTML. Every value from outside goes through ``e``, which makes control characters visible
as escapes and then escapes HTML, so a file name or purpose can never become markup.

Helpers take escaped HTML (strings that ``e`` or another helper made) for their ``body`` arguments
and raw text for everything else.
"""

from __future__ import annotations

import html
import urllib.parse
from typing import Iterable, List, Optional, Sequence, Tuple

from .. import __version__, render
from ..reporting import DEPENDS_ON, DOES_NOT_SHOW, SHOWS
from ..results import Status, Verification
from ..text import printable
from .security import FORM_TOKEN_FIELD

NAV: Tuple[Tuple[str, str], ...] = (
    ("/", "Seals"),
    ("/new", "New seal"),
    ("/check", "Check files I was given"),
    ("/compare", "Compare"),
    ("/jobs", "Jobs"),
    ("/authorities", "Authorities"),
    ("/settings", "Settings"),
)


def e(value: object) -> str:
    return html.escape(printable("" if value is None else value), quote=True)


def url(path: str, **query: object) -> str:
    """A link within this site. Query values are percent-encoded; leave a value None to drop it."""
    pairs = [(name, str(value)) for name, value in query.items() if value not in (None, "")]
    return path + ("?" + urllib.parse.urlencode(pairs) if pairs else "")


def link(href: str, text: object) -> str:
    return f'<a href="{e(href)}">{e(text)}</a>'


def layout(title: str, body: str, current: str = "", refresh: bool = False) -> str:
    nav = []
    for path, label in NAV:
        here = ' aria-current="page"' if path == current else ""
        nav.append(f'<a href="{path}"{here}>{e(label)}</a>')
    head_extra = "<noscript><meta http-equiv=\"refresh\" content=\"3\"></noscript>" if refresh else ""
    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="en"><head><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            f"<title>{e(title)} - evidence-seal</title>",
            '<link rel="stylesheet" href="/assets/style.css">',
            head_extra,
            "</head><body>",
            '<a class="skip" href="#main">Skip to the page</a>',
            f'<header><nav aria-label="Main">{"".join(nav)}</nav></header>',
            f'<main id="main"><h1>{e(title)}</h1>',
            body,
            f'<p class="muted">evidence-seal {e(__version__)}, on this computer only.</p>',
            '</main><script src="/assets/app.js"></script>',
            "</body></html>",
            "",
        ]
    )


def paragraph(text: object, css: str = "") -> str:
    attribute = f' class="{css}"' if css else ""
    return f"<p{attribute}>{e(text)}</p>"


def items(values: Iterable[object]) -> str:
    return "<ul>" + "".join(f"<li>{e(value)}</li>" for value in values) + "</ul>"


def table(headers: Sequence[str], rows: Iterable[Sequence[str]], caption: str = "") -> str:
    """Cells must already be escaped HTML."""
    head = "".join(f'<th scope="col">{e(header)}</th>' for header in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    shown = f"<caption class=\"muted\">{e(caption)}</caption>" if caption else ""
    return f'<div class="table-wrap"><table>{shown}<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def facts(rows: Iterable[Tuple[str, str]]) -> str:
    """Label and value pairs. Values must already be escaped HTML."""
    return '<dl class="facts">' + "".join(f"<dt>{e(label)}</dt><dd>{value}</dd>" for label, value in rows) + "</dl>"


def hidden(name: str, value: object) -> str:
    return f'<input type="hidden" name="{e(name)}" value="{e(value)}">'


def form(action: str, token: str, inner: str, button: str, css: str = "", button_css: str = "", enctype: str = "") -> str:
    """A POST form carrying the session's form token."""
    attributes = f' class="{css}"' if css else ""
    if enctype:
        attributes += f' enctype="{enctype}"'
    button_class = f' class="{button_css}"' if button_css else ""
    return (
        f'<form method="post" action="{e(action)}"{attributes}>{hidden(FORM_TOKEN_FIELD, token)}{inner}'
        f'<button type="submit"{button_class}>{e(button)}</button></form>'
    )


def _field_id(name: str) -> str:
    return "field-" + name.replace("_", "-")


def _help(name: str, text: str) -> Tuple[str, str]:
    if not text:
        return "", ""
    return f' aria-describedby="{_field_id(name)}-help"', f'<span class="help" id="{_field_id(name)}-help">{e(text)}</span>'


def text_field(name: str, label: str, value: object = "", help_text: str = "", required: bool = False, kind: str = "text") -> str:
    described, shown = _help(name, help_text)
    need = " required" if required else ""
    return (
        f'<label for="{_field_id(name)}">{e(label)}</label>{shown}'
        f'<input type="{kind}" id="{_field_id(name)}" name="{e(name)}" value="{e(value)}"{described}{need}>'
    )


def text_box(name: str, label: str, value: object = "", help_text: str = "") -> str:
    described, shown = _help(name, help_text)
    return f'<label for="{_field_id(name)}">{e(label)}</label>{shown}<textarea id="{_field_id(name)}" name="{e(name)}"{described}>{e(value)}</textarea>'


def file_field(name: str, label: str, help_text: str = "", required: bool = False) -> str:
    described, shown = _help(name, help_text)
    need = " required" if required else ""
    return f'<label for="{_field_id(name)}">{e(label)}</label>{shown}<input type="file" id="{_field_id(name)}" name="{e(name)}"{described}{need}>'


def choice(name: str, label: str, options: Sequence[Tuple[str, str]], selected: Optional[str] = None, help_text: str = "") -> str:
    described, shown = _help(name, help_text)
    rendered = []
    for value, text in options:
        mark = " selected" if value == selected else ""
        rendered.append(f'<option value="{e(value)}"{mark}>{e(text)}</option>')
    return f'<label for="{_field_id(name)}">{e(label)}</label>{shown}<select id="{_field_id(name)}" name="{e(name)}"{described}>{"".join(rendered)}</select>'


def pager(path: str, query: dict, page: int, pages: int) -> str:
    if pages <= 1:
        return ""
    parts = [f"<span>Page {page} of {pages}</span>"]
    if page > 1:
        parts.insert(0, link(url(path, **dict(query, page=page - 1)), "Previous page"))
    if page < pages:
        parts.append(link(url(path, **dict(query, page=page + 1)), "Next page"))
    return '<nav class="pager" aria-label="Pages">' + "".join(parts) + "</nav>"


def status(check_status: Status) -> str:
    word = render.status_word(check_status)
    return f'<span class="status status-{word.lower().replace(" ", "-")}">{e(word)}</span>'


def result_word(overall: Optional[str]) -> str:
    """VERIFIED, FAILED or INCOMPLETE as the command line prints it, in words, never by color alone."""
    if not overall:
        return '<span class="muted">never checked</span>'
    return f'<span class="status result-{e(overall.lower())}">{e(overall)}</span>'


def proof_limits() -> str:
    """What a timestamp shows and does not show: the same words as every report."""
    return (
        "<h2>What this shows</h2>"
        + items(SHOWS)
        + "<h2>What this does not show</h2>"
        + items(DOES_NOT_SHOW)
        + "<h2>What it depends on</h2>"
        + items(DEPENDS_ON)
    )


def verdict(verification: Verification) -> str:
    """A verification as the command line shows it: the result, each check, the notes and the limits."""
    overall = verification.overall
    parts: List[str] = [
        f'<section class="verdict verdict-{e(overall.lower())}" aria-labelledby="verdict-heading">',
        f'<h2 id="verdict-heading">RESULT: {e(overall)}</h2>',
        paragraph(render.summary_sentence(verification)),
    ]
    warning = verification.test_authority_warning()
    if warning:
        parts.append(paragraph(warning, "notice"))
    rows = []
    for check in verification.checks:
        detail = e(check.detail) + (f'<br><span class="muted">checked with: {e(check.method)}</span>' if check.method else "")
        rows.append((e(check.title), status(check.status), detail))
    parts.append(table(("Check", "Result", "Detail"), rows))
    differences = verification.differences
    if differences is not None:
        for title, paths in (
            ("Changed", differences.changed),
            ("Missing", differences.missing),
            ("Added", differences.added),
            ("Could not be read", differences.unreadable),
        ):
            if paths:
                shown = [
                    f"{path} (the same bytes are now at {differences.moved_hints[path]})" if path in differences.moved_hints else path
                    for path in paths[: render.MAX_LISTED]
                ]
                more = [f"and {len(paths) - render.MAX_LISTED} more"] if len(paths) > render.MAX_LISTED else []
                parts.append(f"<h3>{e(title)} ({len(paths)})</h3>" + items(shown + more))
    token = verification.facts
    if token is not None and token.time:
        parts.append("<h3>What the token says</h3>")
        parts.append(
            facts(
                [
                    ("Status", e(token.status)),
                    ("Time", e(f"{token.time} ({token.accuracy})")),
                    ("Policy", e(token.policy)),
                    ("Hash algorithm", e(token.hash_algorithm)),
                    ("Authority", e(token.authority or token.signer or "not stated")),
                    ("Serial number", e(token.serial)),
                ]
            )
        )
    if verification.notes:
        parts.append("<h3>Notes</h3>" + items(verification.notes))
    parts.append("<h3>Not checked by this tool in any run</h3>" + items(verification.limits))
    parts.append(f'<p class="muted">Checked {e(verification.checked_at)} by evidence-seal {e(verification.tool_version)}.</p>')
    parts.append("</section>")
    return "".join(parts) + proof_limits()
