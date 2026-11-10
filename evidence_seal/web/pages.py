"""The HTML pages. Each is plain HTML that works without JavaScript. Only a running job's progress
updates by itself, and without JavaScript that page reloads itself every few seconds instead.

Every change is a POST form carrying the session's form token, answered with a redirect, so reloading
a page never repeats it. Forgetting a seal asks first, on a page of its own.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from .. import comparing, exporting, report_formats
from .. import library as lib
from ..authority_commands import TEST_ONLY
from ..console import size_text
from ..errors import EvidenceSealError, UsageError
from ..results import Verification
from ..text import count_of
from . import actions, inputs
from . import markup as m
from .jobs import DONE, FINISHED, Job
from .markup import e
from .routing import UPLOAD_LIMIT, HttpError, Request, Response, Router, bad_request, html_response, not_found, redirect

NETWORK_NOTICE = (
    "Stamping is the only step on these pages that uses the network. It sends the hash of the manifest, a random"
    " number and a request for the authority's certificates to the authority's address, and nothing else: no file"
    " names, no file contents and no text from the manifest."
)
CHECK_NOTICES = (
    "Without a folder, only the token is checked against the manifest. The file check is not run, so the result"
    " cannot be VERIFIED.",
    "A root certificate you upload is trusted for this one check only, in place of the built-in fingerprints and"
    " your authority list. It is not kept.",
    "Uploaded files are held in a private temporary folder inside evidence-seal's own folder while they are checked,"
    " then removed. Nothing is written into your folders, and the check is not recorded in the library.",
)
STATE_WORDS = {"waiting": "Waiting", "running": "Running", "done": "Finished", "failed": "Failed", "cancelled": "Cancelled"}


def _page(title: str, body: str, current: str = "", refresh: bool = False, status: int = 200) -> Response:
    return html_response(m.layout(title, body, current, refresh), status)


def _error_box(message: str) -> str:
    return f'<div class="error" role="alert"><p>{e(message)}</p></div>'


def error_page(error: HttpError) -> Response:
    titles = {401: "This page needs its access key", 403: "This request was refused", 404: "Not found"}
    title = titles.get(error.status, "That did not work")
    hint = ""
    if error.status == 401:
        hint = m.paragraph(
            "Open the address that evidence-seal serve printed when it started. It carries a key that is new for each run."
        )
    body = _error_box(error.message) + hint + '<p><a href="/">Back to the seals</a></p>'
    return _page(title, body, status=error.status)


def _profile_field(request: Request, selected: Optional[str] = None) -> str:
    names = actions.profile_names()
    options = [("", "none: [defaults], then built-in values")] + [(name, name) for name in names]
    chosen = request.app.profile if selected is None else selected
    return m.choice(
        "profile", "Settings profile", options, chosen or "", "values not given on this form come from this profile, then [defaults]"
    )


def _short(sha: str) -> str:
    return f'<a class="mono" href="/seals/{e(sha)}">{e(lib.short_id(sha))}</a>'


def _when(text: Optional[str]) -> str:
    return e(text) if text else '<span class="muted">not stated</span>'


# Overview ------------------------------------------------------------------------------------------


def overview(request: Request) -> Response:
    query = (request.arg("q") or "").strip()
    tag = (request.arg("tag") or "").strip()
    folder = (request.arg("folder") or "").strip()
    page = inputs.page_number(request.arg("page"))
    rows, tags = actions.list_seals(query, tag, folder)
    shown, pages = actions.page_of(rows, page, actions.SEALS_PER_PAGE)
    search = (
        '<form method="get" action="/" role="search">'
        + m.text_field("q", "Search", query, "words from the purpose, the folder, the manifest's path or the ID", kind="search")
        + m.choice("tag", "Tag", [("", "any tag")] + [(item, item) for item in tags], tag)
        + m.text_field("folder", "Folder", folder, "part of the path where the folder was last seen")
        + '<button type="submit">Show matching seals</button></form>'
    )
    if not rows:
        message = "No seal in the library matches." if (query or tag or folder) else (
            "The library has no seals yet. Make one with New seal; seal, stamp and verify on the command line record here too."
        )
        return _page("Seals", search + m.paragraph(message), "/")
    table_rows = []
    for row in shown:
        size = "" if row["total_bytes"] is None else f", {size_text(row['total_bytes'])}"
        last = m.result_word(row["last_result"]) + (f" {e(row['last_checked'])}" if row["last_checked"] else "")
        table_rows.append(
            (
                _short(row["manifest_sha256"]),
                e(row["purpose"] or "not stated"),
                _when(row["created"]),
                e(f"{row['file_count']}{size}"),
                e(row["token_time"]) if row["token_time"] else '<span class="muted">no token</span>',
                last,
                e(", ".join(row["tags"])),
            )
        )
    body = (
        search
        + m.paragraph(f"{count_of(len(rows), 'seal')}, oldest first.")
        + m.table(("ID", "Purpose", "Created (a claim)", "Files", "Token time", "Last check", "Tags"), table_rows)
        + m.pager("/", {"q": query, "tag": tag, "folder": folder}, page, pages)
    )
    return _page("Seals", body, "/")


# One seal ------------------------------------------------------------------------------------------


def _report_links(prefix: str) -> str:
    return "<ul>" + "".join(
        f"<li>{m.link(f'{prefix}/report/{item.name}', item.name)}: {e(item.description)}</li>" for item in report_formats.REPORT_FORMATS
    ) + "</ul>"


def _seal_facts(row: Dict[str, Any]) -> str:
    size = f", {count_of(row['total_bytes'], 'byte')}" if row["total_bytes"] is not None else ""
    return m.facts(
        [
            ("ID (the manifest's SHA-256)", f'<span class="mono">{e(row["manifest_sha256"])}</span>'),
            ("Purpose", e(row["purpose"] or "not stated")),
            ("Created (a claim by whoever sealed it)", _when(row["created"])),
            ("Folder name", e(row["folder_name"] or "not stated")),
            ("Files", e(f"{row['file_count']}{size}")),
            ("Manifest kind", e(row["manifest_kind"])),
            ("Manifest last seen at", e(row["manifest_path"] or "not known")),
            ("Folder last seen at", e(row["folder_path"] or "not known")),
            ("Added to the library", e(row["added_at"])),
            ("Last check", m.result_word(row["last_result"]) + (f" {e(row['last_checked'])}" if row["last_checked"] else "")),
        ]
    )


def _verify_section(request: Request, sha: str, row: Dict[str, Any]) -> str:
    parts = ["<h2>Verify</h2>"]
    parts.append(
        m.paragraph(
            "Checks the folder against the library's copy of the manifest, and the token against the manifest, as library"
            " verify does. It stays offline, and the result is recorded in the library."
        )
    )
    parts.append(
        m.form(
            f"/seals/{sha}/verify",
            request.form_token,
            m.text_field("folder", "Folder (optional)", "", f"leave empty to use where it was last seen: {row['folder_path'] or 'not known'}"),
            "Verify now",
        )
    )
    job = request.app.runner.latest(actions.VERIFY, sha)
    if actions.has_report(job):
        assert job is not None
        outcome: Verification = job.payload[0]
        parts.append(f"<h3>Newest check on these pages: {m.result_word(outcome.overall)}</h3>")
        parts.append(m.paragraph(f"Checked {outcome.checked_at}."))
        parts.append(f'<p>{m.link(f"/jobs/{job.id}", "Every check of that run")}. Download its report:</p>')
        parts.append(_report_links(f"/seals/{sha}"))
    else:
        parts.append(m.paragraph("A report comes from a check. Verify now, and the report of that check can be downloaded in every format."))
    return "".join(parts)


def _stamp_section(request: Request, sha: str, row: Dict[str, Any], tokens: List[Dict[str, Any]]) -> str:
    parts = ["<h2>Stamp</h2>"]
    current = [token for token in tokens if token["is_current"]]
    if current:
        token = current[-1]
        parts.append(m.paragraph(f"This seal has a token from {token['authority'] or 'an authority not named'}, time {token['token_time']}."))
    if not row["manifest_path"] or not Path(row["manifest_path"]).is_file():
        parts.append(m.paragraph("The library does not know where this seal's manifest file is now, so it cannot be stamped from here."))
        return "".join(parts)
    try:
        choices = actions.stamp_choices()
    except UsageError as exc:
        return "".join(parts) + _error_box(str(exc))
    if not choices:
        parts.append(m.paragraph("No authority in the authority list has a root to check its answer against yet."))
        return "".join(parts)
    options = [
        (entry.name, f"{entry.name}: {entry.url}" + (" (TEST ONLY: proves nothing to anyone else)" if entry.test else ""))
        for entry in choices
    ]
    inner = m.choice("authority", "Authority", options, options[0][0], "from your authority list") + _profile_field(request)
    parts.append(f'<p class="notice">{e(NETWORK_NOTICE)}</p>')
    parts.append(m.form(f"/seals/{sha}/stamp", request.form_token, inner, "Stamp, sending the hash to the authority"))
    return "".join(parts)


def _tag_section(request: Request, sha: str, tags: List[str]) -> str:
    parts = ["<h2>Tags</h2>"]
    if tags:
        rows = []
        for tag in tags:
            remove = m.form(f"/seals/{sha}/untag", request.form_token, m.hidden("tag", tag), f"Remove the tag {tag}", "inline", "small")
            rows.append((e(tag), remove))
        parts.append(m.table(("Tag", "Remove"), rows))
    else:
        parts.append(m.paragraph("No tags yet."))
    field = m.text_field("tag", "New tag", "", f"1 to {lib.MAX_TAG_LENGTH} printable characters", required=True)
    parts.append(m.form(f"/seals/{sha}/tags", request.form_token, field, "Add the tag"))
    return "".join(parts)


def _files_section(sha: str, data: Any, page: int) -> str:
    rows, pages = actions.page_of(actions.file_rows(data), page, actions.FILES_PER_PAGE)
    exports = " ".join(m.link(f"/seals/{sha}/export/{name}", name) for name in exporting.EXPORT_FORMATS)
    parts = [
        f"<h2 id=\"files\">Files ({len(data.entries)})</h2>",
        f"<p>Download the list for other tools: {exports}. These come from the manifest alone and prove no date.</p>",
    ]
    table_rows = [
        (f'<span class="mono">{e(item["path"])}</span>', e("" if item["size"] is None else item["size"]), f'<span class="mono">{e(item["algorithm"])} {e(item["hash"])}</span>')
        for item in rows
    ]
    parts.append(m.table(("Path", "Size in bytes", "Hash"), table_rows))
    parts.append(m.pager(f"/seals/{sha}", {}, page, pages))
    if data.links or data.special:
        parts.append(m.paragraph(f"Also listed by name only, not hashed: {count_of(len(data.links) + len(data.special), 'link or special file')}."))
    return "".join(parts)


def _history_sections(tokens: List[Dict[str, Any]], runs: List[Dict[str, Any]], events: List[Dict[str, Any]]) -> str:
    token_rows = [
        (
            e(token["token_time"] or "no time"),
            e(token["authority"] or "not named"),
            e(token["serial"]),
            e("current" if token["is_current"] else "replaced by stamp --force"),
            f'<span class="mono">{e(token["token_sha256"])}</span>',
            e(token["token_path"] or "not known"),
        )
        for token in tokens
    ]
    run_rows = []
    for run in runs:
        checks = "<br>".join(f"[{e(check['status'].upper())}] {e(check['title'])}" for check in run["checks"])
        run_rows.append((e(run["run_at"]), m.result_word(run["overall"]), e(run["exit_code"]), e(run["command"]), e(run["folder_path"] or "not checked"), checks))
    event_rows = [(e(event["at"]), e(event["kind"]), e(event["detail"]), e(event["tool_version"])) for event in events]
    return (
        f"<h2>Tokens ({len(tokens)})</h2>"
        + (m.table(("Time", "Authority", "Serial", "State", "SHA-256", "Last seen at"), token_rows) if tokens else m.paragraph("No token yet."))
        + f"<h2>Verification history ({len(runs)}, newest first)</h2>"
        + (m.table(("When", "Result", "Exit code", "By", "Folder", "Checks"), run_rows) if runs else m.paragraph("Never verified."))
        + f"<h2>Events ({len(events)}, newest first)</h2>"
        + m.table(("When", "Event", "Detail", "evidence-seal"), event_rows)
    )


def seal_page(request: Request) -> Response:
    sha = request.params["sha"]
    page = inputs.page_number(request.arg("page"))
    detail = actions.seal_detail(sha)
    row = detail["seal"]
    body = (
        _seal_facts(row)
        + f'<p>{m.link(m.url("/compare", old=sha), "Compare this seal")} or '
        + f'{m.link(f"/seals/{sha}/forget", "forget it")}.</p>'
        + _verify_section(request, sha, row)
        + _stamp_section(request, sha, row, detail["tokens"])
        + _tag_section(request, sha, row["tags"])
        + _files_section(sha, detail["manifest"], page)
        + _history_sections(detail["tokens"], detail["runs"], detail["events"])
    )
    return _page(f"Seal {lib.short_id(sha)}", body)


def seal_verify(request: Request) -> Response:
    job = actions.start_verify(request.app, request.params["sha"], request.fields.text("folder"))
    return redirect(f"/jobs/{job.id}")


def seal_stamp(request: Request) -> Response:
    job = actions.start_stamp(request.app, request.params["sha"], request.fields)
    return redirect(f"/jobs/{job.id}")


def seal_tag(request: Request) -> Response:
    sha = request.params["sha"]
    tag = request.fields.text("tag", required=True, label="tag") or ""
    actions.change_tag(sha, tag, request.path.endswith("/tags"))
    return redirect(f"/seals/{sha}")


def seal_forget_page(request: Request) -> Response:
    sha = request.params["sha"]
    row = actions.seal_detail(sha)["seal"]
    body = (
        m.paragraph(f"Forget seal {lib.short_id(sha)} ({row['purpose'] or 'no purpose stated'})?")
        + m.paragraph(
            "It is removed from the library, with the copies nothing else in the library uses. Your manifest, tokens and"
            " folder are not touched, and the seal can be imported again later."
        )
        + m.form(f"/seals/{sha}/forget", request.form_token, m.hidden("confirm", "yes"), "Forget this seal", button_css="danger")
        + f'<p>{m.link(f"/seals/{sha}", "Keep it and go back")}</p>'
    )
    return _page("Forget a seal?", body)


def seal_forget(request: Request) -> Response:
    sha = request.params["sha"]
    if not request.fields.flag("confirm"):
        raise bad_request("forgetting a seal needs confirm=yes, which the confirmation page sends")
    dropped = actions.forget(sha)
    copies = "1 copy" if dropped == 1 else f"{dropped} copies"
    body = m.paragraph(
        f"Forgot seal {lib.short_id(sha)}, and removed {copies} that nothing else in the library uses."
        " Your manifest, tokens and folder were not touched."
    ) + '<p><a href="/">Back to the seals</a></p>'
    return _page("Seal forgotten", body)


def seal_report(request: Request) -> Response:
    return actions.seal_report(request.app, request.params["sha"], request.params["format"])


def seal_export(request: Request) -> Response:
    return actions.export(request.params["sha"], request.params["format"])


# New seal ------------------------------------------------------------------------------------------


def _seal_form(request: Request, values: Dict[str, str], error: str = "") -> str:
    inner = (
        m.text_field("folder", "Folder to seal", values.get("folder", ""), "the full path of a folder on this computer", required=True)
        + m.text_field("purpose", "Purpose", values.get("purpose", ""), "why this seal is being made, in your words; a profile may give it")
        + _profile_field(request, values.get("profile"))
        + m.text_box("exclude", "Exclude patterns (optional)", values.get("exclude", ""), "one per line, such as *.tmp or build/; a leading ! puts a file back")
        + m.text_field("out", "Manifest file (optional)", values.get("out", ""), "a full path; leave empty to write it beside the folder")
    )
    note = m.paragraph(
        "The preview opens no file and writes nothing. Sealing then hashes every file and writes the manifest."
        " Both stay offline. Once sealed, the seal's page offers stamping, to get a timestamp."
    ) + f'<p class="notice">{e(NETWORK_NOTICE)}</p>'
    return (_error_box(error) if error else "") + note + m.form("/new/preview", request.form_token, inner, "Preview what would be sealed")


def _form_values(request: Request) -> Dict[str, str]:
    fields = request.fields
    values = {name: fields.text(name) or "" for name in ("folder", "purpose", "out")}
    values["exclude"] = "\n".join(fields.lines("exclude"))
    profile = fields.text("profile")
    if profile is not None:
        values["profile"] = profile
    return values


def new_seal_page(request: Request) -> Response:
    return _page("New seal", _seal_form(request, {}), "/new")


def new_seal_preview(request: Request) -> Response:
    values = _form_values(request)
    try:
        args = actions.seal_args(request.app, request.fields)
        preview = actions.preview_seal(args)
    except (HttpError, EvidenceSealError) as exc:
        message = exc.message if isinstance(exc, HttpError) else str(exc)
        return _page("New seal", _seal_form(request, values, message), "/new", status=400)
    parts = [m.paragraph("Dry run: no file was opened or hashed, and nothing was written.")]
    parts.append(
        m.facts(
            [
                ("Folder", e(preview["folder"])),
                ("Would seal", e(f"{count_of(preview['file_count'], 'file')}, {size_text(preview['total_bytes'])}")),
                ("Manifest would be", e(preview["manifest_path"])),
                ("Purpose", e(preview["purpose"] or "none given")),
            ]
        )
    )
    problems = []
    if preview["manifest_exists"]:
        problems.append("The manifest file already exists. Choose another manifest file name.")
    if preview["purpose"] is None:
        problems.append("A seal needs a purpose, saying why it is being made.")
    if not preview["file_count"]:
        problems.append("The folder has no files to seal after the exclude patterns.")
    if preview["unreadable"]:
        problems.append("Some files could not be read, so sealing would stop. They are listed below.")
    for problem in problems:
        parts.append(_error_box(problem))
    if preview["ready"]:
        inner = "".join(m.hidden(name, value) for name, value in values.items())
        parts.append(m.form("/new/seal", request.form_token, inner, "Seal these files"))
    shown = preview["files"]
    parts.append(f"<h2>Files ({preview['file_count']})</h2>")
    parts.append(m.table(("Size in bytes", "Path"), [(e(item["size"]), f'<span class="mono">{e(item["path"])}</span>') for item in shown]))
    if len(shown) < preview["file_count"]:
        parts.append(m.paragraph(f"The first {len(shown)} are shown."))
    if preview["excluded"]:
        parts.append(f"<h2>Not sealed, by exclude patterns ({len(preview['excluded'])})</h2>")
        parts.append(m.table(("Path", "Pattern", "From"), [(e(item["path"]), e(item["pattern"]), e(item["source"] or "no source")) for item in preview["excluded"]]))
    if preview["by_name_only"]:
        parts.append(f"<h2>Listed by name only, not hashed ({len(preview['by_name_only'])})</h2>" + m.items(preview["by_name_only"]))
    if preview["unmatched_patterns"]:
        parts.append("<h2>Exclude patterns that matched nothing</h2>" + m.paragraph("Check their spelling."))
        parts.append(m.items(f"{item['pattern']} ({item['source']})" for item in preview["unmatched_patterns"]))
    if preview["unreadable"]:
        parts.append(f"<h2>Could not be read ({len(preview['unreadable'])})</h2>")
        parts.append(m.items(f"{item['path']}: {item['reason']}" for item in preview["unreadable"]))
    parts.append("<h2>Change something</h2>" + _seal_form(request, values))
    return _page("Preview of a new seal", "".join(parts), "/new")


def new_seal(request: Request) -> Response:
    job = actions.start_seal(request.app, actions.seal_args(request.app, request.fields))
    return redirect(f"/jobs/{job.id}")


# Check files I was given ---------------------------------------------------------------------------


def check_page(request: Request) -> Response:
    inner = (
        m.file_field("manifest", "Manifest", "the manifest file you were given", required=True)
        + m.file_field("token", "Token", "its timestamp token, usually ending in .tsr", required=True)
        + m.file_field("root", "Root certificate (optional)", "the authority's root, if you got it from the authority yourself")
        + m.text_field("folder", "Folder on this computer (optional)", "", "the full path of the files, to check them too")
        + _profile_field(request)
    )
    body = m.items(CHECK_NOTICES) + m.form("/check", request.form_token, inner, "Check", enctype="multipart/form-data")
    return _page("Check files I was given", body, "/check")


def check_start(request: Request) -> Response:
    job = actions.start_check(request.app, request.fields)
    return redirect(f"/jobs/{job.id}")


# Compare -------------------------------------------------------------------------------------------


def _comparison(comparison: comparing.Comparison, downloads: str) -> str:
    counts = comparison.counts
    summary = (
        f"The lists are identical: {count_of(len(comparison.changes), 'file')}, all unchanged."
        if comparison.identical
        else "The lists differ: " + ", ".join(f"{counts[outcome]} {outcome}" for outcome in comparing.OUTCOMES) + "."
    )
    parts = [
        m.facts(
            [
                ("Old", e(f"{comparison.old.label} ({comparison.old.kind}, {count_of(len(comparison.old.files), 'file')})")),
                ("New", e(f"{comparison.new.label} ({comparison.new.kind}, {count_of(len(comparison.new.files), 'file')})")),
            ]
        ),
        f"<p><strong>{e(summary)}</strong></p>",
        m.paragraph(comparing.LISTS_ONLY, "notice"),
        m.table(("Outcome", "Files"), [(e(outcome), e(count)) for outcome, count in counts.items()]),
    ]
    for outcome in (comparing.CHANGED, comparing.ADDED, comparing.REMOVED, comparing.MOVED):
        found = comparison.of(outcome)
        if found:
            shown = [f"{change.path} -> {change.new_path}" if change.outcome == comparing.MOVED else change.path for change in found[:1000]]
            more = [f"and {len(found) - 1000} more"] if len(found) > 1000 else []
            parts.append(f"<h2>{e(outcome.capitalize())} ({len(found)})</h2>" + m.items(shown + more))
    if comparison.notes:
        parts.append("<h2>Notes</h2>" + m.items(comparison.notes))
    parts.append(f"<p>Download this comparison: {downloads}</p>")
    return "".join(parts)


def compare_page(request: Request) -> Response:
    old = request.arg("old") or ""
    new = request.arg("new") or ""
    rows, _ = actions.list_seals()
    if not rows:
        return _page("Compare", m.paragraph("The library has no seals to compare yet."), "/compare")
    options = [(row["manifest_sha256"], f"{lib.short_id(row['manifest_sha256'])}: {row['purpose'] or 'no purpose'} ({row['created'] or 'no date'})") for row in rows]
    two = (
        '<form method="get" action="/compare">'
        + m.choice("old", "Earlier seal", options, old or options[0][0])
        + m.choice("new", "Later seal", options, new or options[-1][0])
        + '<button type="submit">Compare the two seals</button></form>'
    )
    folder_inner = m.choice("seal", "Seal", options, old or options[-1][0]) + m.text_field(
        "folder", "Folder (optional)", "", "leave empty to use where the seal's folder was last seen"
    )
    folder_form = m.form("/compare/folder", request.form_token, folder_inner, "Compare with the folder now")
    parts = ["<h2>Two seals from the library</h2>", m.paragraph("Reads the library's copies of both manifests. Nothing is hashed."), two]
    if old and new:
        if not (actions.is_sha(old) and actions.is_sha(new)):
            raise bad_request("choose both seals from the lists")
        comparison = actions.compare_seals(old, new)
        downloads = " ".join(m.link(m.url(f"/compare/download/{name}", old=old, new=new), name) for name in comparing.DIFF_FORMATS)
        parts.append("<h2>Result</h2>" + _comparison(comparison, downloads))
    parts += ["<h2>A seal and its folder as it is now</h2>", m.paragraph("Hashes the folder now, in the background. It stays offline."), folder_form]
    return _page("Compare", "".join(parts), "/compare")


def compare_download(request: Request) -> Response:
    old, new = request.arg("old") or "", request.arg("new") or ""
    if not (actions.is_sha(old) and actions.is_sha(new)):
        raise bad_request("give old and new, each a seal's full ID")
    comparison = actions.compare_seals(old, new)
    return actions.diff_download(comparison, request.params["format"], f"{lib.short_id(old)}-{lib.short_id(new)}")


def compare_folder(request: Request) -> Response:
    sha = request.fields.text("seal", required=True, label="seal") or ""
    if not actions.is_sha(sha):
        raise bad_request("choose the seal from the list")
    job = actions.start_compare_folder(request.app, sha, request.fields.text("folder"))
    return redirect(f"/jobs/{job.id}")


# Jobs ----------------------------------------------------------------------------------------------


def _job(request: Request) -> Job:
    job = request.app.runner.get(request.params["job"])
    if job is None:
        raise not_found("this job")
    return job


def jobs_page(request: Request) -> Response:
    jobs = request.app.runner.jobs()
    if not jobs:
        return _page("Jobs", m.paragraph("No job has run since these pages were started."), "/jobs")
    rows = [(m.link(f"/jobs/{job.id}", job.title), e(STATE_WORDS[job.state]), e(job.created), e(job.finished or "")) for job in jobs]
    body = m.paragraph("Jobs since these pages were started, newest first. They are not kept after serve stops.") + m.table(
        ("Job", "State", "Started", "Finished"), rows
    )
    return _page("Jobs", body, "/jobs")


def _seal_result(job: Job) -> str:
    result = job.result or {}
    rows = [
        ("Manifest", e(result["manifest_path"])),
        ("Sealed", e(f"{count_of(result['file_count'], 'file')}, {count_of(result['total_bytes'], 'byte')}")),
    ]
    if result["excluded"]:
        rows.append(("Not sealed, by exclude patterns", e(count_of(result["excluded"], "item"))))
    if result["by_name_only"]:
        rows.append(("Listed by name only, not hashed", e(count_of(result["by_name_only"], "link or special file"))))
    parts = [m.facts(rows)]
    if result["recorded"]:
        seal_link = m.link(f"/seals/{result['manifest_sha256']}", "the seal")
        parts.append(f"<p>The manifest alone proves no date. To get a timestamp, stamp it from {seal_link}.</p>")
    else:
        parts.append(m.paragraph(f"The manifest alone proves no date. To get a timestamp: evidence-seal stamp {result['manifest_path']}"))
    return "".join(parts)


def _stamp_result(job: Job) -> str:
    result = job.result or {}
    facts = result["facts"] or {}
    rows = [("Token", e(result["token_path"])), ("Request", e(result["query_path"]))]
    if result["root_path"]:
        rows.append(("Root certificate copied from the token", e(result["root_path"])))
    rows += [
        ("Time in token", e(facts.get("time") or "not stated")),
        ("Authority", e(facts.get("authority") or facts.get("signer") or "not stated")),
        ("From the authority list", e(f"{result['authority']}, checked against its roots only")),
    ]
    parts = [m.facts(rows)]
    if result["root_path"]:
        parts.append(m.paragraph("That copy of the root is for convenience. A reviewer should get the root from the authority and compare fingerprints."))
    if result["test_authority"]:
        parts.append(m.paragraph(f"{result['authority']} is a local test authority. This token proves nothing to anyone else.", "notice"))
    parts.append(m.items(f"[{check['status'].upper()}] {check['title']}" for check in result["checks"]))
    if result["notes"]:
        parts.append("<h2>Notes</h2>" + m.items(result["notes"]))
    if job.seal:
        parts.append(f"<p>Check it any time, offline, from {m.link(f'/seals/{job.seal}', 'the seal')}.</p>")
    return "".join(parts)


def _verification_result(job: Job) -> str:
    outcome, context = job.payload
    if outcome is None:
        reason = (job.result or {}).get("reason") or "no reason was given"
        return f'<section class="verdict verdict-incomplete"><h2>RESULT: INCOMPLETE</h2>{m.paragraph("No check could be made: " + reason)}</section>'
    parts = []
    if job.kind == actions.CHECK:
        given = [("Manifest uploaded", e(context.manifest_file)), ("Token uploaded", e(context.token_file))]
        if context.root_file is not None:
            given.append(("Root uploaded", e(context.root_file)))
        given.append(("Folder checked", e(outcome.folder) if outcome.folder is not None else '<span class="muted">none given</span>'))
        parts.append(m.facts(given))
        if outcome.folder is None:
            parts.append(m.paragraph("The file check was not run, because no folder was given. The result cannot be VERIFIED.", "notice"))
        if context.root_file is not None:
            parts.append(m.paragraph("The root certificate you uploaded was trusted for this check only, and was not kept.", "notice"))
    parts.append(m.verdict(outcome))
    parts.append("<h2>Download the report of this check</h2>" + _report_links(f"/jobs/{job.id}"))
    return "".join(parts)


def _compare_result(job: Job) -> str:
    downloads = " ".join(m.link(f"/jobs/{job.id}/diff/{name}", name) for name in comparing.DIFF_FORMATS)
    return _comparison(job.payload, downloads)


_RESULTS = {
    actions.SEAL: _seal_result,
    actions.STAMP: _stamp_result,
    actions.VERIFY: _verification_result,
    actions.CHECK: _verification_result,
    actions.COMPARE: _compare_result,
}


def job_page(request: Request) -> Response:
    job = _job(request)
    snapshot = job.to_dict()
    running = job.state not in FINISHED
    parts = [m.facts([("State", e(STATE_WORDS[job.state])), ("Started", e(job.created)), ("Finished", e(job.finished or "not yet"))])]
    if running:
        parts.append(
            f'<div data-job="{e(job.id)}" role="status" aria-live="polite">'
            f'<progress aria-label="Progress" max="1" value="0"></progress>'
            f'<p data-progress-text>{e(snapshot["progress_text"])}</p></div>'
            f'<p>{m.link(f"/jobs/{job.id}", "Refresh")} (this page also refreshes itself)</p>'
        )
        if snapshot["cancellable"]:
            parts.append(m.form(f"/jobs/{job.id}/cancel", request.form_token, "", "Cancel this job", button_css="danger"))
    if snapshot["messages"]:
        parts.append("<h2>Messages</h2>" + m.items(snapshot["messages"]))
    if job.error:
        parts.append(_error_box(job.error))
    if job.state == DONE:
        parts.append(_RESULTS[job.kind](job))
    if job.seal and job.kind != actions.STAMP:
        parts.append(f"<p>{m.link(f'/seals/{job.seal}', 'Go to the seal')}</p>")
    return _page(job.title, "".join(parts), refresh=running)


def job_cancel(request: Request) -> Response:
    job = _job(request)
    job.request_cancel()
    return redirect(f"/jobs/{job.id}")


def job_report(request: Request) -> Response:
    return actions.report_of(_job(request), request.params["format"])


def job_diff(request: Request) -> Response:
    job = _job(request)
    if job.kind != actions.COMPARE or job.state != DONE:
        raise HttpError(409, "no_result", "this job has no comparison to download")
    return actions.diff_download(job.payload, request.params["format"], job.seal[:12] if job.seal else "comparison")


# Authorities and settings --------------------------------------------------------------------------


def authorities_page(request: Request) -> Response:
    try:
        entries = actions.authority_list()
    except UsageError as exc:
        return _page("Authorities", _error_box(str(exc)), "/authorities")
    rows = []
    for entry in entries:
        kind = e(entry["kind"]) if not entry["test"] else f"<strong>{e(entry['kind'])}</strong>"
        rows.append((e(entry["name"]), f'<span class="mono">{e(entry["url"])}</span>', kind, e(len(entry["roots"])), e(entry["policy"] or "the authority chooses"), e(entry["hash"]), e(entry["note"])))
    body = (
        m.paragraph("Read only. Change the list with the authority command.")
        + m.paragraph(TEST_ONLY, "notice")
        + m.table(("Name", "URL", "Kind", "Roots", "Policy", "Hash", "Note"), rows)
    )
    return _page("Authorities", body, "/authorities")


def settings_page(request: Request) -> Response:
    try:
        view = actions.settings_view()
    except UsageError as exc:
        return _page("Settings", _error_box(str(exc)), "/settings")
    where = view["settings_file"] + ("" if view["exists"] else " (it does not exist, so built-in values apply)")
    parts = [m.paragraph(f"Settings file: {where}"), m.paragraph("Read only. Change them with the config and profile commands, or by editing the file.")]
    if request.app.profile:
        parts.append(m.paragraph(f"Forms on these pages start with the profile {request.app.profile}."))
    for profile in view["profiles"]:
        title = "[defaults], then built-in values" if profile["profile"] is None else f"Profile {profile['profile']}"
        rows = [
            (e(key), "<br>".join(e(line) for line in item["text"]) or '<span class="muted">none</span>', e(item["where"]))
            for key, item in profile["settings"].items()
        ]
        parts.append(f"<h2>{e(title)}</h2>" + m.table(("Key", "Value", "Where it came from"), rows))
    return _page("Settings", "".join(parts), "/settings")


def register(router: Router) -> None:
    router.add("GET", "/", overview)
    router.add("GET", "/seals/{sha}", seal_page)
    router.add("POST", "/seals/{sha}/verify", seal_verify)
    router.add("POST", "/seals/{sha}/stamp", seal_stamp)
    router.add("POST", "/seals/{sha}/tags", seal_tag)
    router.add("POST", "/seals/{sha}/untag", seal_tag)
    router.add("GET", "/seals/{sha}/forget", seal_forget_page)
    router.add("POST", "/seals/{sha}/forget", seal_forget)
    router.add("GET", "/seals/{sha}/report/{format}", seal_report)
    router.add("GET", "/seals/{sha}/export/{format}", seal_export)
    router.add("GET", "/new", new_seal_page)
    router.add("POST", "/new/preview", new_seal_preview)
    router.add("POST", "/new/seal", new_seal)
    router.add("GET", "/check", check_page)
    router.add("POST", "/check", check_start, UPLOAD_LIMIT)
    router.add("GET", "/compare", compare_page)
    router.add("GET", "/compare/download/{format}", compare_download)
    router.add("POST", "/compare/folder", compare_folder)
    router.add("GET", "/jobs", jobs_page)
    router.add("GET", "/jobs/{job}", job_page)
    router.add("POST", "/jobs/{job}/cancel", job_cancel)
    router.add("GET", "/jobs/{job}/report/{format}", job_report)
    router.add("GET", "/jobs/{job}/diff/{format}", job_diff)
    router.add("GET", "/authorities", authorities_page)
    router.add("GET", "/settings", settings_page)
