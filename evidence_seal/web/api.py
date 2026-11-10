"""The JSON API under /api/v1/, documented with examples in docs/WEB.md.

Answers are JSON objects. A failure is ``{"error": {"code": ..., "message": ...}}`` with a fitting
HTTP status. A verification is ``Verification.to_dict()`` exactly as ``verify --json`` prints it, and
seals and runs have the shapes ``library show --json`` prints. Work that hashes files or uses the
network starts a job and answers 202 with it; poll ``GET /api/v1/jobs/ID`` until its state is
done, failed or cancelled. The same session, key, form token and Origin rules apply as for the pages.
"""

from __future__ import annotations

from typing import Any, Dict

from .. import __version__, comparing, exporting, report_formats
from .. import library as lib
from ..results import JSON_SCHEMA_VERSION
from . import actions, inputs
from .jobs import DONE, Job
from .routing import UPLOAD_LIMIT, HttpError, Request, Response, Router, bad_request, json_response, not_found

API_VERSION = 1
PREFIX = "/api/v1"


def _job_answer(job: Job) -> Response:
    response = json_response({"schema_version": JSON_SCHEMA_VERSION, "job": job.to_dict()}, 202)
    response.headers.append(("Location", f"{PREFIX}/jobs/{job.id}"))
    return response


def _seal_param(request: Request) -> str:
    return request.params["sha"]


def health(request: Request) -> Response:
    return json_response({"status": "ok", "api_version": API_VERSION, "tool_version": __version__})


def seals(request: Request) -> Response:
    rows, tags = actions.list_seals(request.arg("q") or "", request.arg("tag") or "", request.arg("folder") or "")
    page = inputs.page_number(request.arg("page"))
    shown, pages = actions.page_of(rows, page, actions.SEALS_PER_PAGE)
    return json_response(
        {
            "schema_version": JSON_SCHEMA_VERSION,
            "total": len(rows),
            "page": page,
            "pages": pages,
            "tags": tags,
            "seals": [actions.seal_json(row) for row in shown],
        }
    )


def seal(request: Request) -> Response:
    detail = actions.seal_detail(_seal_param(request))
    data = detail["manifest"]
    return json_response(
        {
            "schema_version": JSON_SCHEMA_VERSION,
            "seal": actions.seal_json(detail["seal"]),
            "tokens": detail["tokens"],
            "runs": detail["runs"],
            "events": detail["events"],
            "files": {"count": len(data.entries), "by_name_only": len(data.links) + len(data.special)},
        }
    )


def seal_files(request: Request) -> Response:
    data = actions.seal_detail(_seal_param(request))["manifest"]
    page = inputs.page_number(request.arg("page"))
    rows, pages = actions.page_of(actions.file_rows(data), page, actions.FILES_PER_PAGE)
    return json_response(
        {"schema_version": JSON_SCHEMA_VERSION, "total": len(data.entries), "page": page, "pages": pages, "files": rows}
    )


def seal_export(request: Request) -> Response:
    return actions.export(_seal_param(request), request.params["format"])


def seal_report(request: Request) -> Response:
    return actions.seal_report(request.app, _seal_param(request), request.params["format"])


def seal_verify(request: Request) -> Response:
    return _job_answer(actions.start_verify(request.app, _seal_param(request), request.fields.text("folder")))


def seal_stamp(request: Request) -> Response:
    return _job_answer(actions.start_stamp(request.app, _seal_param(request), request.fields))


def seal_tag(request: Request) -> Response:
    sha = _seal_param(request)
    tag = lib.check_tag(request.fields.text("tag", required=True, label="tag") or "")
    added = request.path.endswith("/tags")
    changed = actions.change_tag(sha, tag, added)
    return json_response({"schema_version": JSON_SCHEMA_VERSION, "tag": tag, "added" if added else "removed": changed})


def seal_forget(request: Request) -> Response:
    sha = _seal_param(request)
    if not request.fields.flag("confirm"):
        raise bad_request("forgetting a seal needs confirm set to yes")
    dropped = actions.forget(sha)
    return json_response({"schema_version": JSON_SCHEMA_VERSION, "forgotten": sha, "copies_removed": dropped})


def new_seal(request: Request) -> Response:
    args = actions.seal_args(request.app, request.fields)
    if request.fields.flag("dry_run"):
        return json_response({"schema_version": JSON_SCHEMA_VERSION, "preview": actions.preview_seal(args)})
    return _job_answer(actions.start_seal(request.app, args))


def _job(request: Request) -> Job:
    job = request.app.runner.get(request.params["job"])
    if job is None:
        raise not_found("this job")
    return job


def jobs(request: Request) -> Response:
    return json_response({"schema_version": JSON_SCHEMA_VERSION, "jobs": [job.to_dict() for job in request.app.runner.jobs()]})


def job(request: Request) -> Response:
    return json_response({"schema_version": JSON_SCHEMA_VERSION, "job": _job(request).to_dict()})


def job_cancel(request: Request) -> Response:
    found = _job(request)
    if not found.request_cancel():
        raise HttpError(409, "not_cancellable", "this job has finished, or cannot be stopped safely once started")
    return json_response({"schema_version": JSON_SCHEMA_VERSION, "job": found.to_dict()})


def job_report(request: Request) -> Response:
    return actions.report_of(_job(request), request.params["format"])


def job_diff(request: Request) -> Response:
    found = _job(request)
    if found.kind != actions.COMPARE or found.state != DONE:
        raise HttpError(409, "no_result", "this job has no comparison to download")
    return actions.diff_download(found.payload, request.params["format"], found.seal[:12] if found.seal else "comparison")


def compare(request: Request) -> Response:
    old, new = request.arg("old") or "", request.arg("new") or ""
    if not (actions.is_sha(old) and actions.is_sha(new)):
        raise bad_request("give old and new, each a seal's full ID")
    form = request.arg("format") or "json"
    comparison = actions.compare_seals(old, new)
    return actions.diff_download(comparison, form, f"{old[:12]}-{new[:12]}")


def compare_folder(request: Request) -> Response:
    sha = request.fields.text("seal", required=True, label="seal") or ""
    if not actions.is_sha(sha):
        raise bad_request("seal must be a seal's full ID")
    return _job_answer(actions.start_compare_folder(request.app, sha, request.fields.text("folder")))


def check(request: Request) -> Response:
    return _job_answer(actions.start_check(request.app, request.fields))


def authority_list(request: Request) -> Response:
    return json_response({"schema_version": JSON_SCHEMA_VERSION, "authorities": actions.authority_list()})


def settings_view(request: Request) -> Response:
    return json_response(actions.settings_view())


def formats(request: Request) -> Response:
    """The format names each download accepts."""
    data: Dict[str, Any] = {
        "schema_version": JSON_SCHEMA_VERSION,
        "report": [{"name": item.name, "description": item.description, "media_type": item.media_type} for item in report_formats.REPORT_FORMATS],
        "export": list(exporting.EXPORT_FORMATS),
        "diff": list(comparing.DIFF_FORMATS),
    }
    return json_response(data)


def register(router: Router) -> None:
    router.add("GET", f"{PREFIX}/health", health)
    router.add("GET", f"{PREFIX}/formats", formats)
    router.add("GET", f"{PREFIX}/seals", seals)
    router.add("GET", f"{PREFIX}/seals/{{sha}}", seal)
    router.add("GET", f"{PREFIX}/seals/{{sha}}/files", seal_files)
    router.add("GET", f"{PREFIX}/seals/{{sha}}/export/{{format}}", seal_export)
    router.add("GET", f"{PREFIX}/seals/{{sha}}/report/{{format}}", seal_report)
    router.add("POST", f"{PREFIX}/seals/{{sha}}/verify", seal_verify)
    router.add("POST", f"{PREFIX}/seals/{{sha}}/stamp", seal_stamp)
    router.add("POST", f"{PREFIX}/seals/{{sha}}/tags", seal_tag)
    router.add("POST", f"{PREFIX}/seals/{{sha}}/untag", seal_tag)
    router.add("POST", f"{PREFIX}/seals/{{sha}}/forget", seal_forget)
    router.add("POST", f"{PREFIX}/seal", new_seal)
    router.add("GET", f"{PREFIX}/jobs", jobs)
    router.add("GET", f"{PREFIX}/jobs/{{job}}", job)
    router.add("POST", f"{PREFIX}/jobs/{{job}}/cancel", job_cancel)
    router.add("GET", f"{PREFIX}/jobs/{{job}}/report/{{format}}", job_report)
    router.add("GET", f"{PREFIX}/jobs/{{job}}/diff/{{format}}", job_diff)
    router.add("GET", f"{PREFIX}/compare", compare)
    router.add("POST", f"{PREFIX}/compare/folder", compare_folder)
    router.add("POST", f"{PREFIX}/check", check, UPLOAD_LIMIT)
    router.add("GET", f"{PREFIX}/authorities", authority_list)
    router.add("GET", f"{PREFIX}/settings", settings_view)
