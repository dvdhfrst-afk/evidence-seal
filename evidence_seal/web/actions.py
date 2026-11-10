"""What the pages and the JSON API do, built on the command line's own code.

Each action calls the functions the commands call, with the settings applied by the same code, so a
seal, token or verdict made here is the one the command line would make, recorded in the library the
same way: a seal as ``seal`` records it, a token as ``stamp`` does, and a verification as
``library verify`` does. Checking files someone gave you is not recorded, because the uploaded copies
it uses are removed as soon as the check ends.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from .. import authorities, cli, comparing, exporting, hashes, home, library_commands, manifest, report_formats, scan
from .. import library as lib
from .. import sealing, settings, stamping, verification
from ..errors import EvidenceSealError, UsageError
from ..library import Library
from ..reporting import ReportContext
from ..results import Check, Status, Verification
from ..text import printable
from . import inputs
from .inputs import Fields
from .jobs import DONE, Job
from .multipart import Part
from .routing import HttpError, Response, download, not_found, safe_file_name

SEALS_PER_PAGE = 50
FILES_PER_PAGE = 100
MAX_PREVIEW_FILES = 1000
MAX_RUNS = 50
MAX_EVENTS = 200
SEAL, STAMP, VERIFY, CHECK, COMPARE = "seal", "stamp", "verify", "check", "compare"
EXPORT_TYPES = {
    "sha256sum": (".sha256", "text/plain; charset=utf-8"),
    "bsd": (".bsd.txt", "text/plain; charset=utf-8"),
    "csv": (".files.csv", "text/csv; charset=utf-8"),
    "json": (".files.json", "application/json"),
}
DIFF_TYPES = {
    "text": (".diff.txt", "text/plain; charset=utf-8"),
    "json": (".diff.json", "application/json"),
    "csv": (".diff.csv", "text/csv; charset=utf-8"),
    "markdown": (".diff.md", "text/markdown; charset=utf-8"),
}
_SHA = re.compile(r"[0-9a-f]{64}")
NO_FOLDER = "not run: no folder was given, so only the token was checked against the manifest"
NOT_VERIFIED_YET = (
    "this seal has not been verified since these pages were started. Verify it now, and the report comes from that check"
)


# The library ---------------------------------------------------------------------------------------


@contextmanager
def existing_library() -> Iterator[Optional[Library]]:
    """The library, if there is one yet. Reading never creates it."""
    found = lib.open_library(create=False)
    try:
        yield found
    finally:
        if found is not None:
            found.close()


def is_sha(text: str) -> bool:
    """A seal's full ID: the 64 lowercase hex digits of its manifest's SHA-256."""
    return bool(_SHA.fullmatch(text))


def seal_row(library: Optional[Library], sha: str) -> Dict[str, Any]:
    row = library.seal(sha) if library is not None else None
    if row is None:
        raise not_found("this seal")
    return row


def seal_json(row: Dict[str, Any]) -> Dict[str, Any]:
    """A seal in the shape ``library list --json`` prints."""
    return library_commands._seal_json(row)


def manifest_of(library: Library, sha: str) -> manifest.Manifest:
    return manifest.parse(library.read_object(sha, lib.MANIFEST))


def manifest_name(row: Dict[str, Any]) -> str:
    return Path(row["manifest_path"]).name if row["manifest_path"] else f"{lib.short_id(row['manifest_sha256'])}.txt"


def seal_label(row: Dict[str, Any]) -> str:
    return f"seal {lib.short_id(row['manifest_sha256'])} ({manifest_name(row)})"


def list_seals(query: str = "", tag: str = "", folder: str = "") -> Tuple[List[Dict[str, Any]], List[str]]:
    """Seals matching every filter given, oldest first, and every tag in use. Filters match text only."""
    with existing_library() as found:
        rows = found.seals() if found is not None else []
    tags = sorted({item for row in rows for item in row["tags"]})
    if query:
        needle = query.casefold()
        keys = ("manifest_sha256", "purpose", "folder_name", "folder_path", "manifest_path")
        rows = [row for row in rows if any(needle in (row[key] or "").casefold() for key in keys)]
    if tag:
        wanted = lib.check_tag(tag)
        rows = [row for row in rows if wanted in row["tags"]]
    if folder:
        needle = folder.casefold()
        rows = [row for row in rows if row["folder_path"] and needle in row["folder_path"].casefold()]
    return rows, tags


def page_of(items: Sequence[Any], page: int, per_page: int) -> Tuple[List[Any], int]:
    pages = max(1, (len(items) + per_page - 1) // per_page)
    if page > pages:
        raise not_found("this page of the list")
    return list(items[(page - 1) * per_page : page * per_page]), pages


def seal_detail(sha: str) -> Dict[str, Any]:
    with existing_library() as found:
        row = seal_row(found, sha)
        assert found is not None
        return {
            "seal": row,
            "tokens": found.tokens(sha),
            "runs": found.runs(sha, MAX_RUNS),
            "events": found.events(sha, MAX_EVENTS),
            "notes": found.notes(sha),
            "manifest": manifest_of(found, sha),
        }


def file_rows(data: manifest.Manifest) -> List[Dict[str, Any]]:
    return [
        {"path": entry.path, "size": entry.size, "algorithm": entry.algorithm.display, "hash": entry.hexdigest}
        for entry in data.entries
    ]


def export(sha: str, form: str) -> Response:
    """A seal's file list in one of the export command's formats, from the library's copy of its manifest."""
    if form not in EXPORT_TYPES:
        raise not_found("this export format")
    with existing_library() as found:
        row = seal_row(found, sha)
        data = manifest_of(found, sha)  # type: ignore[arg-type]
    name = manifest_name(row)
    suffix, media_type = EXPORT_TYPES[form]
    return download(exporting.render_export(data, name, form), media_type, safe_file_name(Path(name).stem, suffix))


def change_tag(sha: str, tag: str, add: bool) -> bool:
    with existing_library() as found:
        seal_row(found, sha)
        assert found is not None
        return found.tag(sha, tag) if add else found.untag(sha, tag)


def add_note(sha: str, text: str) -> int:
    """Adds a note, as library note does. Returns its number."""
    with existing_library() as found:
        seal_row(found, sha)
        assert found is not None
        return found.add_note(sha, text)


def forget(sha: str) -> int:
    with existing_library() as found:
        seal_row(found, sha)
        assert found is not None
        return found.forget(sha)


# Settings, applied as the command line applies them ------------------------------------------------


def profile_names() -> List[str]:
    """The profiles in the settings file, or none when it cannot be read; using one then says why."""
    try:
        document = settings.read_document(settings.default_path(), required=False)
    except UsageError:
        return []
    return [section.name or "" for section in document.profiles()] if document is not None else []


def profile_choice(app: Any, value: Optional[str]) -> Optional[str]:
    """The profile a form chose: the one serve started with when the form says nothing, none when it is blank."""
    if value is None:
        return app.profile
    return value.strip() or None


def command_args(command: str, profile: Optional[str], **values: Any) -> argparse.Namespace:
    args = argparse.Namespace(command=command, profile=profile, settings_file=None, no_settings=False, no_library=False, **values)
    cli._apply_settings(args)
    return args


def settings_view() -> Dict[str, Any]:
    """The effective settings of [defaults] and of each profile, with where each value came from."""
    path = settings.default_path()
    document = settings.read_document(path, required=False)
    if document is not None:
        settings.require_usable(document)
    names: List[Optional[str]] = [None] + ([section.name for section in document.profiles()] if document else [])
    profiles = []
    for name in names:
        resolved = settings.resolve(document, name, path)
        values = {}
        for key, item in resolved.items.items():
            values[key] = {
                "value": settings.KEYS[key].json_of(item.value),
                "text": item.text(),
                "source": item.origin,
                "where": item.source(),
                "file": str(item.file) if item.file is not None else None,
                "line": item.line,
            }
        profiles.append({"profile": name, "settings": values})
    return {"schema_version": 1, "settings_file": str(path), "exists": document is not None, "profiles": profiles}


def authority_kind(entry: authorities.Entry) -> str:
    if entry.builtin:
        return "built in"
    if entry.test:
        return "local test authority, TEST ONLY"
    return f"added {entry.added}"


def authority_list() -> List[Dict[str, Any]]:
    return [dict(entry.to_dict(), kind=authority_kind(entry)) for entry in authorities.all_entries()]


# Seal ----------------------------------------------------------------------------------------------


def seal_args(app: Any, fields: Fields) -> argparse.Namespace:
    folder = inputs.existing_folder(fields.text("folder", required=True, label="folder to seal"), "folder to seal")
    out_text = (fields.text("out") or "").strip()
    out = inputs.new_file(out_text, "manifest file") if out_text else None
    purpose = (fields.text("purpose") or "").strip() or None
    excludes = [("--exclude", pattern) for pattern in fields.lines("exclude")]
    profile = profile_choice(app, fields.text("profile"))
    args = command_args("seal", profile, folder=folder, purpose=purpose, exclude=excludes, out=out, date=None)
    args.rules = cli.exclude_rules(args)
    return args


def preview_seal(args: argparse.Namespace) -> Dict[str, Any]:
    """What ``seal --dry-run`` shows. No file is opened or hashed, and nothing is written."""
    preview = sealing.preview_folder(args.folder, args.rules, args.out, args.date)
    return {
        "folder": str(preview.folder),
        "manifest_path": str(preview.manifest_path),
        "manifest_exists": preview.manifest_exists,
        "purpose": args.purpose,
        "profile": args.profile,
        "file_count": len(preview.files),
        "total_bytes": preview.total_bytes,
        "files": [{"path": path, "size": size} for path, size in preview.files[:MAX_PREVIEW_FILES]],
        "excluded": [{"path": path, "pattern": rule.text, "source": rule.source} for path, rule in preview.left_out],
        "by_name_only": preview.links + preview.special,
        "unmatched_patterns": [{"pattern": rule.text, "source": rule.source} for rule in preview.unmatched],
        "unreadable": [{"path": path, "reason": reason} for path, reason in preview.errors],
        "ready": bool(preview.files) and not preview.errors and not preview.manifest_exists and args.purpose is not None,
    }


def start_seal(app: Any, args: argparse.Namespace) -> Job:
    if args.purpose is None:
        raise UsageError("a seal needs a purpose, saying why it is being made")

    def work(job: Job) -> Tuple[Dict[str, Any], Any]:
        result = sealing.seal_folder(args.folder, args.purpose, args.rules, args.out, args.date, False, job.meter("Hashed"))
        sha = scan.hash_file(result.manifest_path, hashes.SHA256)[0]
        job.update(seal=sha)
        recorded = lib.record_quietly(args.no_library, lib.record_seal, result.manifest_path, args.folder, notify=job.note)
        if not lib.recording_wanted(args.no_library):
            job.note("Not recorded in the library, because the settings or EVIDENCE_SEAL_LIBRARY turn recording off.")
        return {
            "manifest_path": str(result.manifest_path),
            "manifest_sha256": sha,
            "file_count": result.file_count,
            "total_bytes": result.total_bytes,
            "excluded": len(result.excluded),
            "by_name_only": len(result.links) + len(result.special),
            "unmatched_patterns": [{"pattern": rule.text, "source": rule.source} for rule in result.unmatched],
            "recorded": recorded,
        }, result

    return app.runner.start(SEAL, f"Seal {args.folder.name or args.folder}", work, cancellable=True)


# Stamp ---------------------------------------------------------------------------------------------


def manifest_on_disk(row: Dict[str, Any]) -> Path:
    """The seal's own manifest file, which must still hold exactly the bytes that were sealed."""
    text = row["manifest_path"]
    if not text or not Path(text).is_file():
        raise HttpError(
            409,
            "manifest_not_found",
            "the library does not know where this seal's manifest file is now, so a token would have nowhere to go."
            " Nothing was sent. Stamp it from the command line: evidence-seal stamp MANIFEST"
        )
    path = Path(text)
    if scan.hash_file(path, hashes.SHA256)[0] != row["manifest_sha256"]:
        message = f"{printable(path)} has changed since it was sealed, so it is no longer this seal's manifest. Nothing was sent"
        raise HttpError(409, "manifest_changed", message)
    return path


def stamp_choices() -> List[authorities.Entry]:
    """Authorities a stamp can use: those with a root to check the answer against, as stamp --authority needs."""
    return [entry for entry in authorities.all_entries() if entry.roots]


def start_stamp(app: Any, sha: str, fields: Fields) -> Job:
    with existing_library() as found:
        row = seal_row(found, sha)
    path = manifest_on_disk(row)
    name = (fields.text("authority", required=True, label="authority") or "").strip()
    args = command_args(
        "stamp",
        profile_choice(app, fields.text("profile")),
        manifest=path,
        tsa_url=None,
        authority=name,
        hash_name=None,
        policy=None,
        out=None,
        timeout=None,
        retries=None,
        ca=[],
        force=False,
    )
    url, hash_name, policy, store, entry = cli._stamp_settings(args)
    assert entry is not None

    def work(job: Job) -> Tuple[Dict[str, Any], Any]:
        job.note(f"Sending the hash of the manifest to {url}. This is the only network request these pages make.")
        result = stamping.stamp_manifest(
            path,
            tsa_url=url,
            hash_name=hash_name,
            policy=policy,
            timeout=args.timeout,
            store=store,
            retries=args.retries,
            notify=job.note,
        )
        recorded = lib.record_quietly(args.no_library, lib.record_stamp, path, result, notify=job.note)
        return {
            "token_path": str(result.token_path),
            "query_path": str(result.query_path),
            "root_path": str(result.root_path) if result.root_path else None,
            "facts": result.facts.to_dict() if result.facts else None,
            "checks": [check.to_dict() for check in result.checks],
            "notes": result.notes,
            "kept": [str(item) for item in result.kept],
            "authority": entry.name,
            "test_authority": entry.test,
            "recorded": recorded,
        }, result

    return app.runner.start(STAMP, f"Stamp seal {lib.short_id(sha)} with {entry.name}", work, seal=sha)


# Verify and reports --------------------------------------------------------------------------------


def seal_context(row: Dict[str, Any], outcome: Verification) -> ReportContext:
    root = None
    if row["manifest_path"]:
        candidate = sealing.root_path_for(Path(row["manifest_path"]))
        root = candidate.name if candidate.is_file() else None
    return ReportContext(manifest_file=outcome.manifest_name, token_file=outcome.token_name, root_file=root)


def start_verify(app: Any, sha: str, folder_text: Optional[str]) -> Job:
    with existing_library() as found:
        row = seal_row(found, sha)
    folder = inputs.existing_folder(folder_text) if folder_text and folder_text.strip() else None

    def work(job: Job) -> Tuple[Dict[str, Any], Any]:
        with existing_library() as found:
            if found is None or found.seal(sha) is None:
                raise UsageError("this seal is no longer in the library, so it was not verified")
            checked = library_commands.verify_seal(found, sha, folder, job.meter("Checked"))
        context = seal_context(row, checked.outcome) if checked.outcome is not None else None
        return checked.to_dict(), (checked.outcome, context)

    return app.runner.start(VERIFY, f"Verify seal {lib.short_id(sha)}", work, seal=sha, cancellable=True)


def has_report(job: Optional[Job]) -> bool:
    return job is not None and job.kind in (VERIFY, CHECK) and job.state == DONE and job.payload[0] is not None


def report_of(job: Job, form: str) -> Response:
    if not has_report(job):
        raise HttpError(409, "no_result", "this job has no verification result to report on")
    try:
        chosen = report_formats.by_name(form)
    except ValueError:
        raise not_found("this report format") from None
    outcome, context = job.payload
    return download(chosen.render(outcome, context), chosen.media_type, safe_file_name(Path(context.manifest_file).stem, chosen.suffix))


def seal_report(app: Any, sha: str, form: str) -> Response:
    """The report of this seal's newest check made through these pages."""
    with existing_library() as found:
        seal_row(found, sha)
    job = app.runner.latest(VERIFY, sha)
    if not has_report(job):
        raise HttpError(409, "not_verified_yet", NOT_VERIFIED_YET)
    assert job is not None
    return report_of(job, form)


# Compare -------------------------------------------------------------------------------------------


def compare_seals(old: str, new: str) -> comparing.Comparison:
    warnings: List[str] = []
    sides = []
    with existing_library() as found:
        for sha in (old, new):
            row = seal_row(found, sha)
            data = manifest_of(found, sha)  # type: ignore[arg-type]
            sides.append(comparing.listing_of_data(data, manifest_name(row), seal_label(row), warnings.append))
    comparison = comparing.compare(sides[0], sides[1])
    comparison.notes.extend(warnings)
    return comparison


def start_compare_folder(app: Any, sha: str, folder_text: Optional[str]) -> Job:
    with existing_library() as found:
        row = seal_row(found, sha)
        data = manifest_of(found, sha)  # type: ignore[arg-type]
    if folder_text and folder_text.strip():
        folder = inputs.existing_folder(folder_text)
    elif row["folder_path"] and Path(row["folder_path"]).is_dir():
        folder = Path(row["folder_path"])
    else:
        raise UsageError("the library does not know where this seal's folder is now. Give its path")
    warnings: List[str] = []
    old = comparing.listing_of_data(data, manifest_name(row), seal_label(row), warnings.append)
    rules: List[scan.ExcludeItem] = list(data.excludes)
    if row["manifest_path"]:
        rules += sealing.own_file_rules(folder.resolve(), Path(row["manifest_path"]).resolve())

    def work(job: Job) -> Tuple[Dict[str, Any], Any]:
        new = comparing.listing_of_folder(folder, str(folder), rules, job.meter("Hashed"))
        comparison = comparing.compare(old, new)
        comparison.notes.extend(warnings)
        return json.loads(comparing.render_diff(comparison, "json")), comparison

    return app.runner.start(COMPARE, f"Compare seal {lib.short_id(sha)} with its folder now", work, seal=sha, cancellable=True)


def diff_download(comparison: comparing.Comparison, form: str, stem: str) -> Response:
    if form not in DIFF_TYPES:
        raise not_found("this comparison format")
    suffix, media_type = DIFF_TYPES[form]
    return download(comparing.render_diff(comparison, form), media_type, safe_file_name(stem, suffix))


# Checking files someone gave you -------------------------------------------------------------------


def _given(part: Optional[Part]) -> bool:
    """A browser sends an empty part with no file name for a file field left empty."""
    return part is not None and part.is_file and (bool(part.data) or bool(part.filename))


def _shown_name(part: Part, default: str) -> str:
    """The uploaded file's own name, only to show it: the last part, with no folders, never used as a path."""
    name = (part.filename or "").replace("\\", "/").rsplit("/", 1)[-1].strip()
    return printable(name)[:200] or default


def scratch_folder() -> Path:
    """A private folder inside evidence-seal's own folder, so an upload never lands among a user's files."""
    return Path(tempfile.mkdtemp(prefix="web-check-", dir=str(home.ensure_home())))


def start_check(app: Any, fields: Fields) -> Job:
    """Checks an uploaded token against an uploaded manifest, and the files in a folder when one is given."""
    parts = {}
    for name, label in (("manifest", "manifest"), ("token", "token")):
        part = fields.file(name)
        if not _given(part) or not part.data:  # type: ignore[union-attr]
            raise UsageError(f"choose the {label} file to check")
        parts[name] = part
    root = fields.file("root")
    root = root if _given(root) else None
    if root is not None and not root.data:
        raise UsageError("the root certificate file is empty")
    folder_text = (fields.text("folder") or "").strip()
    folder = inputs.existing_folder(folder_text, "folder to check") if folder_text else None
    profile = profile_choice(app, fields.text("profile"))
    names = (
        _shown_name(parts["manifest"], "manifest.txt"),
        _shown_name(parts["token"], "token.tsr"),
        _shown_name(root, "root.crt") if root is not None else None,
    )
    scratch = scratch_folder()
    try:
        manifest_copy = scratch / "manifest.txt"
        token_copy = sealing.token_path_for(manifest_copy)
        root_copy = scratch / "root.crt"
        sealing.write_new_file(manifest_copy, parts["manifest"].data)
        sealing.write_new_file(token_copy, parts["token"].data)
        if root is not None:
            sealing.write_new_file(root_copy, root.data)
        args = command_args(
            "verify",
            profile,
            manifest=manifest_copy,
            token=token_copy,
            folder=folder,
            query=None,
            ca=[root_copy] if root is not None else [],
            untrusted=[],
            exclude=[],
            allow_added=False,
            skip_files=folder is None,
            openssl=False,
        )
        options = cli._options(args)
    except BaseException:
        shutil.rmtree(scratch, ignore_errors=True)
        raise

    def work(job: Job) -> Tuple[Dict[str, Any], Any]:
        try:
            options.report = job.meter("Checked")
            outcome = verification.verify(options)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
        outcome.manifest_name, outcome.token_name = names[0], names[1]
        if folder is None:
            outcome.files = Check(verification.FILES, "Files match the manifest", Status.NOT_CHECKED, NO_FOLDER)
        return outcome.to_dict(), (outcome, ReportContext(names[0], names[1], names[2]))

    title = "Check uploaded files" + (f" against {folder.name or folder}" if folder is not None else ", token only")
    try:
        return app.runner.start(CHECK, title, work, cancellable=True)
    except EvidenceSealError:
        shutil.rmtree(scratch, ignore_errors=True)
        raise
