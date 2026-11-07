"""Turns a verification into readable text."""

from __future__ import annotations

from typing import List

from .results import FAILED, VERIFIED, Status, Verification
from .text import count_of, printable_block

MAX_LISTED = 200
_STATUS_WORD = {Status.PASS: "PASS", Status.FAIL: "FAIL", Status.NOT_CHECKED: "NOT CHECKED"}


def status_word(status: Status) -> str:
    return _STATUS_WORD[status]


def summary_sentence(verification: Verification) -> str:
    overall = verification.overall
    if overall == VERIFIED:
        facts = verification.facts
        when = facts.time if facts else "the token's time"
        return (
            f"Every check passed. The listed files are byte for byte what the manifest records, and a validly signed"
            f" token covers that manifest. This shows the files existed by {when}, according to the authority."
        )
    if overall == FAILED:
        failed = [check.title for check in verification.checks if check.status is Status.FAIL]
        return "This is not a valid proof as it stands. Failed: " + "; ".join(failed) + "."
    missing = [check.title for check in verification.checks if check.status is Status.NOT_CHECKED]
    return "This is not a pass. Nothing failed, but these could not be established: " + "; ".join(missing) + "."


def _list_paths(lines: List[str], title: str, paths: List[str], hints=None) -> None:
    if not paths:
        return
    lines.append(f"  {title} ({len(paths)}):")
    for path in paths[:MAX_LISTED]:
        suffix = ""
        if hints and path in hints:
            suffix = f"  (the same bytes are now at {hints[path]})"
        lines.append(f"    {path}{suffix}")
    if len(paths) > MAX_LISTED:
        lines.append(f"    ... and {len(paths) - MAX_LISTED} more")


def render_text(verification: Verification) -> str:
    lines: List[str] = []
    lines.append(f"Manifest: {verification.manifest_name} ({verification.manifest_kind})")
    lines.append(f"  SHA-256: {verification.manifest_sha256}")
    if verification.purpose:
        lines.append(f"  Purpose stated in it: {verification.purpose}")
    if verification.created:
        lines.append(f"  Created field (a claim, not proof): {verification.created}")
    size = "" if verification.total_bytes is None else f", {verification.total_bytes} bytes"
    lines.append(f"  Lists: {count_of(verification.file_count, 'file')}{size}")
    lines.append(f"Token: {verification.token_name or 'none'}")
    lines.append(f"Folder: {verification.folder or 'not checked'}")
    lines.append("")
    lines.append("FILES")
    check = verification.files
    lines.append(f"  [{status_word(check.status)}] {check.title}: {check.detail}")
    differences = verification.differences
    if differences is not None:
        _list_paths(lines, "Changed", differences.changed)
        _list_paths(lines, "Missing", differences.missing, differences.moved_hints)
        _list_paths(lines, "Added", differences.added)
        _list_paths(lines, "Could not be read", differences.unreadable)
    lines.append("")
    lines.append("TIMESTAMP TOKEN")
    for item in verification.token_checks:
        lines.append(f"  [{status_word(item.status)}] {item.title}: {item.detail}")
        if item.method:
            lines.append(f"      checked with: {item.method}")
    facts = verification.facts
    if facts is not None and facts.time:
        lines.append("")
        lines.append("WHAT THE TOKEN SAYS")
        lines.append(f"  Status: {facts.status}")
        lines.append(f"  Time: {facts.time} ({facts.accuracy})")
        lines.append(f"  Policy: {facts.policy}")
        lines.append(f"  Hash algorithm: {facts.hash_algorithm}")
        lines.append(f"  Authority: {facts.authority or facts.signer or 'not stated'}")
        lines.append(f"  Serial number: {facts.serial}")
    if verification.notes:
        lines.append("")
        lines.append("NOTES")
        lines.extend(f"  {note}" for note in verification.notes)
    lines.append("")
    lines.append("NOT CHECKED BY THIS TOOL IN ANY RUN")
    lines.extend(f"  {limit}" for limit in verification.limits)
    lines.append("")
    lines.append(f"RESULT: {verification.overall}")
    lines.append(summary_sentence(verification))
    return printable_block(lines)
