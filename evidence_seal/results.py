"""Verdicts. Every check ends in one of three states, and only one of them is a pass."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Status(Enum):
    PASS = "pass"
    FAIL = "fail"
    NOT_CHECKED = "not checked"


EXIT_VERIFIED = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_INCOMPLETE = 3
EXIT_INTERNAL = 4
EXIT_INTERRUPTED = 130

JSON_SCHEMA_VERSION = 1

VERIFIED = "VERIFIED"
FAILED = "FAILED"
INCOMPLETE = "INCOMPLETE"


@dataclass
class Check:
    key: str
    title: str
    status: Status
    detail: str
    method: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "title": self.title,
            "status": self.status.value,
            "detail": self.detail,
            "method": self.method,
        }


def overall_of(checks: List[Check]) -> str:
    """A pass needs every check to pass. One failure outranks anything not checked."""
    if any(check.status is Status.FAIL for check in checks):
        return FAILED
    if not checks or any(check.status is Status.NOT_CHECKED for check in checks):
        return INCOMPLETE
    return VERIFIED


def exit_code_of(overall: str) -> int:
    return {VERIFIED: EXIT_VERIFIED, FAILED: EXIT_FAILED, INCOMPLETE: EXIT_INCOMPLETE}[overall]


UNCHANGED = "unchanged"
CHANGED = "changed"
MISSING = "missing"
ADDED = "added"
MOVED = "moved"
UNREADABLE = "unreadable"
NOT_COMPARED = "not checked"


@dataclass
class FileRow:
    """One file's outcome, for reports that list every file. Hashes are lowercase hex, sizes in bytes."""

    path: str
    outcome: str
    algorithm: Optional[str] = None
    expected_hash: Optional[str] = None
    found_hash: Optional[str] = None
    expected_size: Optional[int] = None
    found_size: Optional[int] = None
    found_path: Optional[str] = None


@dataclass
class FileDifferences:
    """What a re-hash of the folder found. Lists hold relative paths."""

    total: int = 0
    unchanged: int = 0
    changed: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)
    added: List[str] = field(default_factory=list)
    unreadable: List[str] = field(default_factory=list)
    moved_hints: Dict[str, str] = field(default_factory=dict)
    own_files: List[str] = field(default_factory=list)
    other_unicode_forms: Dict[str, str] = field(default_factory=dict)
    rows: List[FileRow] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total": self.total,
            "unchanged": self.unchanged,
            "changed": self.changed,
            "missing": self.missing,
            "added": self.added,
            "unreadable": self.unreadable,
            "possible_moves": self.moved_hints,
            "own_files_not_compared": self.own_files,
            "matched_under_another_unicode_form": self.other_unicode_forms,
        }


@dataclass
class TokenFacts:
    """What the token claims. Facts for display, whether or not they verified."""

    status: str = ""
    time: Optional[str] = None
    accuracy: Optional[str] = None
    policy: Optional[str] = None
    hash_algorithm: Optional[str] = None
    hash_hex: Optional[str] = None
    serial: Optional[str] = None
    nonce: Optional[str] = None
    ordering: Optional[bool] = None
    authority: Optional[str] = None
    signer: Optional[str] = None
    signer_sha256: Optional[str] = None
    certificate_count: int = 0
    is_bare_token: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class Verification:
    """The full result of a verify run."""

    manifest_name: str
    manifest_sha256: str
    manifest_kind: str
    token_name: Optional[str]
    folder: Optional[str]
    purpose: Optional[str]
    created: Optional[str]
    file_count: int
    total_bytes: Optional[int]
    files: Check
    differences: Optional[FileDifferences]
    token_checks: List[Check]
    facts: Optional[TokenFacts]
    notes: List[str] = field(default_factory=list)
    limits: List[str] = field(default_factory=list)
    anchor_certificates: List[Any] = field(default_factory=list)
    checked_at: str = ""
    tool_version: str = ""
    file_rows: List[FileRow] = field(default_factory=list)
    test_authority: Optional[str] = None

    def test_authority_warning(self) -> Optional[str]:
        """A plain statement when the token comes from a local test authority. The verdict is unchanged."""
        if self.test_authority is None:
            return None
        return (
            f"This token comes from {self.test_authority}, a local test authority on this computer."
            " It proves nothing to anyone else: whoever holds its key file can sign any date."
        )

    @property
    def checks(self) -> List[Check]:
        return [self.files] + self.token_checks

    @property
    def overall(self) -> str:
        return overall_of(self.checks)

    @property
    def exit_code(self) -> int:
        return exit_code_of(self.overall)

    def check(self, key: str) -> Optional[Check]:
        for item in self.checks:
            if item.key == key:
                return item
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": JSON_SCHEMA_VERSION,
            "overall": self.overall,
            "exit_code": self.exit_code,
            "manifest": {
                "name": self.manifest_name,
                "sha256": self.manifest_sha256,
                "kind": self.manifest_kind,
                "purpose": self.purpose,
                "created": self.created,
                "file_count": self.file_count,
                "total_bytes": self.total_bytes,
            },
            "token": self.token_name,
            "folder": self.folder,
            "files": self.files.to_dict(),
            "differences": self.differences.to_dict() if self.differences else None,
            "token_checks": [check.to_dict() for check in self.token_checks],
            "facts": self.facts.to_dict() if self.facts else None,
            "notes": self.notes,
            "not_checked_by_design": self.limits,
            "checked_at": self.checked_at,
            "tool_version": self.tool_version,
            "test_authority": self.test_authority,
        }
