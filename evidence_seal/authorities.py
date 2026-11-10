"""The authority list: timestamp authorities a user can name instead of typing a URL.

Built-in entries come from trust.KNOWN_AUTHORITIES and cannot be removed or changed. The user's own
entries live in ``<home>/authorities.json``, and a copy of every root certificate the user chose for
them lives in ``<home>/authorities/``, named by its SHA-256 fingerprint. A root in this list is
trusted by verify and report just as a built-in fingerprint is, because the user chose it
independently of any token.

Every file read here is treated as hostile: sizes are bounded, every field is checked, and a stored
root must still match the fingerprint recorded for it. A list written by a newer version is refused
and never rewritten.

Public API: Entry, Root, FORMAT, list_path(), roots_folder(), check_name(), builtin_entries(),
user_entries(), all_entries(), find(), add(), remove(), trust_root(), untrust_root(), normalize_fingerprint(),
check_test_registration(), register_test_authority(), root_problem(), read_roots(), default_store(),
store_for(), entries_for_naming(), entry_for_root(), test_authority_for().
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from . import __version__, hashes, home, sealing, signatures, stamping, trust
from .errors import AuthorityListError, CertificateFileError, DerError, UsageError
from .signatures import Unsupported
from .trust import ListedRoot, TrustStore
from .x509 import KU_KEY_CERT_SIGN, Certificate, certificates_from_bytes

FORMAT = 1
LIST_FILE = "authorities.json"
ROOTS_FOLDER = "authorities"
MAX_LIST_BYTES = 1024 * 1024
MAX_ROOT_FILE_BYTES = 256 * 1024
MAX_ENTRIES = 500
MAX_ROOTS = 16
MAX_NOTE = 500
MAX_URL = 2048
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$")
_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
_DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
TEST_NOTE = "Made by test-authority init. Its tokens prove nothing to anyone else."


@dataclass
class Root:
    sha256: str
    certificate: Optional[Certificate] = None  # None for a built-in, which is known by fingerprint only


@dataclass
class Entry:
    name: str
    url: str
    roots: List[Root] = field(default_factory=list)
    policy: Optional[str] = None
    hash_name: str = "sha256"
    note: str = ""
    test: bool = False
    added: Optional[str] = None
    builtin: bool = False
    terms_url: Optional[str] = None
    root_url: Optional[str] = None

    def listed_roots(self) -> List[ListedRoot]:
        return [ListedRoot(root.sha256, self.name, self.test, root.certificate, self.builtin) for root in self.roots]

    def record(self) -> Dict[str, Any]:
        """The form kept in authorities.json."""
        return {
            "name": self.name,
            "url": self.url,
            "roots": [{"sha256": root.sha256} for root in self.roots],
            "policy": self.policy,
            "hash": self.hash_name,
            "note": self.note,
            "test": self.test,
            "added": self.added,
        }

    def to_dict(self) -> Dict[str, Any]:
        """The form printed by authority list --json and authority show --json."""
        roots = []
        for root in self.roots:
            cert = root.certificate
            roots.append(
                {
                    "sha256": root.sha256,
                    "subject": cert.subject.display() if cert else None,
                    "valid_from": cert.not_before.strftime("%Y-%m-%d") if cert else None,
                    "valid_to": cert.not_after.strftime("%Y-%m-%d") if cert else None,
                    "stored_copy": str(root_path(root.sha256)) if cert else None,
                }
            )
        return {
            "name": self.name,
            "url": self.url,
            "builtin": self.builtin,
            "test": self.test,
            "policy": self.policy,
            "hash": self.hash_name,
            "note": self.note,
            "added": self.added,
            "terms_url": self.terms_url,
            "root_url": self.root_url,
            "roots": roots,
        }


def list_path() -> Path:
    return home.home_dir() / LIST_FILE


def roots_folder() -> Path:
    return home.home_dir() / ROOTS_FOLDER


def root_path(fingerprint: str) -> Path:
    """Where the copy of a listed root lives. The name comes from a checked fingerprint, never from the list."""
    if not _FINGERPRINT.match(fingerprint):
        raise ValueError("not a SHA-256 fingerprint")
    return roots_folder() / f"{fingerprint}.pem"


def builtin_entries() -> List[Entry]:
    return [
        Entry(
            name=known.name,
            url=known.tsa_url,
            roots=[Root(known.root_sha256)],
            builtin=True,
            terms_url=known.terms_url,
            root_url=known.root_url,
        )
        for known in trust.KNOWN_AUTHORITIES
    ]


def _builtin_named(name: str) -> Optional[Entry]:
    for entry in builtin_entries():
        if entry.name.casefold() == name.casefold():
            return entry
    return None


def check_name(name: str) -> str:
    """A name for a new entry: short, plain, and not already a built-in."""
    if not _NAME.match(name):
        raise UsageError(
            f"{name!r} cannot be an authority name. Use up to 48 letters, digits, dots, hyphens and underscores,"
            " starting with a letter or digit"
        )
    if _builtin_named(name) is not None:
        raise UsageError(f"{name} is the name of a built-in authority, which cannot be removed or changed")
    return name


# Reading the list


def _damaged(path: Path, problem: str) -> AuthorityListError:
    return AuthorityListError(
        f"the authority list {path} is damaged: {problem}. Nothing was changed."
        " Fix that file, or move it away to start a new list"
    )


def _small_int(text: str) -> int:
    if len(text) > 18:
        raise ValueError("a number in it is far too long")
    return int(text)


def _read_bounded(path: Path, limit: int) -> Optional[bytes]:
    """The whole file, or None when it does not exist."""
    try:
        with open(path, "rb") as handle:
            if os.fstat(handle.fileno()).st_size > limit:
                raise AuthorityListError(f"{path} is too large to be part of the authority list (over {limit // 1024} KB)")
            return handle.read(limit + 1)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise AuthorityListError(f"cannot read {path}: {exc.strerror or exc}") from None


def _stored_root(path: Path, name: str, fingerprint: str) -> Certificate:
    copy = root_path(fingerprint)
    data = _read_bounded(copy, MAX_ROOT_FILE_BYTES)
    if data is None:
        raise _damaged(path, f"the stored copy of a root of {name} is missing ({copy})")
    try:
        found = certificates_from_bytes(data, str(copy))
    except CertificateFileError as exc:
        raise _damaged(path, f"the stored copy of a root of {name} cannot be read ({exc})") from None
    if len(found) != 1 or found[0].sha256 != fingerprint:
        raise _damaged(path, f"the stored copy {copy} of a root of {name} does not match its fingerprint")
    return found[0]


def _text(item: Dict[str, Any], key: str, limit: int, optional: bool = False) -> Optional[str]:
    value = item.get(key)
    if value is None and optional:
        return None
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError(f"its {key} is missing or not plain text of at most {limit} characters")
    return value


def _entry_from(item: Any, path: Path, seen: Dict[str, str]) -> Entry:
    if not isinstance(item, dict):
        raise _damaged(path, "an entry is not a JSON object")
    name = item.get("name")
    if not isinstance(name, str) or not _NAME.match(name) or _builtin_named(name) is not None:
        raise _damaged(path, f"an entry has a name that is not allowed ({str(name)[:60]!r})")
    if name.casefold() in seen:
        raise _damaged(path, f"the name {name} is used twice")
    seen[name.casefold()] = name
    try:
        url = _text(item, "url", MAX_URL)
        stamping.check_url(url)
        policy = _text(item, "policy", 200, optional=True)
        if policy is not None:
            stamping.checked_policy(policy)
        hash_name = _text(item, "hash", 20)
        algorithm = hashes.by_name(hash_name)
        if algorithm is None or algorithm.weak or algorithm.name not in ("sha256", "sha384", "sha512"):
            raise ValueError(f"its hash {hash_name!r} is not sha256, sha384 or sha512")
        note = _text(item, "note", MAX_NOTE)
        added = _text(item, "added", 10, optional=True)
        if added is not None and not _DATE.match(added):
            raise ValueError("its date added is not a date")
        test = item.get("test")
        if not isinstance(test, bool):
            raise ValueError("its test flag is not true or false")
        records = item.get("roots")
        if not isinstance(records, list) or len(records) > MAX_ROOTS:
            raise ValueError(f"its roots are not a list of at most {MAX_ROOTS}")
    except (ValueError, UsageError) as exc:
        raise _damaged(path, f"the entry {name}: {exc}") from None
    roots: List[Root] = []
    for record in records:
        fingerprint = record.get("sha256") if isinstance(record, dict) else None
        if not isinstance(fingerprint, str) or not _FINGERPRINT.match(fingerprint):
            raise _damaged(path, f"the entry {name} has a root fingerprint that is not 64 lowercase hex digits")
        if any(root.sha256 == fingerprint for root in roots):
            continue
        roots.append(Root(fingerprint, _stored_root(path, name, fingerprint)))
    return Entry(name, url, roots, policy, algorithm.name, note, test, added)


def user_entries() -> List[Entry]:
    """The user's own entries, from authorities.json. An absent file is an empty list."""
    path = list_path()
    data = _read_bounded(path, MAX_LIST_BYTES)
    if data is None:
        return []
    try:
        document = json.loads(data.decode("utf-8"), parse_int=_small_int)
    except UnicodeDecodeError:
        raise _damaged(path, "it is not UTF-8 text") from None
    except json.JSONDecodeError as exc:
        raise _damaged(path, f"{exc.msg} at line {exc.lineno}") from None
    except (ValueError, RecursionError) as exc:
        reason = "it is nested far too deeply" if isinstance(exc, RecursionError) else str(exc)
        raise _damaged(path, reason) from None
    if not isinstance(document, dict) or "format" not in document:
        raise _damaged(path, "it is not an authority list")
    version = document["format"]
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise _damaged(path, "its format is not a version number")
    if version > FORMAT:
        raise AuthorityListError(
            f"the authority list {path} uses format {version}, and evidence-seal {__version__} reads format {FORMAT}."
            " It was left unchanged. Use a newer version of evidence-seal to read or change it"
        )
    items = document.get("authorities", [])
    if not isinstance(items, list) or len(items) > MAX_ENTRIES:
        raise _damaged(path, f"its authorities are not a list of at most {MAX_ENTRIES}")
    seen: Dict[str, str] = {}
    return [_entry_from(item, path, seen) for item in items]


def all_entries() -> List[Entry]:
    return builtin_entries() + user_entries()


def find(name: str) -> Optional[Entry]:
    """The entry with this name, ignoring case, or None."""
    for entry in all_entries():
        if entry.name.casefold() == name.casefold():
            return entry
    return None


# Changing the list


def _save(entries: Sequence[Entry]) -> None:
    home.ensure_home()
    document = {"format": FORMAT, "authorities": [entry.record() for entry in entries if not entry.builtin]}
    data = (json.dumps(document, indent=2, ensure_ascii=True) + "\n").encode("ascii")
    sealing.write_new_file(list_path(), data, force=True)


def _store_roots(roots: Iterable[Root]) -> None:
    home.ensure_home()
    for root in roots:
        if root.certificate is None:
            continue
        pem = root.certificate.to_pem().encode("ascii")
        copy = root_path(root.sha256)
        try:
            if copy.read_bytes() == pem:
                continue
        except OSError:
            pass
        sealing.write_new_file(copy, pem, force=True)


def _forget_unused_roots(fingerprints: Iterable[str], entries: Sequence[Entry]) -> None:
    """Deletes stored copies that no entry uses any more. The file names come from checked fingerprints."""
    used = {root.sha256 for entry in entries for root in entry.roots}
    for fingerprint in set(fingerprints) - used:
        try:
            root_path(fingerprint).unlink()
        except OSError:
            pass


def root_problem(cert: Certificate) -> Optional[str]:
    """Why this certificate cannot anchor a chain, or None when it can."""
    subject = cert.subject.display()
    if not cert.self_issued:
        return (
            f"the certificate of {subject} was issued by {cert.issuer.display()}, so it is not a root."
            " Give the root certificate the authority publishes"
        )
    try:
        if cert.version >= 3:
            is_ca, _ = cert.basic_constraints()
            if not is_ca:
                return f"the certificate of {subject} is not marked as a certificate authority"
            usage = cert.key_usage()
            if usage is not None and KU_KEY_CERT_SIGN not in usage:
                return f"the certificate of {subject} is not allowed to sign certificates"
        outcome = signatures.verify(cert.public_key, cert.signature_algorithm, cert.tbs_raw, cert.signature)
    except Unsupported:
        return None
    except DerError as exc:
        return f"the certificate of {subject} is malformed: {exc}"
    if not outcome.valid:
        return f"the certificate of {subject} does not verify against its own key, so it is damaged"
    return None


def read_roots(path: Path) -> List[Root]:
    """Every certificate in a root file, each checked to be a usable root."""
    data = _read_bounded(Path(path), MAX_ROOT_FILE_BYTES)
    if data is None:
        raise UsageError(f"the root file {path} does not exist")
    try:
        found = certificates_from_bytes(data, str(path))
    except CertificateFileError as exc:
        raise UsageError(str(exc)) from None
    roots: List[Root] = []
    for cert in found:
        problem = root_problem(cert)
        if problem:
            raise UsageError(f"{path}: {problem}. Nothing was changed")
        roots.append(Root(cert.sha256, cert))
    return roots


def _user_entry(entries: Sequence[Entry], name: str) -> Entry:
    builtin = _builtin_named(name)
    if builtin is not None:
        raise UsageError(f"{builtin.name} is built in, so it cannot be removed or changed. Nothing was changed")
    for entry in entries:
        if entry.name.casefold() == name.casefold():
            return entry
    raise UsageError(f"there is no authority named {name!r} in the list. See the names with: authority list")


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _check_note(note: str) -> str:
    if len(note) > MAX_NOTE or any(ord(char) < 0x20 or ord(char) == 0x7F for char in note):
        raise UsageError(f"--note must be one line of at most {MAX_NOTE} characters")
    return note


def _check_hash(hash_name: str) -> str:
    algorithm = hashes.by_name(hash_name)
    if algorithm is None or algorithm.name not in ("sha256", "sha384", "sha512"):
        raise UsageError(f"--hash must be sha256, sha384 or sha512, not {hash_name!r}")
    return algorithm.name


def _merged(existing: List[Root], new: Sequence[Root]) -> Tuple[List[Root], List[Root]]:
    added = []
    for root in new:
        if all(root.sha256 != have.sha256 for have in existing + added):
            added.append(root)
    if len(existing) + len(added) > MAX_ROOTS:
        raise UsageError(f"an authority can have at most {MAX_ROOTS} roots. Nothing was changed")
    return existing + added, added


def add(
    name: str,
    url: str,
    root_files: Sequence[Path] = (),
    policy: Optional[str] = None,
    hash_name: str = "sha256",
    note: str = "",
) -> Entry:
    """Adds a user entry. Every argument is checked before anything is written."""
    check_name(name)
    entries = user_entries()
    if any(entry.name.casefold() == name.casefold() for entry in entries):
        raise UsageError(f"{name} is already in the authority list. Nothing was changed")
    if len(entries) >= MAX_ENTRIES:
        raise UsageError(f"the authority list already holds {MAX_ENTRIES} entries. Nothing was changed")
    if len(url) > MAX_URL:
        raise UsageError("the authority URL is far too long")
    stamping.check_url(url)
    roots: List[Root] = []
    for path in root_files:
        roots, _ = _merged(roots, read_roots(path))
    entry = Entry(
        name,
        url,
        roots,
        stamping.checked_policy(policy) if policy is not None else None,
        _check_hash(hash_name),
        _check_note(note),
        False,
        _today(),
    )
    _store_roots(roots)
    _save(entries + [entry])
    return entry


def remove(name: str) -> Entry:
    entries = user_entries()
    entry = _user_entry(entries, name)
    rest = [other for other in entries if other is not entry]
    _save(rest)
    _forget_unused_roots([root.sha256 for root in entry.roots], rest)
    return entry


def trust_root(name: str, root_file: Path) -> Tuple[Entry, List[Root]]:
    """Adds the roots in a file to an entry. Returns the entry and the roots that were new."""
    entries = user_entries()
    entry = _user_entry(entries, name)
    entry.roots, added = _merged(entry.roots, read_roots(root_file))
    if added:
        _store_roots(added)
        _save(entries)
    return entry, added


def normalize_fingerprint(text: str) -> str:
    """A fingerprint as openssl prints it, with colons, or as plain hex, in either case."""
    cleaned = "".join(text.split()).replace(":", "").lower()
    if not _FINGERPRINT.match(cleaned):
        raise UsageError(f"{text!r} is not a SHA-256 fingerprint (64 hex digits, colons allowed)")
    return cleaned


def untrust_root(name: str, fingerprint: str) -> Entry:
    wanted = normalize_fingerprint(fingerprint)
    entries = user_entries()
    entry = _user_entry(entries, name)
    if all(root.sha256 != wanted for root in entry.roots):
        have = ", ".join(root.sha256 for root in entry.roots) or "none"
        raise UsageError(f"{entry.name} has no root with that fingerprint. Its roots: {have}. Nothing was changed")
    entry.roots = [root for root in entry.roots if root.sha256 != wanted]
    _save(entries)
    _forget_unused_roots([wanted], entries)
    return entry


def check_test_registration(name: str, replace: bool = False) -> Tuple[List[Entry], Optional[Entry]]:
    """Raises a plain error now if a test authority could not be registered under this name.

    Returns the user's entries and the earlier test authority of that name, which ``replace`` allows
    to be replaced.
    """
    check_name(name)
    entries = user_entries()
    old = next((entry for entry in entries if entry.name.casefold() == name.casefold()), None)
    if old is not None and not old.test:
        raise UsageError(f"the authority list already has {old.name}, and it is not a test authority. Nothing was changed")
    if old is not None and not replace:
        raise UsageError(
            f"the authority list already has the test authority {old.name}. Use --force to replace it,"
            " after which tokens from the old one are no longer trusted. Nothing was changed"
        )
    return entries, old


def register_test_authority(name: str, url: str, root: Certificate, policy: str, replace: bool = False) -> Entry:
    """Adds a local test authority to the list, or replaces the earlier one when ``replace`` is set."""
    entries, old = check_test_registration(name, replace)
    entry = Entry(name, url, [Root(root.sha256, root)], policy, "sha256", TEST_NOTE, True, _today())
    rest = [other for other in entries if other is not old]
    _store_roots(entry.roots)
    _save(rest + [entry])
    if old is not None:
        _forget_unused_roots([item.sha256 for item in old.roots], rest + [entry])
    return entry


# Trust from the list


def default_store() -> TrustStore:
    """What verify and report trust without --ca: the built-in fingerprints and every listed root."""
    return TrustStore(listed=[root for entry in user_entries() for root in entry.listed_roots()])


def store_for(entry: Entry) -> TrustStore:
    """Only this entry's roots, as stamp --authority checks an answer."""
    return TrustStore(listed=entry.listed_roots(), only=f"the roots listed for {entry.name}")


def entries_for_naming() -> List[Entry]:
    """Every entry, for naming roots in output. A user list that cannot be read names nothing here."""
    try:
        return all_entries()
    except AuthorityListError:
        return builtin_entries()


def entry_for_root(fingerprint: str, entries: Optional[Sequence[Entry]] = None) -> Optional[Entry]:
    """The entry that lists this root, built-in or the user's."""
    for entry in entries_for_naming() if entries is None else entries:
        if any(root.sha256 == fingerprint for root in entry.roots):
            return entry
    return None


def test_authority_for(certificates: Iterable[Certificate], entries: Optional[Sequence[Entry]] = None) -> Optional[str]:
    """The name of the listed test authority one of these certificates is the root of, if any."""
    entries = entries_for_naming() if entries is None else entries
    for cert in certificates:
        entry = entry_for_root(cert.sha256, entries)
        if entry is not None and entry.test:
            return entry.name
    return None
