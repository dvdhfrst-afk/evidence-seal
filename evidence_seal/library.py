"""The seal library: a record, on this computer, of every seal made or checked here.

What it keeps, under ``<home>/library/``:

- ``index.sqlite3``: an SQLite index of seals, their tokens, verification runs, tags and a journal of
  events. Its schema version is ``PRAGMA user_version``, and ``migrate`` upgrades it.
- ``objects/``: a copy of every manifest, token, request and root certificate the library has seen,
  named by the SHA-256 of its bytes, written atomically and checked against that hash on every read.

The library writes only inside that folder. It never moves, changes or deletes a user's own files.

Other parts of evidence-seal use it through:

- ``recording_wanted(no_library)``: the one place that decides whether a command records.
- ``record_quietly(no_library, action, *arguments, notify=warn)``: runs ``record_seal``,
  ``record_stamp`` or ``record_verification`` and turns any library problem into one warning line,
  on standard error unless ``notify`` sends it elsewhere, so the command's result, output and exit
  code never change.
- ``open_library(create)`` and the ``Library`` methods, for reading and changing what is recorded.
"""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Sequence, Set, Tuple

from . import __version__, hashes, home, manifest, scan, sealing, showing, stamping, tsp, verification
from .console import warn
from .errors import CertificateFileError, DerError, EvidenceSealError, TokenFormatError, UsageError
from .results import Status, Verification
from .text import count_of, printable
from .x509 import certificates_from_bytes

FOLDER_NAME = "library"
INDEX_NAME = "index.sqlite3"
OBJECTS_NAME = "objects"
SWITCH_VARIABLE = "EVIDENCE_SEAL_LIBRARY"
_OFF_WORDS = ("off", "no", "false", "0")
BUSY_SECONDS = 15.0

MANIFEST = "manifest"
TOKEN = "token"
REQUEST = "request"
ROOT = "root"
_MB = 1024 * 1024
OBJECT_LIMITS = {MANIFEST: 256 * _MB, TOKEN: tsp.MAX_TOKEN_BYTES, REQUEST: _MB, ROOT: _MB}
EVENT_KINDS = ("sealed", "stamped", "verified", "imported", "tagged", "untagged", "forgotten")

MIN_ID_DIGITS = 6
SHORT_ID_DIGITS = 12
MAX_TAG_LENGTH = 64
MAX_TEXT_LENGTH = 2000
MAX_PATH_LENGTH = 32768
MAX_LIST_ROWS = 100000
MAX_LOG_LIMIT = 10000
MAX_PROBLEMS = 1000
_SHA = re.compile(r"^[0-9a-f]{64}$")
_HEX = re.compile(r"^[0-9a-f]{1,64}$")
_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class LibraryError(EvidenceSealError):
    """The library could not be read or written. The user's own files are never involved."""


class NewerLibrary(LibraryError):
    """The index was written by a newer evidence-seal, so this one must not touch it."""


class TokenNotUsable(LibraryError):
    """A token that cannot be kept with this manifest, with the reason."""


def library_root(environ: Optional[Mapping[str, str]] = None) -> Path:
    return home.home_dir(environ) / FOLDER_NAME


def recording_wanted(no_library: bool, environ: Optional[Mapping[str, str]] = None) -> bool:
    """Whether a command records into the library. ``--no-library`` and EVIDENCE_SEAL_LIBRARY=off turn it off."""
    if no_library:
        return False
    environ = os.environ if environ is None else environ
    return environ.get(SWITCH_VARIABLE, "").strip().lower() not in _OFF_WORDS


def now_text(moment: Optional[datetime] = None) -> str:
    return (moment or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime(_TIME_FORMAT)


def short_id(sha: str) -> str:
    return sha[:SHORT_ID_DIGITS]


# Schema -------------------------------------------------------------------------------------------

_SCHEMA_1 = (
    """CREATE TABLE objects (
        sha256 TEXT PRIMARY KEY,
        kind TEXT NOT NULL CHECK (kind IN ('manifest', 'token', 'request', 'root')),
        size INTEGER NOT NULL CHECK (size >= 0),
        added_at TEXT NOT NULL
    )""",
    """CREATE TABLE seals (
        manifest_sha256 TEXT PRIMARY KEY REFERENCES objects (sha256),
        purpose TEXT,
        created TEXT,
        folder_name TEXT,
        file_count INTEGER NOT NULL,
        total_bytes INTEGER,
        manifest_kind TEXT NOT NULL CHECK (manifest_kind IN ('native', 'hand-made')),
        manifest_path TEXT,
        folder_path TEXT,
        added_at TEXT NOT NULL
    )""",
    """CREATE TABLE tokens (
        manifest_sha256 TEXT NOT NULL REFERENCES seals (manifest_sha256) ON DELETE CASCADE,
        token_sha256 TEXT NOT NULL REFERENCES objects (sha256),
        token_time TEXT,
        authority TEXT,
        serial TEXT,
        is_current INTEGER NOT NULL CHECK (is_current IN (0, 1)),
        request_sha256 TEXT REFERENCES objects (sha256),
        root_sha256 TEXT REFERENCES objects (sha256),
        token_path TEXT,
        added_at TEXT NOT NULL,
        PRIMARY KEY (manifest_sha256, token_sha256)
    )""",
    """CREATE TABLE runs (
        id INTEGER PRIMARY KEY,
        manifest_sha256 TEXT NOT NULL REFERENCES seals (manifest_sha256) ON DELETE CASCADE,
        token_sha256 TEXT,
        command TEXT NOT NULL,
        run_at TEXT NOT NULL,
        overall TEXT NOT NULL,
        exit_code INTEGER NOT NULL,
        folder_path TEXT
    )""",
    """CREATE TABLE run_checks (
        run_id INTEGER NOT NULL REFERENCES runs (id) ON DELETE CASCADE,
        position INTEGER NOT NULL,
        key TEXT NOT NULL,
        title TEXT NOT NULL,
        status TEXT NOT NULL,
        PRIMARY KEY (run_id, position)
    )""",
    """CREATE TABLE tags (
        manifest_sha256 TEXT NOT NULL REFERENCES seals (manifest_sha256) ON DELETE CASCADE,
        tag TEXT NOT NULL,
        PRIMARY KEY (manifest_sha256, tag)
    )""",
    """CREATE TABLE events (
        id INTEGER PRIMARY KEY,
        at TEXT NOT NULL,
        kind TEXT NOT NULL,
        manifest_sha256 TEXT,
        detail TEXT NOT NULL,
        tool_version TEXT NOT NULL
    )""",
    "CREATE INDEX runs_by_seal ON runs (manifest_sha256, id)",
    "CREATE INDEX events_by_seal ON events (manifest_sha256, id)",
    "CREATE INDEX tokens_by_object ON tokens (token_sha256)",
)


def _create_schema_1(connection: sqlite3.Connection) -> None:
    for statement in _SCHEMA_1:
        connection.execute(statement)


Migration = Tuple[int, Callable[[sqlite3.Connection], None]]

# Each step takes the index from the version before it to the version it names. Steps run in order,
# all inside one transaction, so an upgrade either completes or leaves the index as it was.
MIGRATIONS: Tuple[Migration, ...] = ((1, _create_schema_1),)


def _user_version(connection: sqlite3.Connection) -> int:
    return int(connection.execute("PRAGMA user_version").fetchone()[0])


def _check_steps(migrations: Sequence[Migration]) -> int:
    for number, (target, _) in enumerate(migrations, 1):
        if target != number:
            raise ValueError(f"migration steps must be numbered 1, 2, 3 and so on; step {number} is {target}")
    return len(migrations)


def _backup_path(index_path: Path, version: int, moment: Optional[datetime]) -> Path:
    stamp = (moment or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
    candidate = index_path.with_name(f"{index_path.name}.backup-schema{version}-{stamp}")
    number = 1
    while os.path.lexists(candidate):
        number += 1
        candidate = index_path.with_name(f"{index_path.name}.backup-schema{version}-{stamp}-{number}")
    return candidate


def _make_backup(index_path: Path, version: int, moment: Optional[datetime]) -> Path:
    """A copy of the index before an upgrade. Taken while holding the write lock, so it is consistent."""
    target = _backup_path(index_path, version, moment)
    try:
        data = index_path.read_bytes()
    except OSError as exc:
        raise LibraryError(f"cannot copy {index_path} before upgrading it: {exc.strerror or exc}. Nothing was changed") from None
    sealing.write_new_file(target, data)
    return target


def _newer(index_path: Path, version: int, known: int) -> NewerLibrary:
    return NewerLibrary(
        f"the library index {index_path} uses schema {version}, and this evidence-seal ({__version__}) knows"
        f" schema {known} at most. It was left exactly as it was. Use the newer evidence-seal that wrote it,"
        " or run commands with --no-library"
    )


def migrate(
    connection: sqlite3.Connection,
    index_path: Path,
    migrations: Sequence[Migration] = MIGRATIONS,
    moment: Optional[datetime] = None,
) -> Optional[Path]:
    """Brings the index up to the newest schema in ``migrations``. Returns the backup made, if any."""
    known = _check_steps(migrations)
    version = _user_version(connection)
    if version == known:
        return None
    if version > known:
        raise _newer(index_path, version, known)  # Before any lock, so nothing is ever written to it
    connection.execute("BEGIN IMMEDIATE")
    backup = None
    try:
        version = _user_version(connection)
        if version > known:
            raise _newer(index_path, version, known)
        if version == known:
            connection.execute("COMMIT")
            return None
        has_tables = connection.execute("SELECT count(*) FROM sqlite_master").fetchone()[0]
        if version == 0 and has_tables:
            raise LibraryError(
                f"{index_path} is an SQLite database but not an evidence-seal library. Nothing was changed."
                " Move it aside, and evidence-seal will start a new library"
            )
        if version > 0:
            backup = _make_backup(index_path, version, moment)
    except BaseException:
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    step = version
    try:
        for target, run_step in migrations:
            if target <= version:
                continue
            step = target
            run_step(connection)
            connection.execute(f"PRAGMA user_version = {int(target)}")
        connection.execute("COMMIT")
    except BaseException as exc:
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        if not isinstance(exc, Exception):
            raise
        kept = f" The copy made before the upgrade is kept at {backup}." if backup else ""
        raise LibraryError(
            f"upgrading the library index {index_path} from schema {version} failed at the step to schema {step}"
            f" ({type(exc).__name__}: {exc}). The index was left at schema {version}, as it was.{kept}"
        ) from None
    return backup


# Opening ------------------------------------------------------------------------------------------


def _plain_database_error(exc: sqlite3.Error, index_path: Path) -> LibraryError:
    text = str(exc)
    lowered = text.lower()
    if "locked" in lowered or "busy" in lowered:
        return LibraryError(
            f"the library index {index_path} stayed busy for {BUSY_SECONDS:g} seconds, because another"
            " evidence-seal command is using it. Nothing was changed. Try again in a moment"
        )
    if "not a database" in lowered or "malformed" in lowered or "corrupt" in lowered:
        return LibraryError(
            f"the library index {index_path} is damaged and cannot be read ({text}). Nothing was changed."
            " Restore it from a backup, or move it aside and evidence-seal will start a new library"
        )
    if "unable to open" in lowered:
        return LibraryError(f"cannot open the library index {index_path} ({text}). Nothing was changed")
    if "readonly" in lowered or "read-only" in lowered:
        return LibraryError(f"the library index {index_path} cannot be written ({text}). Nothing was changed")
    return LibraryError(f"the library index {index_path} could not be used ({text}). Nothing was changed")


def _connect(index_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(str(index_path), timeout=BUSY_SECONDS, isolation_level=None)
    connection.row_factory = sqlite3.Row
    return connection


def open_library(
    create: bool = True,
    root: Optional[Path] = None,
    migrations: Sequence[Migration] = MIGRATIONS,
) -> Optional["Library"]:
    """Opens the library, upgrading its schema if needed. With ``create`` false, None when there is none yet."""
    root = Path(root) if root is not None else library_root()
    index_path = root / INDEX_NAME
    if os.path.lexists(index_path) and not index_path.is_file():
        raise LibraryError(f"{index_path} should be the library index, but it is not a regular file. Nothing was changed")
    if not index_path.exists():
        if not create:
            return None
        try:
            if root == library_root():
                home.ensure_home()
            root.mkdir(parents=True, exist_ok=True)
            if os.name != "nt":
                os.chmod(root, 0o700)
        except OSError as exc:
            raise LibraryError(f"cannot create the library folder {root}: {exc.strerror or exc}") from None
    try:
        connection = _connect(index_path)
    except sqlite3.Error as exc:
        raise _plain_database_error(exc, index_path) from None
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        migrate(connection, index_path, migrations)
        connection.execute("SELECT count(*) FROM sqlite_master").fetchone()  # Reads the first page, where damage shows
    except sqlite3.Error as exc:
        connection.close()
        raise _plain_database_error(exc, index_path) from None
    except BaseException:
        connection.close()
        raise
    return Library(root, connection)


# Reading files the user pointed at ----------------------------------------------------------------


def _read_whole(handle: Any, limit: int) -> Optional[bytes]:
    """The whole file, or None when it is over ``limit`` or changed size while being read."""
    size = os.fstat(handle.fileno()).st_size
    if size > limit:
        return None
    data = handle.read(size + 1)
    return data if len(data) == size else None


def read_bounded(path: Path, kind: str) -> bytes:
    """Reads one file the library is about to keep, refusing anything larger than that kind can be."""
    limit = OBJECT_LIMITS[kind]
    try:
        with open(path, "rb") as handle:
            data = _read_whole(handle, limit)
    except OSError as exc:
        raise LibraryError(f"cannot read {path}: {exc.strerror or exc}") from None
    if data is None:
        raise LibraryError(
            f"{path} is too large for the library to keep as a {kind} (over {limit // _MB} MB), or changed while it was read"
        )
    return data


def _optional_file(path: Optional[Path], kind: str) -> Optional[bytes]:
    if path is None or not Path(path).is_file():
        return None
    try:
        return read_bounded(Path(path), kind)
    except LibraryError:
        return None


def token_facts(token_bytes: bytes, manifest_bytes: bytes) -> Dict[str, Any]:
    """What a token says, after making sure it is a granted token that covers these manifest bytes."""
    try:
        response = tsp.parse_response(token_bytes)
        facts = showing.describe(token_bytes)
    except (DerError, TokenFormatError) as exc:
        raise TokenNotUsable(f"it is not a timestamp token ({exc})") from None
    if not response.granted or response.tst_info is None:
        raise TokenNotUsable("it holds the authority's refusal, not a token")
    algorithm = hashes.by_oid(response.tst_info.hash_oid)
    if algorithm is None or algorithm.digest(manifest_bytes) != response.tst_info.digest:
        raise TokenNotUsable("it does not cover this manifest")
    return facts


def _usable_request(data: Optional[bytes]) -> Optional[bytes]:
    if data is None:
        return None
    try:
        tsp.parse_request(data)
    except (DerError, TokenFormatError):
        return None
    return data


def _usable_root(data: Optional[bytes]) -> Optional[bytes]:
    if data is None:
        return None
    try:
        if not certificates_from_bytes(data, "root copy"):
            return None
    except (CertificateFileError, DerError, TokenFormatError):
        return None
    return data


def _path_text(path: Optional[Path]) -> Any:
    """A path as stored: text, or its raw bytes when the name is not valid text, so it comes back exactly."""
    if path is None:
        return None
    text = os.path.abspath(str(path))
    if len(text) > MAX_PATH_LENGTH:
        return None
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return os.fsencode(text)
    return text


def path_of(value: Any) -> Optional[str]:
    if value is None:
        return None
    return os.fsdecode(value) if isinstance(value, bytes) else str(value)


def _display_text(text: Optional[str]) -> Optional[str]:
    if text is None:
        return None
    shown = printable(text)
    return shown if len(shown) <= MAX_TEXT_LENGTH else shown[: MAX_TEXT_LENGTH - 3] + "..."


def check_tag(tag: str) -> str:
    cleaned = tag.strip()
    if not cleaned or len(cleaned) > MAX_TAG_LENGTH or printable(cleaned) != cleaned:
        raise UsageError(f"a tag must be 1 to {MAX_TAG_LENGTH} printable characters, and {tag!r} is not")
    return cleaned


# The library --------------------------------------------------------------------------------------


class Library:
    """One open library. Use it in a ``with`` block so the index is closed afterwards."""

    def __init__(self, root: Path, connection: sqlite3.Connection):
        self.root = Path(root)
        self.index_path = self.root / INDEX_NAME
        self.objects_path = self.root / OBJECTS_NAME
        self.connection = connection
        self._depth = 0

    def __enter__(self) -> "Library":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self.connection.close()

    # Low level

    def _run(self, sql: str, parameters: Sequence[Any] = ()) -> sqlite3.Cursor:
        try:
            return self.connection.execute(sql, tuple(parameters))
        except sqlite3.Error as exc:
            raise _plain_database_error(exc, self.index_path) from None

    def _all(self, sql: str, parameters: Sequence[Any] = ()) -> List[sqlite3.Row]:
        try:
            return self.connection.execute(sql, tuple(parameters)).fetchall()
        except sqlite3.Error as exc:
            raise _plain_database_error(exc, self.index_path) from None

    def _one(self, sql: str, parameters: Sequence[Any] = ()) -> Optional[sqlite3.Row]:
        rows = self._all(sql, parameters)
        return rows[0] if rows else None

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """One short write transaction. Another command waits for it, up to BUSY_SECONDS.

        Nested uses join the outer one, so a command's whole record is written at once or not at all.
        """
        if self._depth:
            self._depth += 1
            try:
                yield
            finally:
                self._depth -= 1
            return
        self._run("BEGIN IMMEDIATE")
        self._depth = 1
        try:
            yield
            self._run("COMMIT")
        except BaseException:
            try:
                self.connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            self._depth = 0

    def schema_version(self) -> int:
        return int(self._one("PRAGMA user_version")[0])

    def _event(self, kind: str, sha: Optional[str], detail: str) -> None:
        if kind not in EVENT_KINDS:
            raise ValueError(f"unknown event kind {kind}")
        self._run(
            "INSERT INTO events (at, kind, manifest_sha256, detail, tool_version) VALUES (?, ?, ?, ?, ?)",
            (now_text(), kind, sha, _display_text(detail) or "", __version__),
        )

    # Objects

    def object_path(self, sha: str) -> Path:
        if not _SHA.match(sha):
            raise LibraryError(f"{sha!r} is not the name of a library object")
        return self.objects_path / sha[:2] / sha

    def _object_is_sound(self, path: Path, sha: str, size: int) -> bool:
        try:
            if not path.is_file() or path.stat().st_size != size:
                return False
            return scan.hash_file(path, hashes.SHA256)[0] == sha
        except OSError:
            return False

    def _store(self, kind: str, data: bytes) -> str:
        """Keeps a copy of ``data``. Called inside a transaction, so a forget cannot remove it meanwhile."""
        limit = OBJECT_LIMITS[kind]
        if len(data) > limit:
            raise LibraryError(f"this {kind} is too large for the library to keep (over {limit // _MB} MB)")
        sha = hashlib.sha256(data).hexdigest()
        path = self.object_path(sha)
        if not self._object_is_sound(path, sha, len(data)):
            sealing.write_new_file(path, data, force=True)
        self._run(
            "INSERT OR IGNORE INTO objects (sha256, kind, size, added_at) VALUES (?, ?, ?, ?)",
            (sha, kind, len(data), now_text()),
        )
        return sha

    def read_object(self, sha: str, kind: str) -> bytes:
        """The bytes of one copy, after checking them against their hash."""
        path = self.object_path(sha)
        limit = OBJECT_LIMITS[kind]
        try:
            with open(path, "rb") as handle:
                data = _read_whole(handle, limit)
        except FileNotFoundError:
            raise LibraryError(f"the library's copy of this {kind} is missing ({path}). Run: evidence-seal library check") from None
        except OSError as exc:
            raise LibraryError(f"cannot read the library's copy {path}: {exc.strerror or exc}") from None
        if data is None or hashlib.sha256(data).hexdigest() != sha:
            raise LibraryError(
                f"the library's copy of this {kind} is damaged: {path} no longer matches its hash."
                " Run: evidence-seal library check"
            )
        return data

    # Recording

    def add_seal(
        self,
        data: bytes,
        manifest_path: Optional[Path] = None,
        folder_path: Optional[Path] = None,
        event: str = "imported",
        detail: str = "",
    ) -> Tuple[str, bool]:
        """Records a manifest. Returns its SHA-256 and whether it was new to the library."""
        parsed = manifest.parse(data)
        with self.transaction():
            sha = self._store(MANIFEST, data)
            row = self._one("SELECT manifest_path, folder_path FROM seals WHERE manifest_sha256 = ?", (sha,))
            if row is None:
                self._run(
                    "INSERT INTO seals (manifest_sha256, purpose, created, folder_name, file_count, total_bytes,"
                    " manifest_kind, manifest_path, folder_path, added_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        sha,
                        _display_text(parsed.purpose),
                        _display_text(parsed.created),
                        _display_text(parsed.folder_name),
                        len(parsed.entries),
                        parsed.total_bytes,
                        parsed.kind,
                        _path_text(manifest_path),
                        _path_text(folder_path),
                        now_text(),
                    ),
                )
                self._event(event, sha, detail)
                return sha, True
            if manifest_path is not None:
                self._run("UPDATE seals SET manifest_path = ? WHERE manifest_sha256 = ?", (_path_text(manifest_path), sha))
            known_folder = path_of(row["folder_path"])
            if folder_path is not None and (known_folder is None or not Path(known_folder).is_dir()):
                self._run("UPDATE seals SET folder_path = ? WHERE manifest_sha256 = ?", (_path_text(folder_path), sha))
            return sha, False

    def add_token(
        self,
        manifest_sha: str,
        manifest_bytes: bytes,
        token_bytes: bytes,
        token_path: Optional[Path] = None,
        request: Optional[bytes] = None,
        root: Optional[bytes] = None,
        current: bool = True,
        event: Optional[str] = None,
    ) -> bool:
        """Records a token for a seal. Raises TokenNotUsable when it does not belong. True when it was new."""
        facts = token_facts(token_bytes, manifest_bytes)
        request = _usable_request(request)
        root = _usable_root(root)
        with self.transaction():
            if self._one("SELECT 1 FROM seals WHERE manifest_sha256 = ?", (manifest_sha,)) is None:
                raise LibraryError("the seal for this token is not in the library")
            token_sha = self._store(TOKEN, token_bytes)
            request_sha = self._store(REQUEST, request) if request is not None else None
            root_sha = self._store(ROOT, root) if root is not None else None
            known = self._one(
                "SELECT 1 FROM tokens WHERE manifest_sha256 = ? AND token_sha256 = ?", (manifest_sha, token_sha)
            )
            if known is None:
                self._run(
                    "INSERT INTO tokens (manifest_sha256, token_sha256, token_time, authority, serial, is_current,"
                    " request_sha256, root_sha256, token_path, added_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        manifest_sha,
                        token_sha,
                        _display_text(facts.get("time")),
                        _display_text(facts.get("authority") or facts.get("signer")),
                        _display_text(facts.get("serial")),
                        1 if current else 0,
                        request_sha,
                        root_sha,
                        _path_text(token_path),
                        now_text(),
                    ),
                )
                if event is not None:
                    self._event(event, manifest_sha, self._token_detail(facts, current))
                return True
            self._run(
                "UPDATE tokens SET is_current = ?, token_path = COALESCE(?, token_path),"
                " request_sha256 = COALESCE(request_sha256, ?), root_sha256 = COALESCE(root_sha256, ?)"
                " WHERE manifest_sha256 = ? AND token_sha256 = ?",
                (1 if current else 0, _path_text(token_path), request_sha, root_sha, manifest_sha, token_sha),
            )
            return False

    @staticmethod
    def _token_detail(facts: Dict[str, Any], current: bool) -> str:
        who = facts.get("authority") or facts.get("signer") or "an authority that is not named"
        state = "" if current else ", a token that stamp --force replaced"
        return f"token time {facts.get('time')} from {who}{state}"

    def add_run(self, manifest_sha: str, token_sha: Optional[str], command: str, outcome: Verification) -> int:
        """Records one verification run. The folder is remembered when its files matched."""
        with self.transaction():
            cursor = self._run(
                "INSERT INTO runs (manifest_sha256, token_sha256, command, run_at, overall, exit_code, folder_path)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    manifest_sha,
                    token_sha,
                    command,
                    now_text(),
                    outcome.overall,
                    outcome.exit_code,
                    _path_text(Path(outcome.folder)) if outcome.folder else None,
                ),
            )
            run_id = int(cursor.lastrowid)
            for position, check in enumerate(outcome.checks):
                self._run(
                    "INSERT INTO run_checks (run_id, position, key, title, status) VALUES (?, ?, ?, ?, ?)",
                    (run_id, position, check.key, _display_text(check.title), check.status.value),
                )
            if outcome.folder and outcome.files.status is Status.PASS:
                self._run(
                    "UPDATE seals SET folder_path = ? WHERE manifest_sha256 = ?",
                    (_path_text(Path(outcome.folder)), manifest_sha),
                )
            self._event("verified", manifest_sha, f"{command}: {outcome.overall}")
        return run_id

    # Finding seals

    def resolve(self, text: str) -> str:
        """A seal's SHA-256 from a unique ID prefix of at least six hex digits, or from a manifest path."""
        candidate = Path(text)
        if candidate.is_file():
            sha = hashlib.sha256(read_bounded(candidate, MANIFEST)).hexdigest()
            if self._one("SELECT 1 FROM seals WHERE manifest_sha256 = ?", (sha,)) is None:
                raise UsageError(f"{text} is not in the library. Add it with: evidence-seal library import PATH")
            return sha
        prefix = text.strip().lower()
        if not _HEX.match(prefix):
            raise UsageError(
                f"{text!r} is neither a seal ID nor a manifest file. An ID is the start of the manifest's SHA-256,"
                " as library list shows it"
            )
        if len(prefix) < MIN_ID_DIGITS:
            raise UsageError(f"a seal ID needs at least {MIN_ID_DIGITS} hex digits, and {text!r} has {len(prefix)}")
        rows = self._all(
            "SELECT manifest_sha256, created, purpose FROM seals WHERE substr(manifest_sha256, 1, ?) = ?"
            " ORDER BY manifest_sha256 LIMIT 11",
            (len(prefix), prefix),
        )
        if not rows:
            raise UsageError(f"no seal in the library has an ID starting with {prefix}. library list shows them")
        if len(rows) > 1:
            shown = "; ".join(f"{short_id(row[0])} ({row[1] or 'no date'}, {row[2] or 'no purpose'})" for row in rows[:10])
            more = ", and more" if len(rows) > 10 else ""
            raise UsageError(f"the ID {prefix} matches more than one seal: {shown}{more}. Give more digits")
        return rows[0][0]

    def seal(self, sha: str) -> Optional[Dict[str, Any]]:
        rows = self.seals(only=sha)
        return rows[0] if rows else None

    def seals(self, only: Optional[str] = None) -> List[Dict[str, Any]]:
        """Every seal with its newest current token time and its latest verification, oldest seal first."""
        where = "WHERE s.manifest_sha256 = ?" if only else ""
        rows = self._all(
            "SELECT s.*,"
            " (SELECT token_time FROM tokens t WHERE t.manifest_sha256 = s.manifest_sha256 AND t.is_current = 1"
            "  ORDER BY token_time DESC LIMIT 1) AS token_time,"
            " (SELECT overall FROM runs r WHERE r.manifest_sha256 = s.manifest_sha256 ORDER BY id DESC LIMIT 1)"
            "  AS last_result,"
            " (SELECT run_at FROM runs r WHERE r.manifest_sha256 = s.manifest_sha256 ORDER BY id DESC LIMIT 1)"
            "  AS last_checked"
            f" FROM seals s {where} ORDER BY s.created, s.added_at, s.manifest_sha256 LIMIT {MAX_LIST_ROWS}",
            (only,) if only else (),
        )
        tags: Dict[str, List[str]] = {}
        tag_rows = self._all(
            "SELECT manifest_sha256, tag FROM tags" + (" WHERE manifest_sha256 = ?" if only else "") + " ORDER BY tag",
            (only,) if only else (),
        )
        for row in tag_rows:
            tags.setdefault(row[0], []).append(row[1])
        found = []
        for row in rows:
            item = dict(row)
            item["manifest_path"] = path_of(item["manifest_path"])
            item["folder_path"] = path_of(item["folder_path"])
            item["tags"] = tags.get(item["manifest_sha256"], [])
            found.append(item)
        return found

    def tokens(self, sha: str) -> List[Dict[str, Any]]:
        rows = self._all(
            "SELECT * FROM tokens WHERE manifest_sha256 = ? ORDER BY is_current, token_time, added_at", (sha,)
        )
        found = []
        for row in rows:
            item = dict(row)
            item["token_path"] = path_of(item["token_path"])
            item["is_current"] = bool(item["is_current"])
            found.append(item)
        return found

    def current_token(self, sha: str) -> Optional[Dict[str, Any]]:
        current = [token for token in self.tokens(sha) if token["is_current"]]
        return current[-1] if current else None

    def runs(self, sha: str, limit: int = MAX_LOG_LIMIT) -> List[Dict[str, Any]]:
        rows = self._all("SELECT * FROM runs WHERE manifest_sha256 = ? ORDER BY id DESC LIMIT ?", (sha, limit))
        found = []
        for row in rows:
            item = dict(row)
            item["folder_path"] = path_of(item["folder_path"])
            item["checks"] = [
                dict(check)
                for check in self._all(
                    "SELECT key, title, status FROM run_checks WHERE run_id = ? ORDER BY position", (row["id"],)
                )
            ]
            found.append(item)
        return found

    def events(self, sha: Optional[str] = None, limit: int = 20) -> List[Dict[str, Any]]:
        if sha is None:
            rows = self._all("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
        else:
            rows = self._all("SELECT * FROM events WHERE manifest_sha256 = ? ORDER BY id DESC LIMIT ?", (sha, limit))
        return [dict(row) for row in rows]

    def counts(self) -> Dict[str, int]:
        return {
            "seals": int(self._one("SELECT count(*) FROM seals")[0]),
            "tokens": int(self._one("SELECT count(*) FROM tokens")[0]),
            "runs": int(self._one("SELECT count(*) FROM runs")[0]),
            "objects": int(self._one("SELECT count(*) FROM objects")[0]),
        }

    # Changing what is recorded

    def tag(self, sha: str, tag: str) -> bool:
        tag = check_tag(tag)
        with self.transaction():
            cursor = self._run("INSERT OR IGNORE INTO tags (manifest_sha256, tag) VALUES (?, ?)", (sha, tag))
            if cursor.rowcount:
                self._event("tagged", sha, f"added the tag {tag}")
        return bool(cursor.rowcount)

    def untag(self, sha: str, tag: str) -> bool:
        tag = check_tag(tag)
        with self.transaction():
            cursor = self._run("DELETE FROM tags WHERE manifest_sha256 = ? AND tag = ?", (sha, tag))
            if cursor.rowcount:
                self._event("untagged", sha, f"removed the tag {tag}")
        return bool(cursor.rowcount)

    def _referenced(self) -> Set[str]:
        rows = self._all(
            "SELECT manifest_sha256 FROM seals UNION SELECT token_sha256 FROM tokens"
            " UNION SELECT request_sha256 FROM tokens WHERE request_sha256 IS NOT NULL"
            " UNION SELECT root_sha256 FROM tokens WHERE root_sha256 IS NOT NULL"
        )
        return {row[0] for row in rows}

    def forget(self, sha: str) -> int:
        """Removes a seal from the index and drops the copies nothing else uses. Returns how many were dropped."""
        with self.transaction():
            used = {sha}
            for row in self._all(
                "SELECT token_sha256, request_sha256, root_sha256 FROM tokens WHERE manifest_sha256 = ?", (sha,)
            ):
                used.update(value for value in row if value)
            self._run("DELETE FROM tokens WHERE manifest_sha256 = ?", (sha,))
            self._run("DELETE FROM runs WHERE manifest_sha256 = ?", (sha,))
            self._run("DELETE FROM tags WHERE manifest_sha256 = ?", (sha,))
            self._run("DELETE FROM events WHERE manifest_sha256 = ?", (sha,))
            self._run("DELETE FROM seals WHERE manifest_sha256 = ?", (sha,))
            dropped = sorted(used - self._referenced())
            for item in dropped:
                self._run("DELETE FROM objects WHERE sha256 = ?", (item,))
            self._event("forgotten", sha, "removed from the library; the seal's own files were not touched")
        # The files go in a second transaction, and only if nothing has started using them again since.
        with self.transaction():
            for item in dropped:
                if self._one("SELECT 1 FROM objects WHERE sha256 = ?", (item,)) is None:
                    self._remove_object_file(item)
        return len(dropped)

    def _remove_object_file(self, sha: str) -> None:
        path = self.object_path(sha)
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise LibraryError(f"the seal was forgotten, but its copy {path} could not be removed: {exc.strerror or exc}") from None
        try:
            path.parent.rmdir()
        except OSError:
            pass

    # Checking

    def check(self) -> List[str]:
        """Every problem found, in plain words. An empty list means the library is sound."""
        problems: List[str] = []
        for row in self._all("PRAGMA integrity_check(100)"):
            if row[0] != "ok":
                problems.append(f"SQLite integrity check: {row[0]}")
        for row in self._all("PRAGMA foreign_key_check"):
            problems.append(f"a row in {row[0]} refers to something missing from {row[2]}")
        objects = {row[0]: (row[1], row[2]) for row in self._all("SELECT sha256, kind, size FROM objects")}
        for sha, (kind, size) in sorted(objects.items()):
            if not _SHA.match(sha):
                problems.append(f"the object list has a bad name: {sha!r}")
                continue
            path = self.object_path(sha)
            if not path.is_file():
                problems.append(f"the {kind} copy {short_id(sha)} is missing: {path}")
            elif not self._object_is_sound(path, sha, size):
                problems.append(f"the {kind} copy {short_id(sha)} is damaged, its bytes no longer match its hash: {path}")
        referenced = self._referenced()
        for sha in sorted(referenced - set(objects)):
            problems.append(f"a seal or token refers to the copy {short_id(sha)}, which is not in the object list")
        for sha in sorted(set(objects) - referenced):
            problems.append(f"the {objects[sha][0]} copy {short_id(sha)} is not used by any seal (orphaned)")
        problems.extend(self._stray_files(set(objects)))
        return problems[:MAX_PROBLEMS]

    def _stray_files(self, known: Set[str]) -> List[str]:
        stray: List[str] = []
        if not self.objects_path.is_dir():
            return stray
        try:
            folders = sorted(os.scandir(self.objects_path), key=lambda entry: entry.name)
        except OSError as exc:
            return [f"cannot list {self.objects_path}: {exc.strerror or exc}"]
        for folder in folders:
            if not folder.is_dir(follow_symlinks=False) or not re.fullmatch(r"[0-9a-f]{2}", folder.name):
                stray.append(f"a file the library did not make is in its copies folder: {folder.path}")
                continue
            try:
                entries = sorted(os.scandir(folder.path), key=lambda entry: entry.name)
            except OSError as exc:
                stray.append(f"cannot list {folder.path}: {exc.strerror or exc}")
                continue
            for entry in entries:
                if entry.name in known and entry.name.startswith(folder.name) and entry.is_file(follow_symlinks=False):
                    continue
                if _SHA.match(entry.name) and entry.name.startswith(folder.name):
                    stray.append(f"the copy {entry.path} is not in the object list (left by an interrupted run)")
                elif entry.name.endswith(".tmp"):
                    stray.append(f"a partly written copy was left by an interrupted run: {entry.path}")
                else:
                    stray.append(f"a file the library did not make is in its copies folder: {entry.path}")
                if len(stray) >= MAX_PROBLEMS:
                    return stray
        return stray


# Recording from the commands ----------------------------------------------------------------------


def record_quietly(
    no_library: bool, action: Callable[..., Any], *arguments: Any, notify: Callable[[str], None] = warn
) -> bool:
    """Records into the library if wanted. A problem becomes one warning line and changes nothing else.

    Returns whether the run was recorded."""
    if not recording_wanted(no_library):
        return False
    try:
        action(*arguments)
    except Exception as exc:
        reason = str(exc) if isinstance(exc, EvidenceSealError) else f"{type(exc).__name__}: {exc}"
        notify(f"warning: the seal library did not record this run: {reason}. Nothing else was affected.")
        return False
    return True


def read_token_files(token_path: Path, query_path: Optional[Path] = None) -> Tuple[bytes, Optional[bytes], Optional[bytes]]:
    """A token and the request and root copy saved beside it, each only if present and readable."""
    token = read_bounded(token_path, TOKEN)
    request = _optional_file(query_path or token_path.with_suffix(sealing.QUERY_SUFFIX), REQUEST)
    root = _optional_file(token_path.with_suffix(sealing.ROOT_SUFFIX), ROOT)
    return token, request, root


def is_replaced_copy(path: Path) -> bool:
    """A token kept by ``stamp --force`` when it made a new one."""
    return sealing.KEPT_MARK in Path(path).name


def record_seal(manifest_path: Path, folder: Path) -> None:
    data = read_bounded(Path(manifest_path), MANIFEST)
    parsed = manifest.parse(data)
    with open_library() as library, library.transaction():
        library.add_seal(
            data, manifest_path, Path(folder).resolve(), "sealed", f"sealed {count_of(len(parsed.entries), 'file')}"
        )


def record_stamp(manifest_path: Path, result: stamping.StampResult) -> None:
    """Records a new token from ``stamping.stamp_manifest``, and marks the token it replaced, if any."""
    data = read_bounded(Path(manifest_path), MANIFEST)
    token, request, root = read_token_files(Path(result.token_path), Path(result.query_path))
    with open_library() as library, library.transaction():
        sha, _ = library.add_seal(data, manifest_path, None, "imported", "added by stamp")
        kept = {Path(path).suffix: Path(path) for path in result.kept}
        old = kept.get(sealing.TOKEN_SUFFIX)
        if old is not None:
            old_token = read_bounded(old, TOKEN)
            old_request = _optional_file(kept.get(sealing.QUERY_SUFFIX), REQUEST)
            old_root = _optional_file(old.with_suffix(sealing.ROOT_SUFFIX), ROOT)
            try:
                library.add_token(sha, data, old_token, old, old_request, old_root, current=False)
            except TokenNotUsable:
                pass
        library.add_token(sha, data, token, result.token_path, request, root, current=True, event="stamped")


def record_verification(
    command: str,
    outcome: Verification,
    manifest_path: Path,
    token_path: Optional[Path] = None,
    query_path: Optional[Path] = None,
) -> None:
    """Records a verify or report run, adding the seal and its token if the library did not know them."""
    manifest_path = Path(manifest_path)
    data = read_bounded(manifest_path, MANIFEST)
    if hashlib.sha256(data).hexdigest() != outcome.manifest_sha256:
        raise LibraryError(f"{manifest_path} changed while it was being checked, so the run was not recorded")
    folder = Path(outcome.folder) if outcome.folder else None
    token_path = Path(token_path) if token_path else verification.existing_token(manifest_path)
    with open_library() as library, library.transaction():
        sha, _ = library.add_seal(data, manifest_path, folder, "imported", f"added by {command}")
        token_sha = None
        if token_path is not None and outcome.facts is not None and token_path.is_file():
            token, request, root = read_token_files(token_path, query_path)
            if _serial_of(token) == outcome.facts.serial:
                token_sha = hashlib.sha256(token).hexdigest()
                try:
                    library.add_token(sha, data, token, token_path, request, root, not is_replaced_copy(token_path))
                except TokenNotUsable:
                    pass
        library.add_run(sha, token_sha, command, outcome)


def _serial_of(token: bytes) -> Optional[str]:
    """The serial a token states, or None when it cannot be read, to tell it is the token just checked."""
    try:
        return showing.describe(token).get("serial")
    except (DerError, TokenFormatError):
        return None
