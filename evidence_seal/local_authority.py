"""The local test authority: a timestamp authority on this computer, for trying the tool and for tests.

Its tokens prove nothing to anyone else, because whoever holds its key file can sign any time at
all. Every certificate it makes says TEST ONLY, and so does its key file. The root's key exists only
while init runs: it signs the timestamping certificate and is then thrown away, so no other signer
can ever be made under that root.

A folder made by init holds:

- ``authority.json``: its name, policy and creation date (format 1)
- ``root.crt``: the root certificate, which the authority list trusts as ``local-test``
- ``signer.crt``: the timestamping certificate, with a critical extended key usage of timeStamping
- ``TEST-ONLY-signer-key.pem``: the signer's private key, readable only by this user

Public API: REGISTERED_NAME, DEFAULT_PORT, default_folder(), default_url(), init(), load(),
LocalAuthority (answer, refusal), and the RFC 3161 failure codes.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from . import authorities, home, issuing, sealing, tsp
from .errors import CertificateFileError, DerError, TokenFormatError, UsageError
from .hashes import by_oid
from .issuing import EcPrivateKey
from .x509 import Certificate, certificates_from_bytes

FORMAT = 1
REGISTERED_NAME = "local-test"
DEFAULT_PORT = 3161
FOLDER_NAME = "test-authority"
CONFIG_FILE = "authority.json"
ROOT_FILE = "root.crt"
SIGNER_FILE = "signer.crt"
KEY_FILE = "TEST-ONLY-signer-key.pem"
ORGANIZATION = "evidence-seal local test authority"
MAX_DAYS = 36500
MAX_FILE_BYTES = 64 * 1024
_POLICY = re.compile(r"^2\.25\.[1-9][0-9]{0,39}$")
KEY_PREFACE = (
    "TEST ONLY. This is the private key of an evidence-seal local test authority.",
    "Anyone holding it can sign a timestamp with any date, so its tokens prove nothing to anyone else.",
    "Never use it, or tokens it signed, as evidence.",
)

# RFC 3161 PKIStatus rejection, and PKIFailureInfo bits
REJECTION = 2
BAD_ALG = 0
BAD_REQUEST = 2
BAD_DATA_FORMAT = 5
UNACCEPTED_POLICY = 15
UNACCEPTED_EXTENSION = 16
SYSTEM_FAILURE = 25
_STRONG = ("sha256", "sha384", "sha512")


def default_folder() -> Path:
    return home.home_dir() / FOLDER_NAME


def default_url(port: int = DEFAULT_PORT) -> str:
    return f"http://127.0.0.1:{port}/tsr"


def _files(folder: Path):
    return [folder / name for name in (CONFIG_FILE, ROOT_FILE, SIGNER_FILE, KEY_FILE)]


def _check_label(name: str) -> str:
    if not name.strip() or len(name) > 40 or not name.isprintable():
        raise UsageError("--name must be one line of at most 40 printable characters")
    return name.strip()


class LocalAuthority:
    """A loaded test authority, able to answer RFC 3161 requests. Holds no network code."""

    def __init__(self, folder: Path, name: str, policy: str, created: str, root: bytes, signer: bytes, key: EcPrivateKey):
        self.folder = folder
        self.name = name
        self.policy = policy
        self.created = created
        self.root_der = root
        self.signer_der = signer
        self.root = Certificate(root)
        self.signer = Certificate(signer)
        self.key = key

    @staticmethod
    def refusal(failure: int, text: str) -> bytes:
        return issuing.make_response(None, REJECTION, (text,), [failure])

    def answer(self, body: bytes, moment: Optional[datetime] = None) -> bytes:
        """A TimeStampResp for the request bytes. Anything wrong with the request is refused as RFC 3161 says."""
        try:
            request = tsp.parse_request(body)
        except (DerError, TokenFormatError, ValueError):
            return self.refusal(BAD_DATA_FORMAT, "the request could not be read as an RFC 3161 timestamp request")
        if request.version != 1:
            return self.refusal(BAD_REQUEST, "only version 1 requests are understood")
        algorithm = by_oid(request.hash_oid)
        if algorithm is None or algorithm.name not in _STRONG:
            return self.refusal(BAD_ALG, "the hash must be SHA-256, SHA-384 or SHA-512")
        if len(request.digest) != algorithm.size:
            return self.refusal(BAD_DATA_FORMAT, f"the hash is not {algorithm.size} bytes long")
        if request.policy is not None and request.policy != self.policy:
            return self.refusal(UNACCEPTED_POLICY, f"this authority issues only under policy {self.policy}")
        if request.extensions:
            return self.refusal(UNACCEPTED_EXTENSION, "this authority accepts no request extensions")
        when = (moment or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
        content = issuing.make_tst_info(
            request.digest,
            request.hash_oid,
            self.policy,
            secrets.randbits(63) | 1,
            when,
            request.nonce,
            self.signer.subject.raw,
        )
        certificates = (self.signer_der, self.root_der) if request.cert_req else ()
        return issuing.make_response(issuing.sign_token(content, self.key, self.signer_der, certificates), 0)


@dataclass
class InitResult:
    authority: LocalAuthority
    entry: Optional[authorities.Entry]
    replaced: bool


def init(
    folder: Optional[Path] = None,
    name: str = "local",
    days: int = 365,
    force: bool = False,
    register: bool = True,
    now: Optional[datetime] = None,
) -> InitResult:
    """Makes a fresh root and timestamping certificate, and by default lists the root as local-test."""
    folder = Path(folder) if folder is not None else default_folder()
    name = _check_label(name)
    if not 1 <= days <= MAX_DAYS:
        raise UsageError(f"--days must be from 1 to {MAX_DAYS}")
    if folder.exists() and not folder.is_dir():
        raise UsageError(f"{folder} is a file. Give a folder for the test authority")
    existing = [path for path in _files(folder) if os.path.lexists(path)]
    if existing and not force:
        raise UsageError(
            f"{folder} already holds a test authority. Use --force to replace it, after which tokens from the"
            " old one no longer verify against it. Nothing was changed"
        )
    if register:
        authorities.check_test_registration(REGISTERED_NAME, replace=force)
    if folder == default_folder():
        home.ensure_home()
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    not_before, not_after = now - timedelta(hours=1), now + timedelta(days=days)
    root_key, signer_key = EcPrivateKey.generate(), EcPrivateKey.generate()
    unique = uuid.uuid4()
    policy = f"2.25.{unique.int}"
    # Each authority's names differ, so the roots of two test authorities are never mistaken for each other.
    root_name = issuing.make_name(f"TEST ONLY {name} root {unique.hex[:8]}", ORGANIZATION)
    signer_name = issuing.make_name(f"TEST ONLY {name} timestamping {unique.hex[:8]}", ORGANIZATION)
    root = issuing.make_certificate(
        root_name, root_key, root_name, root_key, secrets.randbits(63) | 1, not_before, not_after, issuing.CA_EXTENSIONS
    )
    signer = issuing.make_certificate(
        signer_name, signer_key, root_name, root_key, secrets.randbits(63) | 1, not_before, not_after, issuing.TSA_EXTENSIONS
    )
    del root_key
    config = {"format": FORMAT, "name": name, "policy": policy, "created": now.strftime("%Y-%m-%dT%H:%M:%SZ")}
    sealing.write_new_file(folder / KEY_FILE, signer_key.to_pem(KEY_PREFACE), force=True, mode=0o600)
    sealing.write_new_file(folder / ROOT_FILE, Certificate(root).to_pem().encode("ascii"), force=True)
    sealing.write_new_file(folder / SIGNER_FILE, Certificate(signer).to_pem().encode("ascii"), force=True)
    sealing.write_new_file(folder / CONFIG_FILE, (json.dumps(config, indent=2) + "\n").encode("ascii"), force=True)
    authority = LocalAuthority(folder, name, policy, config["created"], root, signer, signer_key)
    entry = None
    if register:
        entry = authorities.register_test_authority(REGISTERED_NAME, default_url(), authority.root, policy, replace=force)
    return InitResult(authority, entry, bool(existing))


def _read(path: Path, folder: Path) -> bytes:
    try:
        with open(path, "rb") as handle:
            if os.fstat(handle.fileno()).st_size > MAX_FILE_BYTES:
                raise UsageError(f"{path} is too large to belong to a test authority")
            return handle.read()
    except FileNotFoundError:
        raise UsageError(
            f"{folder} holds no complete test authority ({path.name} is missing). Make one with: test-authority init"
        ) from None
    except OSError as exc:
        raise UsageError(f"cannot read {path}: {exc.strerror or exc}") from None


def _one_certificate(path: Path, folder: Path) -> bytes:
    try:
        found = certificates_from_bytes(_read(path, folder), str(path))
    except CertificateFileError as exc:
        raise UsageError(str(exc)) from None
    if len(found) != 1:
        raise UsageError(f"{path} must hold exactly one certificate")
    return found[0].raw


def load(folder: Optional[Path] = None) -> LocalAuthority:
    """Reads a folder made by init, checking that its parts belong together."""
    folder = Path(folder) if folder is not None else default_folder()
    if not folder.is_dir():
        raise UsageError(f"{folder} holds no test authority. Make one with: test-authority init")
    damaged = UsageError(f"{folder / CONFIG_FILE} is damaged. Make a new test authority with: test-authority init --force")
    try:
        config = json.loads(_read(folder / CONFIG_FILE, folder).decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise damaged from None
    if not isinstance(config, dict) or not isinstance(config.get("format"), int):
        raise damaged
    if config["format"] > FORMAT:
        raise UsageError(f"{folder} was made by a newer version of evidence-seal. Use that version to serve it")
    name, policy, created = config.get("name"), config.get("policy"), config.get("created")
    if not all(isinstance(value, str) for value in (name, policy, created)) or not _POLICY.match(policy):
        raise damaged
    root = _one_certificate(folder / ROOT_FILE, folder)
    signer = _one_certificate(folder / SIGNER_FILE, folder)
    key = EcPrivateKey.from_pem(_read(folder / KEY_FILE, folder), str(folder / KEY_FILE))
    authority = LocalAuthority(folder, _check_label(name), policy, created, root, signer, key)
    if authority.signer.spki_raw != key.spki() or not authority.signer.issuer.matches(authority.root.subject):
        raise UsageError(f"the files in {folder} do not belong together. Make a new one with: test-authority init --force")
    return authority
