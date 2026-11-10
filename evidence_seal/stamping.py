"""The stamp command: the only code in this package that touches the network.

It sends only the hash of the manifest, a random nonce and a request for the
authority's certificates. The manifest itself and the files never leave the
machine. A response is checked before anything is saved, so a bad answer cannot
leave a token on disk that looks like proof.
"""

from __future__ import annotations

import http.client
import secrets
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

from . import __version__, hashes, manifest, sealing, tokencheck, tsp
from .errors import ManifestError, StampError, UsageError
from .results import Check, Status, TokenFacts
from .trust import DEFAULT_TSA_URL, TrustStore

USER_AGENT = f"evidence-seal/{__version__}"
DEFAULT_TIMEOUT = 60
DEFAULT_RETRIES = 2
_RETRY_DELAYS = (2.0, 5.0, 10.0)
_LONGEST_WAIT = 120.0
_TRY_AGAIN_STATUS = {429, 500, 502, 503, 504}
NOTHING_SAVED = "Nothing was saved, and your manifest is unchanged."
_BLOCKING_KEYS = (
    tokencheck.STATUS,
    tokencheck.STRUCTURE,
    tokencheck.HASH,
    tokencheck.QUERY,
    tokencheck.SIGNATURE,
    tokencheck.CHAIN,
    tokencheck.NAME,
    tokencheck.TIME,
)


@dataclass
class StampResult:
    token_path: Path
    query_path: Path
    root_path: Optional[Path]
    facts: Optional[TokenFacts]
    checks: List[Check] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    kept: List[Path] = field(default_factory=list)


class TemporaryFailure(StampError):
    """A failure that the same request might not meet a little later."""

    def __init__(self, message: str, wait: Optional[float] = None):
        super().__init__(message)
        self.wait = wait


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """A redirected POST would quietly become a GET, or go somewhere the user did not choose."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open_url(request: urllib.request.Request, timeout: float):
    return urllib.request.build_opener(_NoRedirects()).open(request, timeout=timeout)


def check_url(url: str) -> None:
    """Refuses an authority address that is not a plain http or https URL."""
    try:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname
    except ValueError:
        raise UsageError(f"the authority URL {url!r} cannot be read") from None
    if parts.scheme.lower() not in ("http", "https"):
        raise UsageError(f"the authority URL must start with http:// or https://, not {url!r}")
    if not host or any(char.isspace() or ord(char) < 0x20 for char in url):
        raise UsageError(f"the authority URL {url!r} cannot be read")


def _seconds_to_wait(value: Optional[str]) -> Optional[float]:
    """Reads a Retry-After header in its seconds form. The date form is treated as not given."""
    if value is None or not value.strip().isascii() or not value.strip().isdigit():
        return None
    return float(value.strip()[:9])


def _http_failure(exc: urllib.error.HTTPError) -> StampError:
    code = exc.code
    if 300 <= code < 400:
        target = exc.headers.get("Location") if exc.headers else None
        where = f" to {target}" if target else ""
        return StampError(
            f"the authority redirected this request{where} (HTTP {code}), and stamp does not follow redirects."
            f" If you trust that address, pass it with --tsa-url. {NOTHING_SAVED}"
        )
    wait = _seconds_to_wait(exc.headers.get("Retry-After")) if exc.headers else None
    if code == 429:
        asked = f" It asked for a wait of {wait:g} seconds." if wait is not None else ""
        return TemporaryFailure(f"the authority is limiting requests (HTTP 429).{asked} {NOTHING_SAVED}", wait)
    if code in _TRY_AGAIN_STATUS:
        return TemporaryFailure(
            f"the authority answered with HTTP {code} {exc.reason}, so it is having trouble."
            f" {NOTHING_SAVED} Try again later, or choose another authority with --tsa-url.",
            wait,
        )
    return StampError(f"the authority answered with HTTP {code} {exc.reason}. {NOTHING_SAVED}")


def _connection_failure(url: str, exc: BaseException) -> StampError:
    reason = getattr(exc, "reason", exc)
    if isinstance(reason, ssl.SSLCertVerificationError):
        return StampError(
            f"could not verify the secure connection to {url}: {reason.verify_message or reason}."
            f" Check this computer's date and root certificates. {NOTHING_SAVED}"
        )
    if isinstance(reason, (socket.timeout, TimeoutError)):
        return TemporaryFailure(f"{url} did not answer in time. {NOTHING_SAVED}")
    return TemporaryFailure(f"could not reach {url}: {reason}. Check the network connection. {NOTHING_SAVED}")


def _one_request(url: str, body: bytes, timeout: float) -> bytes:
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/timestamp-query", "User-Agent": USER_AGENT},
    )
    try:
        with _open_url(request, timeout) as answer:
            data = answer.read(tsp.MAX_TOKEN_BYTES + 1)
            headers = getattr(answer, "headers", None)
    except urllib.error.HTTPError as exc:
        failure = _http_failure(exc)
        if exc.fp is not None:
            exc.close()
        raise failure from None
    except (urllib.error.URLError, OSError) as exc:
        raise _connection_failure(url, exc) from None
    except http.client.HTTPException as exc:
        raise TemporaryFailure(f"{url} sent a broken answer: {exc}. {NOTHING_SAVED}") from None
    if not data:
        raise TemporaryFailure(f"the authority sent an empty answer. {NOTHING_SAVED}")
    if len(data) > tsp.MAX_TOKEN_BYTES:
        raise StampError(f"the authority's answer is larger than any real token. {NOTHING_SAVED}")
    kind = headers.get("Content-Type", "") if headers is not None else ""
    if kind.lower().startswith("text/html"):
        raise StampError(f"the authority sent a web page instead of a timestamp. {NOTHING_SAVED}")
    return data


def post_request(url: str, body: bytes, timeout: float) -> bytes:
    """POSTs one timestamp request and returns the raw response body, within ``timeout`` seconds in all."""
    check_url(url)
    outcome: List[object] = []

    def work() -> None:
        try:
            outcome.append(_one_request(url, body, timeout))
        except BaseException as exc:  # Carried back to the waiting thread, which raises it
            outcome.append(exc)

    worker = threading.Thread(target=work, daemon=True)
    worker.start()
    deadline = time.monotonic() + timeout
    while worker.is_alive() and time.monotonic() < deadline:
        worker.join(0.1)
    if not outcome:
        raise TemporaryFailure(f"{url} did not finish answering within {timeout:g} seconds. {NOTHING_SAVED}")
    if isinstance(outcome[0], BaseException):
        raise outcome[0]
    return outcome[0]  # type: ignore[return-value]


def request_with_retries(
    url: str,
    body: bytes,
    timeout: float,
    retries: int = DEFAULT_RETRIES,
    notify: Optional[Callable[[str], None]] = None,
) -> bytes:
    """Asks again after a failure that may pass, and never faster than the delays above."""
    for attempt in range(retries + 1):
        try:
            return post_request(url, body, timeout)
        except TemporaryFailure as exc:
            if attempt == retries:
                raise
            delay = _RETRY_DELAYS[min(attempt, len(_RETRY_DELAYS) - 1)]
            if exc.wait is not None:
                if exc.wait > _LONGEST_WAIT:
                    raise
                delay = max(delay, exc.wait)
            if notify is not None:
                notify(f"{exc} Asking again in {delay:g} seconds ({attempt + 1} of {retries}).")
            time.sleep(delay)
    raise AssertionError("the loop above always returns or raises")


def _same_path(first: Path, second: Path) -> bool:
    return sealing.path_key(first) == sealing.path_key(second)


def stamp_manifest(
    manifest_path: Path,
    tsa_url: str = DEFAULT_TSA_URL,
    hash_name: str = "sha256",
    out: Optional[Path] = None,
    policy: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    force: bool = False,
    store: Optional[TrustStore] = None,
    retries: int = DEFAULT_RETRIES,
    notify: Optional[Callable[[str], None]] = None,
) -> StampResult:
    manifest_path = Path(manifest_path)
    algorithm = hashes.by_name(hash_name)
    if algorithm is None or algorithm.weak:
        raise UsageError(f"--hash must be a strong hash such as sha256, sha384 or sha512, not {hash_name!r}")
    if manifest_path.is_dir():
        raise UsageError(f"{manifest_path} is a folder. Give stamp the manifest file that seal wrote")
    manifest_bytes = manifest.read_limited(manifest_path, "manifest")
    parsed = manifest.parse(manifest_bytes)
    if parsed.kind == manifest.NATIVE and parsed.problems:
        raise UsageError(
            f"{manifest_path} is damaged, so it was not sent for a timestamp: {parsed.problems[0]}."
            " Seal the folder again to get a good manifest"
        )
    token_path = Path(out) if out else sealing.token_path_for(manifest_path)
    query_path = token_path.with_suffix(sealing.QUERY_SUFFIX)
    root_path = token_path.with_suffix(sealing.ROOT_SUFFIX)
    if any(_same_path(manifest_path, path) for path in (token_path, query_path, root_path)):
        raise UsageError(f"the token and its companions would overwrite {manifest_path}. Choose another name with --out")
    if _same_path(token_path, query_path):
        raise UsageError(f"--out cannot end in {sealing.QUERY_SUFFIX}, because that name is used for the request")
    if token_path.is_dir():
        raise UsageError(f"{token_path} is a folder. Give --out a file name")
    if token_path.exists() and not force:
        raise StampError(f"{token_path} already exists; use --force to replace it, or choose another name with --out")
    sealing.check_can_write(token_path)
    if policy is not None:
        problem = policy_problem(policy)
        if problem is not None:
            raise UsageError(f"--policy {problem}")

    nonce = secrets.randbits(63) | (1 << 62)
    request = tsp.build_request(algorithm, algorithm.digest(manifest_bytes), nonce=nonce, cert_req=True, policy=policy)
    answer = request_with_retries(tsa_url, request, timeout, retries, notify)

    report = tokencheck.check_token(answer, manifest_bytes, store or TrustStore(), query_bytes=request)
    for check in report.checks:
        if check.key in _BLOCKING_KEYS and check.status is Status.FAIL:
            raise StampError(f"the authority's answer was not saved. {check.title}: {check.detail}")
        if check.key == tokencheck.SIGNATURE and check.status is Status.NOT_CHECKED:
            report.notes.append(f"The signature on the new token was not checked: {check.detail}")
    if parsed.kind == manifest.HAND_MADE and not parsed.entries:
        report.notes.append("This file lists no hashes this tool can read, so the token covers its text and no files.")

    kept: List[Path] = []
    if force:
        _keep_copy(token_path, answer, kept)
    sealing.write_new_file(token_path, answer, force=force)
    root_cert = None
    if report.response is not None and report.response.signed_data is not None:
        roots = [cert for cert in report.response.signed_data.certificates if cert.self_issued]
        root_cert = roots[0] if roots else None
    saved_root = None
    try:
        _keep_copy(query_path, request, kept)
        sealing.write_new_file(query_path, request, force=True)
        if root_cert is not None:
            pem = root_cert.to_pem().encode("ascii")
            _keep_copy(root_path, pem, kept)
            sealing.write_new_file(root_path, pem, force=True)
            saved_root = root_path
    except ManifestError as exc:
        report.notes.append(f"The token was saved, but a companion file was not: {exc}")
    return StampResult(token_path, query_path, saved_root, report.facts, report.checks, report.notes, kept)


def _keep_copy(path: Path, new_bytes: bytes, kept: List[Path]) -> None:
    """Keeps what is about to be replaced. An earlier token shows an earlier date and cannot be issued again."""
    copy = sealing.keep_copy_of(path, new_bytes)
    if copy is not None:
        kept.append(copy)


def policy_problem(policy: str) -> Optional[str]:
    """Why this is not a policy object identifier, or None when it is one."""
    parts = policy.split(".")
    if len(parts) < 2 or not all(part.isascii() and part.isdigit() for part in parts):
        return f"must be an object identifier such as 1.2.3.4, not {policy!r}"
    if int(parts[0]) > 2 or (int(parts[0]) < 2 and int(parts[1]) >= 40):
        return f"must be a valid object identifier, and {policy!r} is not"
    return None
