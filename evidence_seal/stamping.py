"""The stamp command: the only code in this package that touches the network.

It sends only the hash of the manifest, a random nonce and a request for the
authority's certificates. The manifest itself and the files never leave the
machine. A response is checked before anything is saved, so a bad answer cannot
leave a token on disk that looks like proof.
"""

from __future__ import annotations

import secrets
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from . import __version__, hashes, sealing, tokencheck, tsp
from .errors import StampError, UsageError
from .results import Check, Status, TokenFacts
from .trust import DEFAULT_TSA_URL, TrustStore

USER_AGENT = f"evidence-seal/{__version__}"
DEFAULT_TIMEOUT = 60
_BLOCKING_KEYS = (
    tokencheck.STATUS,
    tokencheck.STRUCTURE,
    tokencheck.HASH,
    tokencheck.QUERY,
    tokencheck.SIGNATURE,
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


def post_request(url: str, body: bytes, timeout: float) -> bytes:
    """POSTs a timestamp request and returns the raw response body."""
    if not url.lower().startswith(("http://", "https://")):
        raise UsageError(f"the authority URL must start with http:// or https://, not {url!r}")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/timestamp-query", "User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as answer:
            data = answer.read(tsp.MAX_TOKEN_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise StampError(f"the authority answered with HTTP {exc.code} {exc.reason}") from None
    except (urllib.error.URLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise StampError(f"could not reach {url}: {reason}") from None
    if not data:
        raise StampError("the authority sent an empty answer")
    return data


def stamp_manifest(
    manifest_path: Path,
    tsa_url: str = DEFAULT_TSA_URL,
    hash_name: str = "sha256",
    out: Optional[Path] = None,
    policy: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    force: bool = False,
    store: Optional[TrustStore] = None,
) -> StampResult:
    manifest_path = Path(manifest_path)
    algorithm = hashes.by_name(hash_name)
    if algorithm is None or algorithm.weak:
        raise UsageError(f"--hash must be a strong hash such as sha256, sha384 or sha512, not {hash_name!r}")
    try:
        manifest_bytes = manifest_path.read_bytes()
    except OSError as exc:
        raise UsageError(f"cannot read manifest {manifest_path}: {exc.strerror or exc}") from None
    token_path = Path(out) if out else sealing.token_path_for(manifest_path)
    query_path = token_path.with_suffix(sealing.QUERY_SUFFIX)
    if token_path.exists() and not force:
        raise StampError(f"{token_path} already exists; use --force to replace it, or choose another name with --out")

    nonce = secrets.randbits(63) | (1 << 62)
    request = tsp.build_request(algorithm, algorithm.digest(manifest_bytes), nonce=nonce, cert_req=True, policy=policy)
    answer = post_request(tsa_url, request, timeout)

    report = tokencheck.check_token(answer, manifest_bytes, store or TrustStore(), query_bytes=request)
    for check in report.checks:
        if check.key in _BLOCKING_KEYS and check.status is Status.FAIL:
            raise StampError(f"the authority's answer was not saved. {check.title}: {check.detail}")
        if check.key == tokencheck.SIGNATURE and check.status is Status.NOT_CHECKED:
            report.notes.append(f"The signature on the new token was not checked: {check.detail}")

    sealing.write_new_file(query_path, request, force=True)
    sealing.write_new_file(token_path, answer, force=force)
    root_path = None
    if report.response is not None and report.response.signed_data is not None:
        roots = [cert for cert in report.response.signed_data.certificates if cert.self_issued]
        if roots:
            root_path = token_path.with_suffix(sealing.ROOT_SUFFIX)
            sealing.write_new_file(root_path, roots[0].to_pem().encode("ascii"), force=True)
    return StampResult(token_path, query_path, root_path, report.facts, report.checks, report.notes)
