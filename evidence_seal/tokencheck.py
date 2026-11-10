"""Checks one timestamp token against manifest bytes and a set of trusted roots.

Each check stands alone and ends as pass, fail or not checked. "Not checked"
covers everything that could not be established, and it is never rolled up into
a pass. Hash match, signature and chain are separate results on purpose: a token
can be correctly signed and still say nothing about the manifest in hand.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from . import chain, cms, der, hashes, openssl_bridge, oids, signatures, tsp
from .errors import DerError, TokenFormatError
from .results import Check, Status, TokenFacts
from .signatures import Unsupported
from .trust import TrustStore
from .x509 import Certificate

STATUS = "status"
STRUCTURE = "structure"
HASH = "hash"
QUERY = "query"
SIGNATURE = "signature"
CHAIN = "chain"
NAME = "authority_name"
TIME = "time"
CROSS_CHECK = "openssl_cross_check"

TITLES = {
    STATUS: "Authority granted the timestamp",
    STRUCTURE: "Token is well formed",
    HASH: "Token covers this manifest",
    QUERY: "Token answers the saved request",
    SIGNATURE: "Signature is valid",
    CHAIN: "Certificate chain reaches a trusted root",
    NAME: "Authority name matches the signer",
    TIME: "Token time is plausible",
    CROSS_CHECK: "openssl ts -verify agrees",
}
FUTURE_MARGIN = timedelta(days=1)


@dataclass
class TokenReport:
    checks: List[Check]
    facts: Optional[TokenFacts]
    notes: List[str] = field(default_factory=list)
    response: Optional[tsp.TimeStampResponse] = None
    signer: Optional[Certificate] = None
    roots: List[Certificate] = field(default_factory=list)
    chain: List[Certificate] = field(default_factory=list)
    untrusted: List[Certificate] = field(default_factory=list)

    def status_of(self, key: str) -> Optional[Status]:
        for check in self.checks:
            if check.key == key:
                return check.status
        return None


def _check(key: str, status: Status, detail: str, method: Optional[str] = None) -> Check:
    return Check(key, TITLES[key], status, detail, method)


def format_time(moment: datetime) -> str:
    text = moment.strftime("%Y-%m-%d %H:%M:%S")
    if moment.microsecond:
        text += f".{moment.microsecond:06d}".rstrip("0")
    return text + " UTC"


def facts_of(response: tsp.TimeStampResponse) -> TokenFacts:
    facts = TokenFacts(status=response.status_text(), is_bare_token=response.is_bare_token)
    if response.signed_data is not None:
        facts.certificate_count = len(response.signed_data.certificates)
    info = response.tst_info
    if info is not None:
        algorithm = hashes.by_oid(info.hash_oid)
        facts.time = format_time(info.gen_time)
        facts.accuracy = info.accuracy_text()
        facts.policy = info.policy
        facts.hash_algorithm = algorithm.display if algorithm else info.hash_oid
        facts.hash_hex = info.digest.hex()
        facts.serial = f"{info.serial:x}"
        facts.nonce = f"{info.nonce:x}" if info.nonce is not None else None
        facts.ordering = info.ordering
        facts.authority = info.authority_text()
    return facts


def _not_checked_rest(checks: List[Check], reason: str, *keys: str) -> None:
    done = {check.key for check in checks}
    for key in keys:
        if key not in done:
            checks.append(_check(key, Status.NOT_CHECKED, reason))


HASH_MISMATCH_NOTE = (
    "A hash mismatch means this token does not cover these exact bytes. That is not by itself proof of tampering:"
    " a hand-made manifest may have hashed a different form of the text, for example other line endings or without"
    " a footer."
)

ALL_KEYS = (STATUS, STRUCTURE, HASH, SIGNATURE, CHAIN, NAME, TIME)


def check_token(
    token_bytes: bytes,
    manifest_bytes: Optional[bytes],
    store: TrustStore,
    untrusted: Sequence[Certificate] = (),
    query_bytes: Optional[bytes] = None,
    now: Optional[datetime] = None,
    cross_check: bool = False,
    manifest_path: Optional[Path] = None,
    token_path: Optional[Path] = None,
) -> TokenReport:
    """Runs every token check. Nothing here raises for a bad token: it reports."""
    now = now or datetime.now(timezone.utc)
    checks: List[Check] = []
    try:
        response = tsp.parse_response(token_bytes)
    except (DerError, TokenFormatError) as exc:
        checks.append(_check(STRUCTURE, Status.FAIL, f"the token could not be read: {exc}"))
        _not_checked_rest(checks, "the token could not be read", *ALL_KEYS)
        return TokenReport(checks, None)

    facts = facts_of(response)
    report = TokenReport(checks, facts, response=response)
    if response.status is None:
        checks.append(_check(STATUS, Status.PASS, "this is a bare token, which only exists for a granted request"))
    elif response.granted:
        checks.append(_check(STATUS, Status.PASS, response.status_text()))
    else:
        reason = response.status_text()
        if response.failure_text():
            reason += f" ({response.failure_text()})"
        checks.append(_check(STATUS, Status.FAIL, f"the authority's answer was: {reason}"))
    if response.tst_info is None or response.signed_data is None:
        checks.append(_check(STRUCTURE, Status.FAIL, "the response holds no timestamp token"))
        _not_checked_rest(checks, "the response holds no timestamp token", *ALL_KEYS)
        return report
    info = response.tst_info
    signed = response.signed_data

    structure_problem = None
    if info.version != 1:
        structure_problem = f"TSTInfo version is {info.version}, and RFC 3161 defines only version 1"
    elif len(signed.signers) != 1:
        structure_problem = f"the token has {len(signed.signers)} signers, and RFC 3161 requires exactly one"
    elif signed.signers[0].digest_algorithm.oid not in [item.oid for item in signed.digest_algorithms]:
        structure_problem = "the signer's digest algorithm is not in the token's list of digest algorithms"
    if structure_problem:
        checks.append(_check(STRUCTURE, Status.FAIL, structure_problem))
    else:
        checks.append(_check(STRUCTURE, Status.PASS, "response, signed data and TSTInfo all parsed"))

    hash_check = _hash_check(info, manifest_bytes)
    checks.append(hash_check)
    if hash_check.status is Status.FAIL:
        report.notes.append(HASH_MISMATCH_NOTE)
    if query_bytes is not None:
        checks.append(_query_check(info, query_bytes))
    if len(signed.signers) != 1:
        _not_checked_rest(checks, "the token does not have exactly one signer", SIGNATURE, CHAIN, NAME)
    else:
        pool = list(signed.certificates) + [cert for cert in untrusted if cert not in signed.certificates]
        report.untrusted = pool
        signer_info = signed.signers[0]
        signer = cms.find_signer_certificate(signer_info, pool)
        report.signer = signer
        if signer is None:
            reason = (
                "the signer's certificate is not in the token or the files given; "
                "pass the authority's certificate with --untrusted"
            )
            _not_checked_rest(checks, reason, SIGNATURE, CHAIN, NAME)
        else:
            facts.signer = signer.subject.display()
            facts.signer_sha256 = signer.sha256
            checks.append(_signature_check(signer_info, signer, info, pool, response.token_raw or b""))
            chain_check, notes, roots = _chain_check(signer, pool, store, info.gen_time, now, report)
            checks.append(chain_check)
            report.notes.extend(notes)
            report.roots = roots
            checks.append(_name_check(info, signer))
    checks.append(_time_check(info, now))
    if cross_check:
        checks.append(_cross_check(report, store, manifest_path, token_path, info.gen_time, response.is_bare_token))
    return report


def _hash_check(info: tsp.TstInfo, manifest_bytes: Optional[bytes]) -> Check:
    algorithm = hashes.by_oid(info.hash_oid)
    if algorithm is None:
        return _check(HASH, Status.NOT_CHECKED, f"the token uses a hash this tool does not know ({info.hash_oid})")
    if manifest_bytes is None:
        return _check(HASH, Status.NOT_CHECKED, "no manifest was given to compare with")
    actual = algorithm.digest(manifest_bytes)
    if actual != info.digest:
        return _check(
            HASH,
            Status.FAIL,
            f"the manifest's {algorithm.display} is {actual.hex()}, but the token covers {info.digest.hex()}",
        )
    if algorithm.weak:
        return _check(
            HASH,
            Status.NOT_CHECKED,
            f"the {algorithm.display} values match, but {algorithm.display} is no longer collision resistant,"
            " so the match cannot be relied on",
        )
    return _check(HASH, Status.PASS, f"{algorithm.display} of the manifest is {actual.hex()}, the same as in the token")


def _query_check(info: tsp.TstInfo, query_bytes: bytes) -> Check:
    try:
        request = tsp.parse_request(query_bytes)
    except (DerError, TokenFormatError) as exc:
        return _check(QUERY, Status.FAIL, f"the saved request could not be read: {exc}")
    if request.hash_oid != info.hash_oid or request.digest != info.digest:
        return _check(QUERY, Status.FAIL, "the saved request asked about a different hash than the token covers")
    if request.nonce != info.nonce:
        return _check(QUERY, Status.FAIL, "the nonce in the saved request does not match the token")
    if request.policy is not None and request.policy != info.policy:
        return _check(QUERY, Status.FAIL, "the policy in the saved request does not match the token")
    return _check(QUERY, Status.PASS, "hash and nonce match the saved request")


def _signature_check(
    signer_info: cms.SignerInfo,
    signer: Certificate,
    info: tsp.TstInfo,
    pool: Sequence[Certificate],
    token_der: bytes,
) -> Check:
    if signer_info.signed_attrs_raw is None:
        return _check(SIGNATURE, Status.FAIL, "the token has no signed attributes, which RFC 3161 tokens must have")
    digest_algorithm = hashes.by_oid(signer_info.digest_algorithm.oid)
    if digest_algorithm is None:
        return _openssl_signature(token_der, pool, f"digest algorithm {signer_info.digest_algorithm.oid}")
    try:
        content_type = signer_info.single_attribute(oids.ATTR_CONTENT_TYPE)
        message_digest = signer_info.single_attribute(oids.ATTR_MESSAGE_DIGEST)
        if content_type is None or der.oid_value(content_type) != oids.CT_TST_INFO:
            return _check(SIGNATURE, Status.FAIL, "the signed content-type attribute is missing or wrong")
        if message_digest is None:
            return _check(SIGNATURE, Status.FAIL, "the signed message-digest attribute is missing")
        if der.octets(message_digest) != digest_algorithm.digest(info.raw):
            return _check(
                SIGNATURE,
                Status.FAIL,
                "the timestamp content was changed: its hash does not match the signed attributes",
            )
        ok, explanation = cms.check_signing_cert_attribute(signer_info, signer)
    except (DerError, TokenFormatError) as exc:
        return _check(SIGNATURE, Status.FAIL, f"the signed attributes are malformed: {exc}")
    if not ok:
        return _check(SIGNATURE, Status.FAIL, explanation)
    try:
        outcome = signatures.verify(
            signer.public_key,
            signer_info.signature_algorithm,
            signer_info.signed_message(),
            signer_info.signature,
            digest_oid=signer_info.digest_algorithm.oid,
        )
    except Unsupported as exc:
        return _openssl_signature(token_der, pool, str(exc))
    except (DerError, TokenFormatError) as exc:
        return _check(SIGNATURE, Status.FAIL, f"the signature is malformed: {exc}")
    if not outcome.valid:
        detail = outcome.detail or "the signature does not verify against the signer's public key"
        return _check(SIGNATURE, Status.FAIL, detail, outcome.method)
    if outcome.weak:
        return _check(
            SIGNATURE,
            Status.NOT_CHECKED,
            f"the signature verifies, but {outcome.weak}, so it cannot be relied on",
            outcome.method,
        )
    return _check(
        SIGNATURE,
        Status.PASS,
        f"the signature verifies under the certificate of {signer.subject.common_name() or signer.subject.display()}",
        outcome.method,
    )


def _openssl_signature(token_der: bytes, pool: Sequence[Certificate], reason: str) -> Check:
    """Only reached when pure Python cannot do the arithmetic."""
    result = openssl_bridge.verify_signature_only(token_der, pool)
    if result.answer == openssl_bridge.YES:
        return _check(SIGNATURE, Status.PASS, f"openssl verified the signature ({reason} is not covered in pure Python)", result.command)
    if result.answer == openssl_bridge.NO:
        return _check(SIGNATURE, Status.FAIL, f"openssl rejected the signature: {_first_line(result.output)}", result.command)
    return _check(
        SIGNATURE,
        Status.NOT_CHECKED,
        f"pure Python does not cover {reason}, and openssl is not available to check it",
    )


def _first_line(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return "no message"


def _chain_check(
    signer: Certificate,
    pool: Sequence[Certificate],
    store: TrustStore,
    at_time: datetime,
    now: datetime,
    report: TokenReport,
) -> Tuple[Check, List[str], List[Certificate]]:
    notes: List[str] = []
    result = chain.validate(signer, pool, store, at_time)
    report.chain = list(result.path)
    roots: List[Certificate] = []
    for cert in list(pool) + store.anchor_certificates:
        if store.anchor_label(cert) is not None and cert not in roots:
            roots.append(cert)
    for cert in result.path:
        if now > cert.not_after:
            notes.append(
                f"Certificate {cert.subject.common_name() or cert.subject.display()} has expired since"
                f" ({cert.not_after:%Y-%m-%d}). It was checked at the token's time. openssl needs -attime to do the same."
            )
    method = result.methods[0] if result.methods else None
    if result.kind == chain.OK:
        detail = f"{result.detail}, trusted through {result.anchor_label}"
        return _check(CHAIN, Status.PASS, detail, method), notes, roots
    if result.kind == chain.WEAK:
        return (
            _check(CHAIN, Status.NOT_CHECKED, f"{result.detail}, so the chain cannot be relied on", method),
            notes,
            roots,
        )
    if result.kind == chain.FAILED:
        return _check(CHAIN, Status.FAIL, result.detail, method), notes, roots
    if result.kind == chain.UNANCHORED:
        detail = (
            f"{result.detail}. The token's own certificates prove nothing by themselves, because anyone can"
            " make such a chain. Pass the authority's root with --ca, or add it to your authority list, to check it."
        )
        return _check(CHAIN, Status.NOT_CHECKED, detail), notes, roots
    if not roots:
        return (
            _check(CHAIN, Status.NOT_CHECKED, f"pure Python does not cover {result.detail}, and no trusted root is known"),
            notes,
            roots,
        )
    bridged = openssl_bridge.verify_chain(signer, pool, roots, at_time)
    if bridged.answer == openssl_bridge.YES:
        return (
            _check(CHAIN, Status.PASS, f"openssl verified the chain ({result.detail} is not covered in pure Python)", bridged.command),
            notes,
            roots,
        )
    if bridged.answer == openssl_bridge.NO:
        return (
            _check(CHAIN, Status.FAIL, f"openssl rejected the chain: {_first_line(bridged.output)}", bridged.command),
            notes,
            roots,
        )
    return (
        _check(CHAIN, Status.NOT_CHECKED, f"pure Python does not cover {result.detail}, and openssl is not available"),
        notes,
        roots,
    )


def _name_check(info: tsp.TstInfo, signer: Certificate) -> Check:
    if info.tsa_name is None:
        if info.tsa_text is not None:
            return _check(NAME, Status.NOT_CHECKED, f"the token names the authority in a form this tool cannot compare: {info.tsa_text}")
        return _check(NAME, Status.PASS, f"the token states no separate name; the signer is {signer.subject.display()}")
    if info.tsa_name.matches(signer.subject):
        return _check(NAME, Status.PASS, f"{signer.subject.display()}")
    return _check(
        NAME,
        Status.FAIL,
        f"the token names {info.tsa_name.display()}, but it was signed by {signer.subject.display()}",
    )


def _time_check(info: tsp.TstInfo, now: datetime) -> Check:
    if info.gen_time > now + FUTURE_MARGIN:
        return _check(TIME, Status.FAIL, f"the token claims {format_time(info.gen_time)}, which is in the future. If this computer's clock is wrong, correct it and check again")
    return _check(TIME, Status.PASS, f"{format_time(info.gen_time)} is not in the future")


def _cross_check(
    report: TokenReport,
    store: TrustStore,
    manifest_path: Optional[Path],
    token_path: Optional[Path],
    at_time: datetime,
    token_in: bool,
) -> Check:
    if manifest_path is None or token_path is None:
        return _check(CROSS_CHECK, Status.NOT_CHECKED, "the manifest and token files were not both given")
    if not report.roots:
        return _check(CROSS_CHECK, Status.NOT_CHECKED, "no trusted root is known, so openssl has nothing to check against")
    result = openssl_bridge.ts_verify(manifest_path, token_path, report.roots, report.untrusted, at_time, token_in)
    if result.answer == openssl_bridge.UNAVAILABLE:
        return _check(CROSS_CHECK, Status.NOT_CHECKED, result.output or "openssl is not available")
    if result.answer == openssl_bridge.YES:
        return _check(CROSS_CHECK, Status.PASS, "openssl printed Verification: OK", result.command)
    return _check(CROSS_CHECK, Status.FAIL, f"openssl did not accept it: {_openssl_reason(result.output)}", result.command)


def _openssl_reason(output: str) -> str:
    for line in output.splitlines():
        lowered = line.lower()
        if "verify error" in lowered or "error:" in lowered or "failed" in lowered:
            return line.strip()
    return _first_line(output)
