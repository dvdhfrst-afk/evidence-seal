"""Certificate path building and validation for a timestamp signer.

The rules follow what ``openssl ts -verify`` applies with the timestamp-signing
purpose, with one deliberate difference: validity dates are checked at the time
in the token, not at the time of the check. A certificate that expired after it
issued a token does not make that token false, and the difference is reported.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Sequence

from . import oids, signatures
from .errors import DerError
from .signatures import Unsupported
from .trust import TrustStore
from .x509 import KU_DIGITAL_SIGNATURE, KU_KEY_CERT_SIGN, KU_NON_REPUDIATION, Certificate

MAX_PATH = 8
MAX_SIGNATURE_CHECKS = 64

OK = "ok"
FAILED = "failed"
UNANCHORED = "unanchored"
UNSUPPORTED = "unsupported"
WEAK = "weak"

_UNDERSTOOD_CRITICAL = {
    oids.EXT_BASIC_CONSTRAINTS,
    oids.EXT_KEY_USAGE,
    oids.EXT_EXTENDED_KEY_USAGE,
    oids.EXT_SUBJECT_KEY_ID,
    oids.EXT_AUTHORITY_KEY_ID,
    oids.EXT_SUBJECT_ALT_NAME,
    oids.EXT_CERT_POLICIES,
}
_NEEDS_OPENSSL = {oids.EXT_NAME_CONSTRAINTS, oids.EXT_POLICY_CONSTRAINTS, oids.EXT_INHIBIT_ANY_POLICY}


@dataclass
class ChainResult:
    kind: str
    detail: str
    path: List[Certificate] = field(default_factory=list)
    anchor_label: Optional[str] = None
    methods: List[str] = field(default_factory=list)


def _common_problems(cert: Certificate, at_time: datetime) -> Optional[str]:
    name = cert.subject.display()
    if at_time < cert.not_before:
        return f"certificate {name} was not yet valid at the token's time (valid from {cert.not_before:%Y-%m-%d})"
    if at_time > cert.not_after:
        return f"certificate {name} had already expired at the token's time (expired {cert.not_after:%Y-%m-%d})"
    for extension in cert.extensions.values():
        if extension.oid in _NEEDS_OPENSSL:
            raise Unsupported(f"certificate extension {extension.oid} on {name}")
        if extension.critical and extension.oid not in _UNDERSTOOD_CRITICAL:
            return f"certificate {name} has a critical extension this tool does not understand ({extension.oid})"
    return None


def signer_purpose_problem(cert: Certificate) -> Optional[str]:
    """RFC 3161 section 2.3: the extended key usage must be critical and only timeStamping."""
    name = cert.subject.display()
    usage = cert.extended_key_usage()
    if usage is None:
        return f"certificate {name} is not marked for timestamping (no extended key usage)"
    if usage != [oids.KP_TIME_STAMPING]:
        return f"certificate {name} must have timestamping as its only extended key usage"
    if not cert.extensions[oids.EXT_EXTENDED_KEY_USAGE].critical:
        return f"certificate {name} must mark its extended key usage as critical"
    key_usage = cert.key_usage()
    if key_usage is not None and not key_usage <= {KU_DIGITAL_SIGNATURE, KU_NON_REPUDIATION}:
        return f"certificate {name} has key usages that do not fit a timestamp signer"
    return None


def _issuer_problem(cert: Certificate, below: int) -> Optional[str]:
    name = cert.subject.display()
    if cert.version < 3:
        # Only old style roots may lack extensions.
        return None if cert.self_issued else f"certificate {name} is version {cert.version} and cannot act as an issuer"
    is_ca, path_length = cert.basic_constraints()
    if not is_ca:
        return f"certificate {name} issued another certificate but is not a certificate authority"
    if path_length is not None and below > path_length:
        return f"certificate {name} allows {path_length} intermediate certificates below it, but has {below}"
    key_usage = cert.key_usage()
    if key_usage is not None and KU_KEY_CERT_SIGN not in key_usage:
        return f"certificate {name} is not allowed to sign certificates"
    return None


class _Search:
    def __init__(self, pool: Sequence[Certificate], store: TrustStore, at_time: datetime):
        self.pool = pool
        self.store = store
        self.at_time = at_time
        self.failures: List[str] = []
        self.unanchored: List[str] = []
        self.unsupported: List[str] = []
        self.checks_left = MAX_SIGNATURE_CHECKS

    def walk(self, path: List[Certificate], methods: List[str], weak: Optional[str]) -> Optional[ChainResult]:
        current = path[-1]
        try:
            problem = _common_problems(current, self.at_time)
        except Unsupported as exc:
            self.unsupported.append(str(exc))
            return None
        if problem:
            self.failures.append(problem)
            return None
        if len(path) > 1:
            problem = _issuer_problem(current, len(path) - 2)
            if problem:
                self.failures.append(problem)
                return None
        if current.self_issued:
            label = self.store.anchor_label(current)
            if label is not None:
                return self._finish(path, methods, weak, label)
        issuers = [
            cert
            for cert in self.pool
            if cert.subject.matches(current.issuer) and all(cert.raw != seen.raw for seen in path)
        ]
        if not issuers or len(path) >= MAX_PATH:
            if current.self_issued:
                self.unanchored.append(f"the chain ends at {current.subject.display()}, which is not a trusted root")
            else:
                self.unanchored.append(f"the issuer of {current.subject.display()} is not available")
            return None
        for issuer in issuers:
            if self.checks_left <= 0:
                # Many certificates with the same name could otherwise make this search take days.
                self.unsupported.append("the certificates in this token take too many attempts to sort out")
                return None
            self.checks_left -= 1
            try:
                outcome = signatures.verify(
                    issuer.public_key, current.signature_algorithm, current.tbs_raw, current.signature
                )
            except Unsupported as exc:
                self.unsupported.append(f"{exc} on {current.subject.display()}")
                continue
            except DerError as exc:
                self.failures.append(f"certificate {current.subject.display()} is malformed: {exc}")
                continue
            if not outcome.valid:
                self.failures.append(
                    f"the signature on {current.subject.display()} does not verify against"
                    f" {issuer.subject.display()}"
                )
                continue
            found = self.walk(path + [issuer], methods + [outcome.method], weak or outcome.weak)
            if found is not None:
                return found
        return None

    def _finish(self, path, methods, weak, label) -> ChainResult:
        names = " -> ".join(cert.subject.common_name() or cert.subject.display() for cert in path)
        if weak:
            return ChainResult(WEAK, f"chain {names}: {weak}", list(path), label, list(methods))
        return ChainResult(OK, f"chain {names}", list(path), label, list(methods))


def validate(
    signer: Certificate,
    pool: Sequence[Certificate],
    store: TrustStore,
    at_time: datetime,
) -> ChainResult:
    """Finds a valid path from the signer to a trusted root, at the token's time."""
    try:
        purpose = signer_purpose_problem(signer)
    except DerError as exc:
        return ChainResult(FAILED, f"certificate {signer.subject.display()} is malformed: {exc}")
    if purpose:
        return ChainResult(FAILED, purpose)
    candidates = list(pool) + [cert for cert in store.anchor_certificates if all(cert.raw != c.raw for c in pool)]
    search = _Search(candidates, store, at_time)
    try:
        found = search.walk([signer], [], None)
    except DerError as exc:
        return ChainResult(FAILED, f"a certificate in the chain is malformed: {exc}")
    if found is not None:
        return found
    if search.failures:
        return ChainResult(FAILED, search.failures[0])
    if search.unsupported:
        return ChainResult(UNSUPPORTED, search.unsupported[0])
    reason = search.unanchored[0] if search.unanchored else "no path to a trusted root was found"
    if store.explicit:
        return ChainResult(FAILED, f"{reason}; it does not reach {store.named_roots}")
    return ChainResult(UNANCHORED, reason)
