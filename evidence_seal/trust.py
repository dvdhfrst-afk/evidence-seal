"""Which roots count as trusted, and what is known about public authorities.

A token carries its own certificates, so a forger can include any chain they
like. A chain only means something when it ends at a root the verifier chose
independently of the token. There are two sources for that root, and nothing
else counts: a certificate file passed on the command line, or a root whose
SHA-256 fingerprint is written into this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .x509 import Certificate, load_certificates

DEFAULT_TSA_URL = "https://freetsa.org/tsr"


@dataclass(frozen=True)
class Authority:
    name: str
    tsa_url: str
    terms_url: str
    root_url: str
    root_sha256: str


KNOWN_AUTHORITIES: Tuple[Authority, ...] = (
    Authority(
        name="FreeTSA",
        tsa_url=DEFAULT_TSA_URL,
        terms_url="https://freetsa.org/freetsa.html",
        root_url="https://freetsa.org/files/cacert.pem",
        root_sha256="a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc",
    ),
)


def authority_for_root(fingerprint: str) -> Optional[Authority]:
    for authority in KNOWN_AUTHORITIES:
        if authority.root_sha256 == fingerprint:
            return authority
    return None


class TrustStore:
    """The verifier's roots: explicit certificates, or the built-in fingerprints."""

    def __init__(self, certificates: Sequence[Certificate] = (), sources: Sequence[str] = ()):
        self.certificates: List[Certificate] = list(certificates)
        self.sources: List[str] = list(sources)
        self._labels: Dict[str, str] = {}
        for cert, source in zip(self.certificates, self.sources):
            self._labels[cert.sha256] = source

    @classmethod
    def from_files(cls, paths: Sequence[Path]) -> "TrustStore":
        certificates: List[Certificate] = []
        sources: List[str] = []
        for path in paths:
            for cert in load_certificates(path):
                certificates.append(cert)
                sources.append(Path(path).name)
        return cls(certificates, sources)

    @property
    def explicit(self) -> bool:
        """True when the caller named its own roots. The built-in fingerprints are then ignored."""
        return bool(self.certificates)

    def anchor_label(self, cert: Certificate) -> Optional[str]:
        """How this certificate came to be trusted, or None when it is not trusted."""
        fingerprint = cert.sha256
        if self.explicit:
            source = self._labels.get(fingerprint)
            return f"certificate file {source}" if source else None
        authority = authority_for_root(fingerprint)
        if authority is not None:
            return f"built-in fingerprint for the {authority.name} root"
        return None
