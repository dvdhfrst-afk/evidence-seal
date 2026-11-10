"""Which roots count as trusted, and what is known about public authorities.

A token carries its own certificates, so a forger can include any chain they
like. A chain only means something when it ends at a root the verifier chose
independently of the token. There are three sources for that root, and nothing
else counts: a certificate file passed on the command line, a root whose
SHA-256 fingerprint is written into this module, and a root the user added to
their authority list (see authorities.py), which reaches this module as a
ListedRoot.
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


@dataclass(frozen=True)
class ListedRoot:
    """A root trusted through an entry of the authority list. The certificate is None for a built-in."""

    sha256: str
    authority: str
    test: bool = False
    certificate: Optional[Certificate] = None
    builtin: bool = False

    @property
    def label(self) -> str:
        if self.builtin:
            return f"built-in fingerprint for the {self.authority} root"
        if self.test:
            return f"the root of {self.authority} in your authority list, a local test authority"
        return f"the root of {self.authority} in your authority list"


class TrustStore:
    """The verifier's roots: explicit certificates, or the built-in fingerprints and listed roots.

    ``only`` restricts the store to its listed roots, with the built-in fingerprints off. It names
    those roots for messages, as in "the roots listed for NAME".
    """

    def __init__(
        self,
        certificates: Sequence[Certificate] = (),
        sources: Sequence[str] = (),
        listed: Sequence[ListedRoot] = (),
        only: Optional[str] = None,
    ):
        self.certificates: List[Certificate] = list(certificates)
        self.sources: List[str] = list(sources)
        self.listed: List[ListedRoot] = list(listed)
        self.only = only
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
        """True when the caller named exactly which roots count. Every other root is then ignored."""
        return bool(self.certificates) or self.only is not None

    @property
    def named_roots(self) -> str:
        """The roots an explicit store holds, in words."""
        return self.only if self.only is not None else "the certificates you supplied"

    @property
    def anchor_certificates(self) -> List[Certificate]:
        """Trusted certificates the store holds itself, for building a chain a token does not carry."""
        if self.certificates:
            return list(self.certificates)
        return [root.certificate for root in self.listed if root.certificate is not None]

    def listed_root(self, cert: Certificate) -> Optional[ListedRoot]:
        if self.certificates:
            return None
        fingerprint = cert.sha256
        for root in self.listed:
            if root.sha256 == fingerprint:
                return root
        return None

    def anchor_label(self, cert: Certificate) -> Optional[str]:
        """How this certificate came to be trusted, or None when it is not trusted."""
        fingerprint = cert.sha256
        if self.certificates:
            source = self._labels.get(fingerprint)
            return f"certificate file {source}" if source else None
        root = self.listed_root(cert)
        if root is not None:
            return root.label
        if self.only is not None:
            return None
        authority = authority_for_root(fingerprint)
        if authority is not None:
            return f"built-in fingerprint for the {authority.name} root"
        return None
