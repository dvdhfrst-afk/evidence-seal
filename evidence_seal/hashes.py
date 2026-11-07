"""Hash algorithms by object identifier and by name."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, Optional

from . import oids
from .der import encode_null, encode_octets, encode_oid, encode_seq


@dataclass(frozen=True)
class HashAlgorithm:
    name: str
    display: str
    oid: str
    size: int
    weak: bool = False

    def digest(self, data: bytes) -> bytes:
        return hashlib.new(self.name, data).digest()

    def new(self):
        return hashlib.new(self.name)

    def digest_info(self, digest: bytes) -> bytes:
        """The structure PKCS#1 v1.5 pads and signs."""
        return encode_seq(encode_seq(encode_oid(self.oid), encode_null()), encode_octets(digest))


_ALL = (
    HashAlgorithm("md5", "MD5", oids.MD5, 16, weak=True),
    HashAlgorithm("sha1", "SHA-1", oids.SHA1, 20, weak=True),
    HashAlgorithm("sha224", "SHA-224", oids.SHA224, 28),
    HashAlgorithm("sha256", "SHA-256", oids.SHA256, 32),
    HashAlgorithm("sha384", "SHA-384", oids.SHA384, 48),
    HashAlgorithm("sha512", "SHA-512", oids.SHA512, 64),
    HashAlgorithm("sha3_256", "SHA3-256", oids.SHA3_256, 32),
    HashAlgorithm("sha3_384", "SHA3-384", oids.SHA3_384, 48),
    HashAlgorithm("sha3_512", "SHA3-512", oids.SHA3_512, 64),
)
_BY_OID: Dict[str, HashAlgorithm] = {item.oid: item for item in _ALL}
_BY_NAME: Dict[str, HashAlgorithm] = {item.name: item for item in _ALL}

SHA256 = _BY_NAME["sha256"]


def by_oid(oid: str) -> Optional[HashAlgorithm]:
    return _BY_OID.get(oid)


def by_name(name: str) -> Optional[HashAlgorithm]:
    return _BY_NAME.get(name.lower().replace("-", ""))


def by_hex_length(length: int) -> Optional[HashAlgorithm]:
    """The hash a hand-made manifest most likely used, judged by its hex length."""
    lengths = {32: "md5", 40: "sha1", 56: "sha224", 64: "sha256", 96: "sha384", 128: "sha512"}
    name = lengths.get(length)
    return _BY_NAME[name] if name else None
