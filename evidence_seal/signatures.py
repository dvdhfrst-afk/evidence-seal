"""Public keys and signature checks, shared by certificates and timestamp tokens.

A check has three possible endings. It returns an outcome saying the signature
is valid or invalid, or it raises ``Unsupported`` when pure Python here does not
cover the algorithm, in which case the caller may hand the job to openssl.
Unsupported must never be read as a pass or as a failure.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from . import der, ecdsa, hashes, oids, rsa
from .errors import DerError
from .hashes import HashAlgorithm

MIN_RSA_BITS = 2048
MAX_RSA_BITS = 16384
MAX_RSA_EXPONENT_BITS = 256


class Unsupported(Exception):
    """An algorithm or key type that pure Python here does not implement."""


@dataclass(frozen=True)
class AlgorithmId:
    """An AlgorithmIdentifier: an OID and the raw bytes of its parameters, if any."""

    oid: str
    params: Optional[bytes] = None

    @classmethod
    def parse(cls, node: der.Node) -> "AlgorithmId":
        cursor = der.Cursor(node, "algorithm identifier")
        oid = der.oid_value(cursor.universal(der.OID, "algorithm"))
        following = cursor.peek()
        if following is not None:
            cursor.next("parameters")
        cursor.finish()
        return cls(oid, following.raw if following is not None else None)

    def has_no_real_params(self) -> bool:
        return self.params is None or self.params == b"\x05\x00"


@dataclass(frozen=True)
class RsaKey:
    n: int
    e: int

    @property
    def bits(self) -> int:
        return self.n.bit_length()

    def describe(self) -> str:
        return f"RSA {self.bits} bit"


@dataclass(frozen=True)
class EcKey:
    curve: ecdsa.Curve
    point: Tuple[int, int]

    @property
    def bits(self) -> int:
        return self.curve.n.bit_length()

    def describe(self) -> str:
        return f"ECDSA {self.curve.name}"


@dataclass(frozen=True)
class OtherKey:
    """A key this module cannot use. Parsed anyway so a token can still be described."""

    oid: str
    detail: str = ""

    def describe(self) -> str:
        return f"unsupported key type ({self.detail or self.oid})"


@dataclass(frozen=True)
class Outcome:
    valid: bool
    method: str
    weak: Optional[str] = None
    detail: str = ""


def parse_public_key(spki: bytes):
    """Reads a SubjectPublicKeyInfo. Keys of unknown type come back as ``OtherKey``."""
    cursor = der.Cursor(der.parse(spki), "public key info")
    algorithm = AlgorithmId.parse(cursor.universal(der.SEQUENCE, "algorithm"))
    bits = der.bit_octets(cursor.universal(der.BIT_STRING, "public key"))
    cursor.finish()
    if algorithm.oid in (oids.RSA_ENCRYPTION, oids.RSA_PSS):
        inner = der.Cursor(der.parse(bits), "RSA public key")
        n = der.int_value(inner.universal(der.INTEGER, "modulus"))
        e = der.int_value(inner.universal(der.INTEGER, "exponent"))
        inner.finish()
        if n <= 0 or e < 3 or not e & 1:
            raise DerError("RSA public key has impossible values")
        if n.bit_length() > MAX_RSA_BITS or e.bit_length() > MAX_RSA_EXPONENT_BITS:
            # A hostile certificate could otherwise tie up this tool for hours in one calculation.
            raise DerError(f"RSA public key is larger than this tool accepts ({n.bit_length()} bit)")
        return RsaKey(n, e)
    if algorithm.oid == oids.EC_PUBLIC_KEY:
        curve_oid = None
        if algorithm.params is not None:
            params = der.parse(algorithm.params)
            if params.is_universal(der.OID):
                curve_oid = der.oid_value(params)
        curve = ecdsa.CURVES.get(curve_oid) if curve_oid else None
        if curve is None:
            return OtherKey(algorithm.oid, f"elliptic curve {curve_oid or 'with explicit parameters'}")
        try:
            return EcKey(curve, ecdsa.decode_point(curve, bits))
        except ValueError as exc:
            raise DerError(str(exc)) from None
    return OtherKey(algorithm.oid)


_RSA_SIGNATURES = {
    oids.MD5_WITH_RSA: oids.MD5,
    oids.SHA1_WITH_RSA: oids.SHA1,
    oids.SHA224_WITH_RSA: oids.SHA224,
    oids.SHA256_WITH_RSA: oids.SHA256,
    oids.SHA384_WITH_RSA: oids.SHA384,
    oids.SHA512_WITH_RSA: oids.SHA512,
}
_ECDSA_SIGNATURES = {
    oids.ECDSA_SHA1: oids.SHA1,
    oids.ECDSA_SHA224: oids.SHA224,
    oids.ECDSA_SHA256: oids.SHA256,
    oids.ECDSA_SHA384: oids.SHA384,
    oids.ECDSA_SHA512: oids.SHA512,
}


def _hash_or_unsupported(oid: str) -> HashAlgorithm:
    algorithm = hashes.by_oid(oid)
    if algorithm is None:
        raise Unsupported(f"hash algorithm {oid}")
    return algorithm


def _resolve_hash(table_oid: Optional[str], digest_oid: Optional[str]) -> HashAlgorithm:
    if table_oid is not None and digest_oid is not None and table_oid != digest_oid:
        raise DerError("the signature algorithm and the digest algorithm disagree")
    chosen = table_oid or digest_oid
    if chosen is None:
        raise DerError("signature algorithm does not say which hash it used")
    return _hash_or_unsupported(chosen)


def _weakness(algorithm: HashAlgorithm, key) -> Optional[str]:
    if algorithm.weak:
        return f"{algorithm.display} is no longer collision resistant"
    if isinstance(key, RsaKey) and key.bits < MIN_RSA_BITS:
        return f"a {key.bits} bit RSA key is too short to rely on"
    return None


def _parse_pss_params(params: Optional[bytes]) -> Tuple[HashAlgorithm, HashAlgorithm, int]:
    hash_oid = oids.SHA1
    mgf_hash_oid = oids.SHA1
    salt = 20
    if params is not None:
        cursor = der.Cursor(der.parse(params), "PSS parameters")
        node = cursor.optional_context(0)
        if node is not None:
            hash_oid = AlgorithmId.parse(_only_child(node)).oid
        node = cursor.optional_context(1)
        if node is not None:
            mgf = AlgorithmId.parse(_only_child(node))
            if mgf.oid != oids.MGF1 or mgf.params is None:
                raise Unsupported("PSS with a mask function other than MGF1")
            mgf_hash_oid = AlgorithmId.parse(der.parse(mgf.params)).oid
        node = cursor.optional_context(2)
        if node is not None:
            salt = der.int_value(_only_child(node))
        node = cursor.optional_context(3)
        if node is not None and der.int_value(_only_child(node)) != 1:
            raise DerError("PSS trailer field must be 1")
        cursor.finish()
    if salt < 0:
        raise DerError("PSS salt length is negative")
    return _hash_or_unsupported(hash_oid), _hash_or_unsupported(mgf_hash_oid), salt


def _only_child(node: der.Node) -> der.Node:
    if len(node.children) != 1:
        raise DerError(f"expected one value inside {node.describe()}")
    return node.children[0]


def verify(key, algorithm: AlgorithmId, message: bytes, signature: bytes, digest_oid: Optional[str] = None) -> Outcome:
    """Checks ``signature`` over ``message``.

    ``digest_oid`` is the separate digest algorithm a CMS signer states. Certificates
    do not have one, because their signature algorithm names the hash itself.
    """
    if isinstance(key, OtherKey):
        raise Unsupported(key.describe())
    oid = algorithm.oid
    if oid != oids.RSA_PSS and not algorithm.has_no_real_params():
        if oid in _RSA_SIGNATURES or oid in _ECDSA_SIGNATURES or oid in (oids.RSA_ENCRYPTION, oids.EC_PUBLIC_KEY):
            raise DerError("this signature algorithm takes no parameters")
    if oid in _RSA_SIGNATURES or oid == oids.RSA_ENCRYPTION:
        if not isinstance(key, RsaKey):
            return Outcome(False, "pure Python", detail="the signature algorithm does not fit the key type")
        chosen = _resolve_hash(_RSA_SIGNATURES.get(oid), digest_oid)
        valid = rsa.verify_pkcs1_v15(key.n, key.e, chosen, chosen.digest(message), signature)
        method = f"pure Python RSA {key.bits} bit PKCS#1 v1.5 with {chosen.display}"
        return Outcome(valid, method, _weakness(chosen, key))
    if oid == oids.RSA_PSS:
        if not isinstance(key, RsaKey):
            return Outcome(False, "pure Python", detail="the signature algorithm does not fit the key type")
        chosen, mgf_hash, salt = _parse_pss_params(algorithm.params)
        if digest_oid is not None and digest_oid != chosen.oid:
            raise DerError("the signature algorithm and the digest algorithm disagree")
        valid = rsa.verify_pss(key.n, key.e, chosen, mgf_hash, salt, chosen.digest(message), signature)
        method = f"pure Python RSA {key.bits} bit PSS with {chosen.display}"
        return Outcome(valid, method, _weakness(chosen, key))
    if oid in _ECDSA_SIGNATURES or oid == oids.EC_PUBLIC_KEY:
        if not isinstance(key, EcKey):
            return Outcome(False, "pure Python", detail="the signature algorithm does not fit the key type")
        chosen = _resolve_hash(_ECDSA_SIGNATURES.get(oid), digest_oid)
        method = f"pure Python ECDSA {key.curve.name} with {chosen.display}"
        try:
            cursor = der.Cursor(der.parse(signature), "ECDSA signature")
            r = der.int_value(cursor.universal(der.INTEGER, "r"))
            s = der.int_value(cursor.universal(der.INTEGER, "s"))
            cursor.finish()
        except DerError as exc:
            return Outcome(False, method, detail=f"signature is malformed: {exc}")
        valid = ecdsa.verify(key.curve, key.point, chosen.digest(message), r, s)
        return Outcome(valid, method, _weakness(chosen, key))
    raise Unsupported(f"signature algorithm {oid}")
