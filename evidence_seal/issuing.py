"""Building keys, certificates and RFC 3161 answers, for the local test authority.

This is the issuing side of what the rest of the package checks: an elliptic curve key, ECDSA
signatures, X.509 certificates with the extensions a timestamp authority needs, TSTInfo, CMS
SignedData and the TimeStampResp wrapper. Everything is pure Python.

The arithmetic is not written to resist timing measurements, so a key made here is fit only for a
test authority whose tokens prove nothing to anyone else. That is the only use it gets.

Public API: EcPrivateKey (generate, sign, to_pem, from_pem), make_name, extension, basic_constraints,
key_usage, extended_key_usage, TSA_EXTENSIONS, CA_EXTENSIONS, make_certificate, make_tst_info,
attribute, token_attributes, make_signer_info, make_signed_data, sign_token, make_response and
named_bits.
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
from datetime import datetime
from typing import Iterable, List, Optional, Sequence

from . import der, ecdsa, hashes, oids
from .errors import DerError, UsageError
from .der import (
    encode_bits,
    encode_bool,
    encode_context,
    encode_int,
    encode_null,
    encode_octets,
    encode_oid,
    encode_seq,
    encode_set,
    encode_time,
    encode_utc_time,
    encode_utf8,
)
from .x509 import Certificate

ECDSA_BY_HASH = {
    "sha1": oids.ECDSA_SHA1,
    "sha256": oids.ECDSA_SHA256,
    "sha384": oids.ECDSA_SHA384,
    "sha512": oids.ECDSA_SHA512,
}
PRIVATE_KEY_LABEL = "EC PRIVATE KEY"
_KEY_BLOCK = re.compile(rb"-----BEGIN EC PRIVATE KEY-----(.+?)-----END EC PRIVATE KEY-----", re.DOTALL)


class EcPrivateKey:
    """An elliptic curve private key with its public point."""

    def __init__(self, d: int, curve: ecdsa.Curve = ecdsa.P256, curve_oid: str = oids.CURVE_P256):
        if not 1 <= d < curve.n:
            raise ValueError("the private value is out of range for the curve")
        self.curve = curve
        self.curve_oid = curve_oid
        self.d = d
        self.point = ecdsa.scalar_multiply(curve, d, curve.generator)

    @classmethod
    def generate(cls, curve: ecdsa.Curve = ecdsa.P256, curve_oid: str = oids.CURVE_P256) -> "EcPrivateKey":
        """A fresh key from the operating system's secure random source."""
        return cls(secrets.randbelow(curve.n - 1) + 1, curve, curve_oid)

    def public_bytes(self) -> bytes:
        size = self.curve.size
        return b"\x04" + self.point[0].to_bytes(size, "big") + self.point[1].to_bytes(size, "big")

    def spki(self) -> bytes:
        algorithm = encode_seq(encode_oid(oids.EC_PUBLIC_KEY), encode_oid(self.curve_oid))
        return encode_seq(algorithm, encode_bits(self.public_bytes()))

    def algorithm(self, hash_name: str) -> bytes:
        return encode_seq(encode_oid(ECDSA_BY_HASH[hash_name]))

    def _nonce(self) -> int:
        return secrets.randbelow(self.curve.n - 1) + 1

    def sign(self, message: bytes, hash_name: str = "sha256") -> bytes:
        """An ECDSA signature over the hash of ``message``, as the DER sequence of r and s."""
        digest = hashlib.new(hash_name, message).digest()
        n = self.curve.n
        e = int.from_bytes(digest, "big")
        excess = len(digest) * 8 - n.bit_length()
        if excess > 0:
            e >>= excess
        while True:
            k = self._nonce()
            point = ecdsa.scalar_multiply(self.curve, k, self.curve.generator)
            r = point[0] % n
            s = pow(k, n - 2, n) * (e + r * self.d) % n
            if r and s:
                return encode_seq(encode_int(r), encode_int(s))

    def to_der(self) -> bytes:
        """The RFC 5915 form, which openssl also reads."""
        return encode_seq(
            encode_int(1),
            encode_octets(self.d.to_bytes(self.curve.size, "big")),
            encode_context(0, encode_oid(self.curve_oid)),
            encode_context(1, encode_bits(self.public_bytes())),
        )

    def to_pem(self, preface: Sequence[str] = ()) -> bytes:
        """PEM text, with lines of explanation before the block. PEM readers skip such lines."""
        body = base64.b64encode(self.to_der()).decode("ascii")
        lines = list(preface) + [f"-----BEGIN {PRIVATE_KEY_LABEL}-----"]
        lines += [body[i:i + 64] for i in range(0, len(body), 64)]
        lines.append(f"-----END {PRIVATE_KEY_LABEL}-----")
        return ("\n".join(lines) + "\n").encode("ascii")

    @classmethod
    def from_pem(cls, data: bytes, label: str) -> "EcPrivateKey":
        """Reads a P-256 key written by ``to_pem``, and checks its public point."""
        found = _KEY_BLOCK.findall(data)
        if len(found) != 1:
            raise UsageError(f"{label} does not hold exactly one EC private key")
        try:
            raw = base64.b64decode(b"".join(found[0].split()), validate=True)
            cursor = der.Cursor(der.parse(raw), "private key")
            if der.int_value(cursor.universal(der.INTEGER, "version")) != 1:
                raise DerError("unknown private key version")
            secret = der.octets(cursor.universal(der.OCTET_STRING, "private value"))
            curve_node = cursor.optional_context(0)
            public_node = cursor.optional_context(1)
            cursor.finish()
            if curve_node is None or len(curve_node.children) != 1:
                raise DerError("the curve is not named")
            if der.oid_value(curve_node.children[0]) != oids.CURVE_P256 or len(secret) != ecdsa.P256.size:
                raise DerError("only P-256 keys are used here")
            key = cls(int.from_bytes(secret, "big"))
            if public_node is not None:
                if len(public_node.children) != 1 or der.bit_octets(public_node.children[0]) != key.public_bytes():
                    raise DerError("the public point does not belong to the private value")
        except (DerError, ValueError) as exc:
            raise UsageError(f"{label} is not a usable private key: {exc}") from None
        return key


def make_name(common_name: str, organization: Optional[str] = None) -> bytes:
    """A distinguished name with an optional organization and a common name, in UTF-8."""
    parts = []
    if organization is not None:
        parts.append(encode_set([encode_seq(encode_oid("2.5.4.10"), encode_utf8(organization))]))
    parts.append(encode_set([encode_seq(encode_oid("2.5.4.3"), encode_utf8(common_name))]))
    return encode_seq(*parts)


def extension(oid: str, critical: bool, value: bytes) -> bytes:
    parts = [encode_oid(oid)]
    if critical:
        parts.append(encode_bool(True))
    parts.append(encode_octets(value))
    return encode_seq(*parts)


def named_bits(bits: Iterable[int]) -> bytes:
    """A DER named-bit BIT STRING, with bit 0 the most significant and no trailing zero bits."""
    chosen = set(bits)
    if not chosen:
        return der.encode_tlv(der.BIT_STRING, b"\x00")
    highest = max(chosen)
    value = bytearray(highest // 8 + 1)
    for bit in chosen:
        value[bit // 8] |= 0x80 >> (bit % 8)
    return der.encode_tlv(der.BIT_STRING, bytes([7 - highest % 8]) + bytes(value))


def basic_constraints(ca: bool, path_length: Optional[int] = None, critical: bool = True) -> bytes:
    body = []
    if ca:
        body.append(encode_bool(True))
    if path_length is not None:
        body.append(encode_int(path_length))
    return extension(oids.EXT_BASIC_CONSTRAINTS, critical, encode_seq(*body))


def key_usage(bits: Sequence[int], critical: bool = True) -> bytes:
    return extension(oids.EXT_KEY_USAGE, critical, named_bits(bits))


def extended_key_usage(usages: Sequence[str] = (oids.KP_TIME_STAMPING,), critical: bool = True) -> bytes:
    return extension(oids.EXT_EXTENDED_KEY_USAGE, critical, encode_seq(*[encode_oid(item) for item in usages]))


# RFC 3161 section 2.3: a signer's extended key usage is critical and only timeStamping.
TSA_EXTENSIONS = (basic_constraints(False), key_usage([0]), extended_key_usage())
CA_EXTENSIONS = (basic_constraints(True), key_usage([5, 6]))


def validity_time(moment: datetime) -> bytes:
    """RFC 5280: UTCTime through 2049, GeneralizedTime after."""
    return encode_utc_time(moment) if moment.year < 2050 else encode_time(moment)


def make_certificate(
    subject_name: bytes,
    subject_key,
    issuer_name: bytes,
    issuer_key,
    serial: int,
    not_before: datetime,
    not_after: datetime,
    extensions: Sequence[bytes] = TSA_EXTENSIONS,
    sign_hash: str = "sha256",
) -> bytes:
    """A version 3 certificate. Keys need spki(), algorithm(hash_name) and sign(message, hash_name)."""
    algorithm = issuer_key.algorithm(sign_hash)
    parts = [
        encode_context(0, encode_int(2)),
        encode_int(serial),
        algorithm,
        issuer_name,
        encode_seq(validity_time(not_before), validity_time(not_after)),
        subject_name,
        subject_key.spki(),
    ]
    if extensions:
        parts.append(encode_context(3, encode_seq(*extensions)))
    tbs = encode_seq(*parts)
    return encode_seq(tbs, algorithm, encode_bits(issuer_key.sign(tbs, sign_hash)))


def make_tst_info(
    data_hash: bytes,
    hash_oid: str,
    policy: str,
    serial: int,
    moment: datetime,
    nonce: Optional[int] = None,
    tsa_name: Optional[bytes] = None,
    version: int = 1,
) -> bytes:
    """TSTInfo, the content an authority signs. ``tsa_name`` is the DER of a distinguished name."""
    imprint = encode_seq(encode_seq(encode_oid(hash_oid), encode_null()), encode_octets(data_hash))
    parts = [encode_int(version), encode_oid(policy), imprint, encode_int(serial), encode_time(moment)]
    if nonce is not None:
        parts.append(encode_int(nonce))
    if tsa_name is not None:
        parts.append(encode_context(0, encode_context(4, tsa_name)))
    return encode_seq(*parts)


def attribute(oid: str, *values: bytes) -> bytes:
    return encode_seq(encode_oid(oid), encode_set(values))


def token_attributes(content: bytes, signer_cert: bytes, digest_name: str = "sha256") -> List[bytes]:
    """The signed attributes RFC 3161 needs: content type, message digest and the signing certificate."""
    ess = encode_seq(encode_seq(encode_seq(encode_octets(hashlib.sha256(signer_cert).digest()))))
    return [
        attribute(oids.ATTR_CONTENT_TYPE, encode_oid(oids.CT_TST_INFO)),
        attribute(oids.ATTR_MESSAGE_DIGEST, encode_octets(hashlib.new(digest_name, content).digest())),
        attribute(oids.ATTR_SIGNING_CERTIFICATE_V2, ess),
    ]


def digest_algorithm(digest_name: str) -> bytes:
    return encode_seq(encode_oid(hashes.by_name(digest_name).oid), encode_null())


def make_signer_info(
    issuer_name: bytes,
    serial: int,
    digest_name: str,
    signed_attributes: Optional[bytes],
    signature_algorithm: bytes,
    signature: bytes,
) -> bytes:
    """A SignerInfo. ``signed_attributes`` is the DER SET that was signed, or None for none."""
    parts = [encode_int(1), encode_seq(issuer_name, encode_int(serial)), digest_algorithm(digest_name)]
    if signed_attributes is not None:
        parts.append(der.encode_tlv(0xA0, der.parse(signed_attributes).content))
    parts.extend([signature_algorithm, encode_octets(signature)])
    return encode_seq(*parts)


def make_signed_data(
    content: bytes, signer_infos: Sequence[bytes], certificates: Sequence[bytes], digest_name: str = "sha256"
) -> bytes:
    """A ContentInfo holding SignedData over a TSTInfo."""
    body = [
        encode_int(3),
        encode_set([digest_algorithm(digest_name)]),
        encode_seq(encode_oid(oids.CT_TST_INFO), encode_context(0, encode_octets(content))),
    ]
    if certificates:
        body.append(encode_context(0, b"".join(certificates)))
    body.append(der.encode_tlv(0x31, b"".join(signer_infos)))
    return encode_seq(encode_oid(oids.CMS_SIGNED_DATA), encode_context(0, encode_seq(*body)))


def sign_token(
    content: bytes, key, signer_cert: bytes, certificates: Sequence[bytes] = (), digest_name: str = "sha256"
) -> bytes:
    """A complete timestamp token: ``content`` signed by ``key``, whose certificate is ``signer_cert``."""
    cert = Certificate(signer_cert)
    signed = encode_set(token_attributes(content, signer_cert, digest_name))
    signer = make_signer_info(
        cert.issuer.raw, cert.serial, digest_name, signed, key.algorithm(digest_name), key.sign(signed, digest_name)
    )
    return make_signed_data(content, [signer], certificates, digest_name)


def make_response(
    token: Optional[bytes] = None,
    status: int = 0,
    status_strings: Sequence[str] = (),
    failure_info: Optional[Iterable[int]] = None,
) -> bytes:
    """A TimeStampResp: the status, and the token when there is one."""
    status_parts = [encode_int(status)]
    if status_strings:
        status_parts.append(encode_seq(*[encode_utf8(text) for text in status_strings]))
    if failure_info is not None:
        status_parts.append(named_bits(failure_info))
    parts = [encode_seq(*status_parts)]
    if token is not None:
        parts.append(token)
    return encode_seq(*parts)
