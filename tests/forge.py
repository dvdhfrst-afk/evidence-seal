"""A small pure Python timestamp authority for tests, with no key files.

Keys are made fresh from fixed seeds, so nothing secret is stored and the tests
need no openssl. Its purpose is to build tokens that are validly signed but wrong
in some specific way, which is exactly what tampering with bytes cannot produce.
"""

import hashlib
import random
from datetime import datetime, timezone

from evidence_seal import der, ecdsa, hashes, oids
from evidence_seal.der import (
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

FAR_PAST = datetime(2001, 1, 1, tzinfo=timezone.utc)
FAR_FUTURE = datetime(2099, 1, 1, tzinfo=timezone.utc)
TOKEN_TIME = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
ECDSA_BY_HASH = {
    "sha1": oids.ECDSA_SHA1,
    "sha256": oids.ECDSA_SHA256,
    "sha384": oids.ECDSA_SHA384,
    "sha512": oids.ECDSA_SHA512,
}
_RNG = random.Random(20260301)


class EcKey:
    def __init__(self, seed, curve=ecdsa.P256, curve_oid=oids.CURVE_P256):
        rng = random.Random(seed)
        self.curve = curve
        self.curve_oid = curve_oid
        self.d = rng.randrange(1, curve.n)
        self.point = ecdsa.scalar_multiply(curve, self.d, curve.generator)

    def spki(self):
        size = self.curve.size
        encoded = b"\x04" + self.point[0].to_bytes(size, "big") + self.point[1].to_bytes(size, "big")
        return encode_seq(encode_seq(encode_oid(oids.EC_PUBLIC_KEY), encode_oid(self.curve_oid)), encode_bits(encoded))

    def algorithm(self, hash_name):
        return encode_seq(encode_oid(ECDSA_BY_HASH[hash_name]))

    def sign(self, message, hash_name="sha256"):
        digest = hashlib.new(hash_name, message).digest()
        n = self.curve.n
        e = int.from_bytes(digest, "big")
        excess = len(digest) * 8 - n.bit_length()
        if excess > 0:
            e >>= excess
        while True:
            k = _RNG.randrange(1, n)
            point = ecdsa.scalar_multiply(self.curve, k, self.curve.generator)
            r = point[0] % n
            s = pow(k, n - 2, n) * (e + r * self.d) % n
            if r and s:
                return encode_seq(encode_int(r), encode_int(s))


def _is_probable_prime(candidate, rng):
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if candidate % small == 0:
            return candidate == small
    d = candidate - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(12):
        a = rng.randrange(2, candidate - 1)
        x = pow(a, d, candidate)
        if x in (1, candidate - 1):
            continue
        for _ in range(r - 1):
            x = x * x % candidate
            if x == candidate - 1:
                break
        else:
            return False
    return True


def _prime(bits, rng):
    while True:
        candidate = rng.getrandbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if _is_probable_prime(candidate, rng):
            return candidate


class RsaKey:
    def __init__(self, seed, bits=1024):
        rng = random.Random(seed)
        self.e = 65537
        while True:
            p = _prime(bits // 2, rng)
            q = _prime(bits // 2, rng)
            phi = (p - 1) * (q - 1)
            if p != q and phi % self.e:
                break
        self.n = p * q
        self.d = pow(self.e, -1, phi)
        self.bits = self.n.bit_length()

    def spki(self):
        body = encode_seq(encode_int(self.n), encode_int(self.e))
        return encode_seq(encode_seq(encode_oid(oids.RSA_ENCRYPTION), encode_null()), encode_bits(body))

    def algorithm(self, hash_name):
        table = {
            "sha1": oids.SHA1_WITH_RSA,
            "sha256": oids.SHA256_WITH_RSA,
            "sha384": oids.SHA384_WITH_RSA,
            "sha512": oids.SHA512_WITH_RSA,
        }
        return encode_seq(encode_oid(table[hash_name]), encode_null())

    def raw_sign(self, block):
        return pow(int.from_bytes(block, "big"), self.d, self.n).to_bytes((self.n.bit_length() + 7) // 8, "big")

    def sign(self, message, hash_name="sha256"):
        algorithm = hashes.by_name(hash_name)
        info = algorithm.digest_info(algorithm.digest(message))
        size = (self.n.bit_length() + 7) // 8
        return self.raw_sign(b"\x00\x01" + b"\xff" * (size - len(info) - 3) + b"\x00" + info)


def name(common_name):
    attribute = encode_seq(encode_oid("2.5.4.3"), encode_utf8(common_name))
    org = encode_seq(encode_oid("2.5.4.10"), encode_utf8("evidence-seal tests"))
    return encode_seq(encode_set([org]), encode_set([attribute]))


def _extension(oid, critical, value):
    parts = [encode_oid(oid)]
    if critical:
        parts.append(encode_bool(True))
    parts.append(encode_octets(value))
    return encode_seq(*parts)


def basic_constraints(ca, path_length=None, critical=True):
    body = []
    if ca:
        body.append(encode_bool(True))
    if path_length is not None:
        body.append(encode_int(path_length))
    return _extension(oids.EXT_BASIC_CONSTRAINTS, critical, encode_seq(*body))


def key_usage(bits, critical=True):
    highest = max(bits)
    value = bytearray((highest // 8) + 1)
    for bit in bits:
        value[bit // 8] |= 0x80 >> (bit % 8)
    unused = 7 - highest % 8
    return _extension(oids.EXT_KEY_USAGE, critical, der.encode_tlv(der.BIT_STRING, bytes([unused]) + bytes(value)))


def extended_key_usage(usages=(oids.KP_TIME_STAMPING,), critical=True):
    return _extension(oids.EXT_EXTENDED_KEY_USAGE, critical, encode_seq(*[encode_oid(item) for item in usages]))


def unknown_critical_extension():
    return _extension("1.2.3.4.5.6.7", True, encode_null())


TSA_EXTENSIONS = (basic_constraints(False), key_usage([0]), extended_key_usage())
CA_EXTENSIONS = (basic_constraints(True), key_usage([5, 6]))


def _validity_time(moment):
    return encode_utc_time(moment) if moment.year < 2050 else encode_time(moment)


def make_certificate(
    subject,
    subject_key,
    issuer,
    issuer_key,
    serial=1000,
    not_before=FAR_PAST,
    not_after=FAR_FUTURE,
    extensions=TSA_EXTENSIONS,
    sign_hash="sha256",
):
    algorithm = issuer_key.algorithm(sign_hash)
    parts = [
        encode_context(0, encode_int(2)),
        encode_int(serial),
        algorithm,
        name(issuer),
        encode_seq(_validity_time(not_before), _validity_time(not_after)),
        name(subject),
        subject_key.spki(),
    ]
    if extensions:
        parts.append(encode_context(3, encode_seq(*extensions)))
    tbs = encode_seq(*parts)
    return encode_seq(tbs, algorithm, encode_bits(issuer_key.sign(tbs, sign_hash)))


class Authority:
    """A root and a timestamp signer, each with a fresh key from a seed."""

    def __init__(
        self, label="forged", seed=1, signer_extensions=TSA_EXTENSIONS, signer_key=None, root_key=None, **signer_options
    ):
        self.label = label
        self.root_key = root_key or EcKey(seed * 10 + 1)
        self.signer_key = signer_key or EcKey(seed * 10 + 2)
        self.root_name = f"TEST ONLY {label} root"
        self.signer_name = f"TEST ONLY {label} signer"
        self.root = make_certificate(
            self.root_name,
            self.root_key,
            self.root_name,
            self.root_key,
            serial=seed,
            extensions=CA_EXTENSIONS,
            sign_hash=signer_options.get("sign_hash", "sha256"),
        )
        self.signer = make_certificate(
            self.signer_name,
            self.signer_key,
            self.root_name,
            self.root_key,
            serial=seed + 100,
            extensions=signer_extensions,
            **signer_options,
        )

    def token(self, data, **options):
        options.setdefault("certificates", (self.signer, self.root))
        return make_response(data, self.signer_key, self.signer, self.signer_name, self.root_name, **options)


_mixed_authority = None


def mixed_authority():
    """A P-384 signer under an RSA root, the mix public authorities use. Built once, because RSA keys are slow."""
    global _mixed_authority
    if _mixed_authority is None:
        _mixed_authority = Authority(
            "mixed",
            seed=70,
            signer_key=EcKey(702, ecdsa.P384, oids.CURVE_P384),
            root_key=RsaKey(701, bits=2048),
            sign_hash="sha512",
        )
    return _mixed_authority


def make_tst_info(
    data_hash,
    hash_oid=oids.SHA256,
    policy="1.2.3.4.1",
    serial=4242,
    moment=TOKEN_TIME,
    nonce=None,
    tsa_name=None,
    version=1,
):
    imprint = encode_seq(encode_seq(encode_oid(hash_oid), encode_null()), encode_octets(data_hash))
    parts = [encode_int(version), encode_oid(policy), imprint, encode_int(serial), encode_time(moment)]
    if nonce is not None:
        parts.append(encode_int(nonce))
    if tsa_name is not None:
        parts.append(encode_context(0, encode_context(4, tsa_name)))
    return encode_seq(*parts)


def _attribute(oid, *values):
    return encode_seq(encode_oid(oid), encode_set(values))


def make_response(
    data,
    signer_key,
    signer_der,
    signer_name,
    issuer_name,
    certificates=(),
    data_hash=None,
    hash_oid=oids.SHA256,
    moment=TOKEN_TIME,
    nonce=None,
    tsa_name=None,
    version=1,
    digest_name="sha256",
    status=0,
    status_strings=(),
    failure_bits=None,
    wrap=True,
    omit_signed_attrs=False,
    omit_signing_cert=False,
    wrong_signing_cert=False,
    wrong_message_digest=False,
    wrong_content_type=False,
    second_signer=False,
    signer_serial=None,
    corrupt_signature=False,
    include_token=True,
):
    digest_algorithm = encode_seq(encode_oid(hashes.by_name(digest_name).oid), encode_null())
    if data_hash is None:
        data_hash = hashlib.sha256(data).digest()
    if tsa_name is None:
        tsa_name = name(signer_name)
    tst = make_tst_info(data_hash, hash_oid=hash_oid, moment=moment, nonce=nonce, tsa_name=tsa_name, version=version)
    tst_digest = hashlib.new(digest_name, tst).digest()
    if wrong_message_digest:
        tst_digest = bytes(len(tst_digest))
    content_type = oids.CMS_DATA if wrong_content_type else oids.CT_TST_INFO
    attributes = [
        _attribute(oids.ATTR_CONTENT_TYPE, encode_oid(content_type)),
        _attribute(oids.ATTR_MESSAGE_DIGEST, encode_octets(tst_digest)),
    ]
    if not omit_signing_cert:
        cert_hash = hashlib.sha256(b"not this certificate" if wrong_signing_cert else signer_der).digest()
        ess = encode_seq(encode_seq(encode_seq(encode_octets(cert_hash))))
        attributes.append(_attribute(oids.ATTR_SIGNING_CERTIFICATE_V2, ess))
    signed_set = encode_set(attributes)
    issuer_and_serial = encode_seq(name(issuer_name), encode_int(signer_serial or _serial_of(signer_der)))
    signer_parts = [encode_int(1), issuer_and_serial, digest_algorithm]
    if omit_signed_attrs:
        signature = signer_key.sign(tst, digest_name)
    else:
        signer_parts.append(der.encode_tlv(0xA0, der.parse(signed_set).content))
        signature = signer_key.sign(signed_set, digest_name)
    if corrupt_signature:
        signature = signer_key.sign(b"something else entirely", digest_name)
    signer_parts.extend([signer_key.algorithm(digest_name), encode_octets(signature)])
    signer_info = encode_seq(*signer_parts)
    signers = [signer_info, signer_info] if second_signer else [signer_info]
    signers_set = der.encode_tlv(0x31, b"".join(signers))
    body_parts = [
        encode_int(3),
        encode_set([digest_algorithm]),
        encode_seq(encode_oid(oids.CT_TST_INFO), encode_context(0, encode_octets(tst))),
    ]
    if certificates:
        body_parts.append(encode_context(0, b"".join(certificates)))
    body_parts.append(signers_set)
    token = encode_seq(encode_oid(oids.CMS_SIGNED_DATA), encode_context(0, encode_seq(*body_parts)))
    if not wrap:
        return token
    status_parts = [encode_int(status)]
    if status_strings:
        status_parts.append(encode_seq(*[encode_utf8(text) for text in status_strings]))
    if failure_bits is not None:
        status_parts.append(failure_bits)
    parts = [encode_seq(*status_parts)]
    if include_token:
        parts.append(token)
    return encode_seq(*parts)


def _serial_of(cert_der):
    node = der.parse(cert_der)
    tbs = node.children[0]
    return der.int_value(tbs.children[1])


def rejection(status=2, strings=("request refused",), failure=b"\x07\x04"):
    """A response with no token, as an authority sends for a refused request."""
    parts = [encode_int(status)]
    if strings:
        parts.append(encode_seq(*[encode_utf8(text) for text in strings]))
    if failure is not None:
        parts.append(der.encode_tlv(der.BIT_STRING, b"\x05\xa0"))
    return encode_seq(encode_seq(*parts))
