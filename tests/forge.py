"""A small pure Python timestamp authority for tests, with no key files.

The building blocks are the package's own (evidence_seal.issuing). What lives here is only what tests
need on top: keys made from fixed seeds, so nothing secret is stored and runs repeat exactly, an RSA
key, and tokens that are validly signed but wrong in some specific way, which is exactly what
tampering with bytes cannot produce.
"""

import hashlib
import random
from datetime import datetime, timezone

from evidence_seal import der, ecdsa, hashes, issuing, oids
from evidence_seal.der import encode_bits, encode_int, encode_null, encode_octets, encode_oid, encode_seq, encode_set
# The tests use these through this module, alongside the test-only pieces below.
from evidence_seal.issuing import CA_EXTENSIONS, TSA_EXTENSIONS, basic_constraints, extended_key_usage, key_usage

FAR_PAST = datetime(2001, 1, 1, tzinfo=timezone.utc)
FAR_FUTURE = datetime(2099, 1, 1, tzinfo=timezone.utc)
TOKEN_TIME = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
_RNG = random.Random(20260301)


class EcKey(issuing.EcPrivateKey):
    """A key from a fixed seed, with signing nonces from a fixed sequence, so every run is the same."""

    def __init__(self, seed, curve=ecdsa.P256, curve_oid=oids.CURVE_P256):
        super().__init__(random.Random(seed).randrange(1, curve.n), curve, curve_oid)

    def _nonce(self):
        return _RNG.randrange(1, self.curve.n)


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
    return issuing.make_name(common_name, "evidence-seal tests")


def unknown_critical_extension():
    return issuing.extension("1.2.3.4.5.6.7", True, encode_null())


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
    return issuing.make_certificate(
        name(subject), subject_key, name(issuer), issuer_key, serial, not_before, not_after, extensions, sign_hash
    )


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
    return issuing.make_tst_info(data_hash, hash_oid, policy, serial, moment, nonce, tsa_name, version)


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
    wrap=True,
    omit_signed_attrs=False,
    omit_signing_cert=False,
    wrong_signing_cert=False,
    wrong_message_digest=False,
    wrong_content_type=False,
    second_signer=False,
    signer_serial=None,
    corrupt_signature=False,
):
    """A response whose token is signed correctly, unless one of the wrong_ or omit_ switches says otherwise."""
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
        issuing.attribute(oids.ATTR_CONTENT_TYPE, encode_oid(content_type)),
        issuing.attribute(oids.ATTR_MESSAGE_DIGEST, encode_octets(tst_digest)),
    ]
    if not omit_signing_cert:
        cert_hash = hashlib.sha256(b"not this certificate" if wrong_signing_cert else signer_der).digest()
        ess = encode_seq(encode_seq(encode_seq(encode_octets(cert_hash))))
        attributes.append(issuing.attribute(oids.ATTR_SIGNING_CERTIFICATE_V2, ess))
    signed_set = None if omit_signed_attrs else encode_set(attributes)
    signature = signer_key.sign(tst if signed_set is None else signed_set, digest_name)
    if corrupt_signature:
        signature = signer_key.sign(b"something else entirely", digest_name)
    signer_info = issuing.make_signer_info(
        name(issuer_name),
        signer_serial or _serial_of(signer_der),
        digest_name,
        signed_set,
        signer_key.algorithm(digest_name),
        signature,
    )
    signers = [signer_info, signer_info] if second_signer else [signer_info]
    token = issuing.make_signed_data(tst, signers, certificates, digest_name)
    if not wrap:
        return token
    return issuing.make_response(token, status)


def _serial_of(cert_der):
    node = der.parse(cert_der)
    tbs = node.children[0]
    return der.int_value(tbs.children[1])


def rejection(status=2, strings=("request refused",), failure=(0, 2)):
    """A response with no token, as an authority sends for a refused request."""
    return issuing.make_response(None, status, strings, failure)
