"""The pure Python signature arithmetic, including published test vectors."""

import hashlib
import unittest

from evidence_seal import der, ecdsa, hashes, oids, rsa, signatures
from evidence_seal.errors import DerError
from evidence_seal.signatures import AlgorithmId, Unsupported
from evidence_seal.x509 import load_certificates
from tests import forge
from tests.support import LOCAL


class EcdsaVectors(unittest.TestCase):
    def test_generators_are_on_their_curves(self):
        for curve in ecdsa.CURVES.values():
            self.assertTrue(curve.contains(curve.gx, curve.gy))
            self.assertIsNone(ecdsa.scalar_multiply(curve, curve.n, curve.generator))

    def test_rfc6979_p256_sha256_sample(self):
        """RFC 6979 appendix A.2.5, message "sample"."""
        qx = 0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
        qy = 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299
        r = 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
        s = 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8
        digest = hashlib.sha256(b"sample").digest()
        self.assertTrue(ecdsa.verify(ecdsa.P256, (qx, qy), digest, r, s))
        self.assertFalse(ecdsa.verify(ecdsa.P256, (qx, qy), hashlib.sha256(b"test").digest(), r, s))
        self.assertFalse(ecdsa.verify(ecdsa.P256, (qx, qy), digest, r ^ 1, s))
        self.assertFalse(ecdsa.verify(ecdsa.P256, (qx, qy), digest, r, s ^ 1))

    def test_rfc6979_p384_sha384_sample(self):
        """RFC 6979 appendix A.2.6, message "sample"."""
        qx = int(
            "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64"
            "DEF8F0EA9055866064A254515480BC13",
            16,
        )
        qy = int(
            "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1"
            "288B231C3AE0D4FE7344FD2533264720",
            16,
        )
        r = int(
            "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C"
            "81A648152E44ACF96E36DD1E80FABE46",
            16,
        )
        s = int(
            "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94F"
            "A329C145786E679E7B82C71A38628AC8",
            16,
        )
        digest = hashlib.sha384(b"sample").digest()
        self.assertTrue(ecdsa.verify(ecdsa.P384, (qx, qy), digest, r, s))
        self.assertFalse(ecdsa.verify(ecdsa.P384, (qx, qy), hashlib.sha384(b"test").digest(), r, s))

    def test_out_of_range_values_fail(self):
        curve = ecdsa.P256
        digest = hashlib.sha256(b"x").digest()
        for r, s in ((0, 1), (1, 0), (curve.n, 1), (1, curve.n), (-1, 1)):
            self.assertFalse(ecdsa.verify(curve, curve.generator, digest, r, s))

    def test_generated_keys_round_trip_on_every_curve(self):
        for seed, (oid, curve) in enumerate(ecdsa.CURVES.items()):
            key = forge.EcKey(seed + 50, curve, oid)
            signature = key.sign(b"message", "sha512")
            node = der.parse(signature)
            r, s = (der.int_value(child) for child in node.children)
            digest = hashlib.sha512(b"message").digest()
            self.assertTrue(ecdsa.verify(curve, key.point, digest, r, s), curve.name)
            self.assertFalse(ecdsa.verify(curve, key.point, hashlib.sha512(b"other").digest(), r, s), curve.name)

    def test_point_decoding(self):
        curve = ecdsa.P256
        size = curve.size
        uncompressed = b"\x04" + curve.gx.to_bytes(size, "big") + curve.gy.to_bytes(size, "big")
        self.assertEqual(ecdsa.decode_point(curve, uncompressed), curve.generator)
        compressed = bytes([2 + (curve.gy & 1)]) + curve.gx.to_bytes(size, "big")
        self.assertEqual(ecdsa.decode_point(curve, compressed), curve.generator)
        off_curve = b"\x04" + curve.gx.to_bytes(size, "big") + (curve.gy ^ 1).to_bytes(size, "big")
        with self.assertRaises(ValueError):
            ecdsa.decode_point(curve, off_curve)
        with self.assertRaises(ValueError):
            ecdsa.decode_point(curve, b"\x04\x01")


class RsaPadding(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = forge.RsaKey(77, bits=2048)
        cls.algorithm = hashes.SHA256
        cls.digest = hashlib.sha256(b"message").digest()

    def verify(self, signature):
        return rsa.verify_pkcs1_v15(self.key.n, self.key.e, self.algorithm, self.digest, signature)

    def block(self, body):
        size = (self.key.n.bit_length() + 7) // 8
        return body.rjust(size, b"\x00")

    def test_good_signature_passes(self):
        self.assertTrue(self.verify(self.key.sign(b"message")))
        self.assertFalse(self.verify(self.key.sign(b"another")))

    def test_wrong_length_fails(self):
        signature = self.key.sign(b"message")
        self.assertFalse(self.verify(signature[1:]))
        self.assertFalse(self.verify(b"\x00" + signature))

    def test_value_out_of_range_fails(self):
        too_big = (self.key.n + 1).to_bytes((self.key.n.bit_length() + 7) // 8, "big")
        self.assertFalse(self.verify(too_big))

    def test_padding_with_trailing_garbage_fails(self):
        """The classic forgery shape: short padding, hash, then attacker-chosen bytes."""
        info = self.algorithm.digest_info(self.digest)
        size = (self.key.n.bit_length() + 7) // 8
        body = b"\x00\x01\xff\xff\xff\xff\xff\xff\xff\xff\x00" + info
        forged = body + b"\xaa" * (size - len(body))
        self.assertFalse(self.verify(self.key.raw_sign(forged)))

    def test_padding_byte_other_than_ff_fails(self):
        info = self.algorithm.digest_info(self.digest)
        size = (self.key.n.bit_length() + 7) // 8
        forged = b"\x00\x01" + b"\xfe" * (size - len(info) - 3) + b"\x00" + info
        self.assertFalse(self.verify(self.key.raw_sign(forged)))

    def test_digest_info_for_another_hash_fails(self):
        other = hashes.by_name("sha1")
        info = other.digest_info(self.digest[:20])
        size = (self.key.n.bit_length() + 7) // 8
        forged = b"\x00\x01" + b"\xff" * (size - len(info) - 3) + b"\x00" + info
        self.assertFalse(self.verify(self.key.raw_sign(forged)))

    def test_short_padding_fails(self):
        info = self.algorithm.digest_info(self.digest)
        size = (self.key.n.bit_length() + 7) // 8
        padded = b"\x00\x01" + b"\x00" + info
        self.assertFalse(self.verify(self.key.raw_sign(self.block(padded)[:size])))

    def _pss_sign(self, digest, salt, mgf=None, top_bits_clear=True):
        size = (self.key.n.bit_length() + 7) // 8
        em_bits = self.key.n.bit_length() - 1
        em_len = (em_bits + 7) // 8
        tag = self.algorithm.digest(b"\x00" * 8 + digest + salt)
        db = b"\x00" * (em_len - len(salt) - self.algorithm.size - 2) + b"\x01" + salt
        mask = rsa._mgf1(tag, len(db), mgf or self.algorithm)
        masked = bytearray(a ^ b for a, b in zip(db, mask))
        if top_bits_clear:
            masked[0] &= 0xFF >> (8 * em_len - em_bits)
        encoded = bytes(masked) + tag + b"\xbc"
        return self.key.raw_sign(encoded.rjust(size, b"\x00"))

    def test_pss_round_trip_and_rejections(self):
        salt = b"\x11" * 32
        signature = self._pss_sign(self.digest, salt)
        check = lambda sig, digest=self.digest, length=32: rsa.verify_pss(
            self.key.n, self.key.e, self.algorithm, self.algorithm, length, digest, sig
        )
        self.assertTrue(check(signature))
        self.assertFalse(check(signature, digest=hashlib.sha256(b"other").digest()))
        self.assertFalse(check(signature, length=20))
        self.assertFalse(check(self.key.sign(b"message")))
        self.assertFalse(check(signature[:-1] + bytes([signature[-1] ^ 1])))


class SignatureDispatch(unittest.TestCase):
    def test_algorithm_oid_and_key_must_fit(self):
        rsa_key = load_certificates(LOCAL / "tsa-rsa.crt")[0].public_key
        ec_key = load_certificates(LOCAL / "tsa-ec.crt")[0].public_key
        outcome = signatures.verify(rsa_key, AlgorithmId(oids.ECDSA_SHA256), b"m", b"\x00")
        self.assertFalse(outcome.valid)
        outcome = signatures.verify(ec_key, AlgorithmId(oids.SHA256_WITH_RSA), b"m", b"\x00")
        self.assertFalse(outcome.valid)

    def test_malformed_ecdsa_signature_is_invalid_not_a_crash(self):
        ec_key = load_certificates(LOCAL / "tsa-ec.crt")[0].public_key
        for junk in (b"", b"\x30\x00", b"\x30\x03\x02\x01\x01", b"\xff\xff"):
            self.assertFalse(signatures.verify(ec_key, AlgorithmId(oids.ECDSA_SHA384), b"m", junk).valid)

    def test_unknown_algorithm_is_unsupported_not_invalid(self):
        rsa_key = load_certificates(LOCAL / "tsa-rsa.crt")[0].public_key
        with self.assertRaises(Unsupported):
            signatures.verify(rsa_key, AlgorithmId("1.3.101.112"), b"m", b"s")

    def test_unsupported_curve_is_unsupported(self):
        key = load_certificates(LOCAL / "tsa-brainpool.crt")[0].public_key
        self.assertIsInstance(key, signatures.OtherKey)
        with self.assertRaises(Unsupported):
            signatures.verify(key, AlgorithmId(oids.ECDSA_SHA256), b"m", b"s")

    def test_digest_and_signature_algorithm_must_agree(self):
        ec_key = load_certificates(LOCAL / "tsa-ec.crt")[0].public_key
        with self.assertRaises(DerError):
            signatures.verify(ec_key, AlgorithmId(oids.ECDSA_SHA256), b"m", b"s", digest_oid=oids.SHA384)

    def test_public_key_with_impossible_values_is_refused(self):
        for n, e in ((0, 65537), (15, 1), (15, 4)):
            spki = der.encode_seq(
                der.encode_seq(der.encode_oid(oids.RSA_ENCRYPTION), der.encode_null()),
                der.encode_bits(der.encode_seq(der.encode_int(n), der.encode_int(e))),
            )
            with self.assertRaises(DerError):
                signatures.parse_public_key(spki)


if __name__ == "__main__":
    unittest.main()
