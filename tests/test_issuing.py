"""The issuing side: keys, certificates and answers that the package's own checks accept."""

import hashlib
import unittest
from datetime import datetime, timedelta, timezone

from evidence_seal import der, ecdsa, hashes, issuing, oids, tokencheck, tsp
from evidence_seal.errors import UsageError
from evidence_seal.results import Status
from evidence_seal.trust import TrustStore
from evidence_seal.x509 import Certificate

NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
DATA = b"bytes covered by an issued token\n"


def authority():
    root_key, signer_key = issuing.EcPrivateKey.generate(), issuing.EcPrivateKey.generate()
    root_name = issuing.make_name("TEST ONLY issuing root", "Example Org")
    signer_name = issuing.make_name("TEST ONLY issuing signer", "Example Org")
    start, end = NOW - timedelta(days=1), NOW + timedelta(days=1)
    root = issuing.make_certificate(root_name, root_key, root_name, root_key, 1, start, end, issuing.CA_EXTENSIONS)
    signer = issuing.make_certificate(signer_name, signer_key, root_name, root_key, 2, start, end, issuing.TSA_EXTENSIONS)
    return root, signer, signer_key


class Keys(unittest.TestCase):
    def test_generated_keys_are_fresh_and_sign_verifiably(self):
        first, second = issuing.EcPrivateKey.generate(), issuing.EcPrivateKey.generate()
        self.assertNotEqual(first.d, second.d)
        self.assertTrue(ecdsa.P256.contains(*first.point))
        signature = der.parse(first.sign(b"message"))
        r, s = (der.int_value(child) for child in signature.children)
        self.assertTrue(ecdsa.verify(ecdsa.P256, first.point, hashlib.sha256(b"message").digest(), r, s))
        self.assertFalse(ecdsa.verify(ecdsa.P256, second.point, hashlib.sha256(b"message").digest(), r, s))

    def test_two_signatures_of_one_message_use_different_nonces(self):
        key = issuing.EcPrivateKey.generate()
        self.assertNotEqual(key.sign(b"same"), key.sign(b"same"))

    def test_out_of_range_private_values_are_refused(self):
        for value in (0, ecdsa.P256.n, -1):
            with self.subTest(value), self.assertRaises(ValueError):
                issuing.EcPrivateKey(value)

    def test_pem_round_trip_keeps_the_preface_outside_the_block(self):
        key = issuing.EcPrivateKey.generate()
        pem = key.to_pem(("TEST ONLY line one", "line two"))
        self.assertTrue(pem.startswith(b"TEST ONLY line one\nline two\n-----BEGIN EC PRIVATE KEY-----\n"))
        self.assertEqual(issuing.EcPrivateKey.from_pem(pem, "key").d, key.d)

    def test_damaged_key_files_are_refused_plainly(self):
        key = issuing.EcPrivateKey.generate()
        good = key.to_pem()
        other = issuing.EcPrivateKey.generate()
        wrong_point = issuing.EcPrivateKey(key.d)
        wrong_point.point = other.point
        p384 = issuing.EcPrivateKey(5, ecdsa.P384, oids.CURVE_P384)
        cases = {
            "empty": b"",
            "two keys": good + other.to_pem(),
            "not base64": b"-----BEGIN EC PRIVATE KEY-----\n!!!!\n-----END EC PRIVATE KEY-----\n",
            "not DER": b"-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n",
            "wrong public point": wrong_point.to_pem(),
            "another curve": p384.to_pem(),
        }
        for label, data in cases.items():
            with self.subTest(label), self.assertRaises(UsageError) as caught:
                issuing.EcPrivateKey.from_pem(data, "the key file")
            self.assertIn("the key file", str(caught.exception))


class Structures(unittest.TestCase):
    def test_named_bits_are_minimal_der(self):
        self.assertEqual(issuing.named_bits([0, 2]), b"\x03\x02\x05\xa0")
        self.assertEqual(issuing.named_bits([25]), b"\x03\x05\x06\x00\x00\x00\x40")
        self.assertEqual(issuing.named_bits([]), b"\x03\x01\x00")
        self.assertEqual(der.bit_flags(der.parse(issuing.named_bits([5, 15]))), {5, 15})

    def test_certificates_carry_what_a_timestamp_authority_needs(self):
        root_der, signer_der, _ = authority()
        root, signer = Certificate(root_der), Certificate(signer_der)
        self.assertTrue(root.self_issued)
        self.assertEqual(root.basic_constraints(), (True, None))
        self.assertEqual(signer.extended_key_usage(), [oids.KP_TIME_STAMPING])
        self.assertTrue(signer.extensions[oids.EXT_EXTENDED_KEY_USAGE].critical)
        self.assertEqual(signer.issuer.raw, root.subject.raw)
        self.assertEqual(signer.subject.display(), "O=Example Org, CN=TEST ONLY issuing signer")

    def test_validity_after_2049_uses_generalized_time(self):
        self.assertEqual(issuing.validity_time(datetime(2049, 1, 1, tzinfo=timezone.utc))[0], der.UTC_TIME)
        self.assertEqual(issuing.validity_time(datetime(2050, 1, 1, tzinfo=timezone.utc))[0], der.GENERALIZED_TIME)

    def test_an_issued_token_passes_every_check(self):
        root, signer, key = authority()
        digest = hashes.SHA256.digest(DATA)
        content = issuing.make_tst_info(digest, oids.SHA256, "1.2.3.4", 77, NOW, nonce=99, tsa_name=Certificate(signer).subject.raw)
        answer = issuing.make_response(issuing.sign_token(content, key, signer, (signer, root)))
        query = tsp.build_request(hashes.SHA256, digest, nonce=99)
        report = tokencheck.check_token(answer, DATA, TrustStore([Certificate(root)], ["root"]), query_bytes=query, now=NOW)
        self.assertEqual({check.status for check in report.checks}, {Status.PASS}, [c.detail for c in report.checks])
        self.assertEqual(report.facts.nonce, f"{99:x}")

    def test_a_rejection_reads_back(self):
        response = tsp.parse_response(issuing.make_response(None, 2, ("no",), [15]))
        self.assertFalse(response.granted)
        self.assertEqual(response.failure_bits, [15])
        self.assertIn("policy is not supported", response.failure_text())


if __name__ == "__main__":
    unittest.main()
