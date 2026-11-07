"""Certificates, signed data, requests and responses."""

import base64
import re
import unittest
from datetime import timezone
from unittest import mock

from evidence_seal import cms, der, hashes, oids, showing, tsp
from evidence_seal.errors import CertificateFileError, DerError, TokenFormatError
from evidence_seal.signatures import EcKey, RsaKey
from evidence_seal.trust import DEFAULT_TSA_URL, KNOWN_AUTHORITIES, Authority, TrustStore, authority_for_root
from evidence_seal.x509 import Certificate, Name, certificates_from_bytes, load_certificates
from tests import forge
from tests.support import LOCAL, SAMPLE_MANIFEST, TempFolderTestCase


class Certificates(TempFolderTestCase):
    def test_reads_an_rsa_timestamp_certificate(self):
        cert = load_certificates(LOCAL / "tsa-rsa.crt")[0]
        self.assertEqual(cert.version, 3)
        self.assertIn("TEST ONLY tsa-rsa", cert.subject.display())
        self.assertIn("TEST ONLY root-rsa", cert.issuer.display())
        self.assertEqual(cert.subject.common_name(), "TEST ONLY tsa-rsa")
        self.assertIsInstance(cert.public_key, RsaKey)
        self.assertEqual(cert.public_key.bits, 2048)
        self.assertEqual(cert.extended_key_usage(), [oids.KP_TIME_STAMPING])
        self.assertEqual(cert.basic_constraints(), (False, None))
        self.assertEqual(cert.key_usage(), {0})
        self.assertFalse(cert.self_issued)
        self.assertEqual(len(cert.subject_key_id()), 20)

    def test_reads_an_ec_root(self):
        cert = load_certificates(LOCAL / "root-ec.crt")[0]
        self.assertIsInstance(cert.public_key, EcKey)
        self.assertEqual(cert.public_key.curve.name, "P-256")
        self.assertTrue(cert.self_issued)
        self.assertEqual(cert.basic_constraints(), (True, None))

    def test_pem_and_der_load_the_same(self):
        cert = load_certificates(LOCAL / "tsa-ec.crt")[0]
        der_file = self.write("cert.der", cert.raw)
        self.assertEqual(load_certificates(der_file)[0], cert)
        pem_file = self.write("cert.pem", cert.to_pem().encode("ascii"))
        self.assertEqual(load_certificates(pem_file)[0], cert)

    def test_pem_file_with_several_certificates(self):
        one = load_certificates(LOCAL / "tsa-ec.crt")[0]
        two = load_certificates(LOCAL / "root-ec.crt")[0]
        data = ("text before\n" + one.to_pem() + "between\n" + two.to_pem()).encode("ascii")
        self.assertEqual(certificates_from_bytes(data, "test"), [one, two])

    def test_bad_certificate_files_are_refused(self):
        for label, data in (
            ("empty", b""),
            ("text", b"hello there"),
            ("bad base64", b"-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n"),
            (
                "not a cert",
                b"-----BEGIN CERTIFICATE-----\n" + base64.b64encode(b"\x30\x00") + b"\n-----END CERTIFICATE-----\n",
            ),
            ("truncated", load_certificates(LOCAL / "tsa-ec.crt")[0].raw[:100]),
        ):
            with self.subTest(label):
                with self.assertRaises(CertificateFileError):
                    certificates_from_bytes(data, label)

    def test_missing_file_is_a_clear_error(self):
        with self.assertRaises(CertificateFileError):
            load_certificates(self.temp / "nope.crt")

    def test_two_different_signature_algorithms_are_refused(self):
        raw = load_certificates(LOCAL / "root-ec.crt")[0].raw
        node = der.parse(raw)
        tbs, _algorithm, signature = node.children
        other = der.encode_seq(der.encode_oid(oids.ECDSA_SHA384))
        forged = der.encode_seq(tbs.raw, other, signature.raw)
        with self.assertRaises(TokenFormatError):
            Certificate(forged)

    def test_repeated_extension_is_refused(self):
        key = forge.EcKey(5)
        repeated = forge.make_certificate(
            "TEST ONLY x", key, "TEST ONLY x", key, extensions=(forge.basic_constraints(True), forge.basic_constraints(True))
        )
        with self.assertRaises(TokenFormatError):
            Certificate(repeated)

    def test_names_compare_like_rfc5280(self):
        def build(*pairs):
            rdns = [der.encode_set([der.encode_seq(der.encode_oid(o), der.encode_utf8(v))]) for o, v in pairs]
            return Name(der.encode_seq(*rdns))

        base = build(("2.5.4.10", "Org"), ("2.5.4.3", "Some Name"))
        self.assertTrue(base.matches(build(("2.5.4.10", "ORG"), ("2.5.4.3", "some   name"))))
        self.assertFalse(base.matches(build(("2.5.4.3", "Some Name"), ("2.5.4.10", "Org"))))
        self.assertFalse(base.matches(build(("2.5.4.10", "Org"), ("2.5.4.3", "Other"))))
        self.assertEqual(base.display(), "O=Org, CN=Some Name")
        self.assertEqual(Name(der.encode_seq()).display(), "(empty name)")


def pinned(cert):
    """Makes a test certificate count as a built-in root for the length of a with block."""
    known = Authority("TEST ONLY", "https://tsa.invalid/", "https://tsa.invalid/", "https://tsa.invalid/", cert.sha256)
    return mock.patch("evidence_seal.trust.KNOWN_AUTHORITIES", (known,))


class Trust(unittest.TestCase):
    def test_built_in_entries_are_well_formed(self):
        self.assertEqual(KNOWN_AUTHORITIES[0].tsa_url, DEFAULT_TSA_URL)
        for authority in KNOWN_AUTHORITIES:
            self.assertRegex(authority.root_sha256, re.compile(r"^[0-9a-f]{64}$"))
            for url in (authority.tsa_url, authority.terms_url, authority.root_url):
                self.assertTrue(url.startswith("https://"), url)

    def test_built_in_fingerprint_makes_a_root_trusted(self):
        root = load_certificates(LOCAL / "root-rsa.crt")[0]
        self.assertIsNone(TrustStore().anchor_label(root))
        with pinned(root):
            self.assertEqual(authority_for_root(root.sha256).name, "TEST ONLY")
            self.assertIn("built-in", TrustStore().anchor_label(root))

    def test_explicit_files_turn_off_the_built_in_fingerprints(self):
        root = load_certificates(LOCAL / "root-rsa.crt")[0]
        store = TrustStore.from_files([LOCAL / "root-ec.crt"])
        self.assertTrue(store.explicit)
        with pinned(root):
            self.assertIsNone(store.anchor_label(root))
        self.assertIn("root-ec.crt", store.anchor_label(store.certificates[0]))

    def test_unknown_certificate_has_no_label(self):
        self.assertIsNone(TrustStore().anchor_label(load_certificates(LOCAL / "root-ec.crt")[0]))


class Requests(unittest.TestCase):
    def test_build_and_parse_round_trip(self):
        digest = hashes.SHA256.digest(b"data")
        data = tsp.build_request(hashes.SHA256, digest, nonce=12345, policy="1.2.3.4", cert_req=True)
        request = tsp.parse_request(data)
        self.assertEqual(request.version, 1)
        self.assertEqual(request.hash_oid, oids.SHA256)
        self.assertEqual(request.digest, digest)
        self.assertEqual(request.nonce, 12345)
        self.assertEqual(request.policy, "1.2.3.4")
        self.assertTrue(request.cert_req)

    def test_minimal_request(self):
        data = tsp.build_request(hashes.SHA256, bytes(32), cert_req=False)
        request = tsp.parse_request(data)
        self.assertIsNone(request.nonce)
        self.assertIsNone(request.policy)
        self.assertFalse(request.cert_req)

    def test_reads_a_request_made_by_openssl(self):
        request = tsp.parse_request((LOCAL / "token-rsa.tsq").read_bytes())
        self.assertEqual(request.digest, hashes.SHA256.digest(SAMPLE_MANIFEST.read_bytes()))
        self.assertTrue(request.cert_req)
        self.assertIsNotNone(request.nonce)


class Responses(unittest.TestCase):
    def test_reads_all_fields_of_an_openssl_token(self):
        response = tsp.parse_response((LOCAL / "token-rsa.tsr").read_bytes())
        self.assertEqual(response.status, 0)
        self.assertTrue(response.granted)
        info = response.tst_info
        self.assertEqual(info.version, 1)
        self.assertEqual(info.policy, "1.2.3.4.1")
        self.assertEqual(info.hash_oid, oids.SHA256)
        self.assertEqual(info.accuracy_seconds, 1)
        self.assertEqual(info.accuracy_millis, 500)
        self.assertEqual(info.accuracy_micros, 100)
        self.assertTrue(info.ordering)
        self.assertIsNotNone(info.nonce)
        self.assertIn("TEST ONLY tsa-rsa", info.authority_text())
        self.assertIn("1 s", info.accuracy_text())
        self.assertEqual(info.gen_time.tzinfo, timezone.utc)

    def test_signed_data_fields(self):
        signed = tsp.parse_response((LOCAL / "token-rsa.tsr").read_bytes()).signed_data
        self.assertEqual(signed.content_type, oids.CT_TST_INFO)
        self.assertEqual(len(signed.certificates), 2)
        self.assertEqual(len(signed.signers), 1)
        signer = signed.signers[0]
        self.assertEqual(signer.digest_algorithm.oid, oids.SHA256)
        cert = cms.find_signer_certificate(signer, signed.certificates)
        self.assertIn("tsa-rsa", cert.subject.display())
        self.assertEqual(cms.check_signing_cert_attribute(signer, cert)[0], True)
        other = load_certificates(LOCAL / "tsa-ec.crt")[0]
        self.assertEqual(cms.check_signing_cert_attribute(signer, other)[0], False)
        self.assertTrue(signer.signed_message().startswith(b"\x31"))

    def test_rejection_is_readable(self):
        response = tsp.parse_response(forge.rejection())
        self.assertEqual(response.status, 2)
        self.assertFalse(response.granted)
        self.assertIsNone(response.tst_info)
        self.assertIn("request refused", response.failure_text())
        self.assertEqual(response.status_text(), "rejected")

    def test_size_limit(self):
        with self.assertRaises(TokenFormatError):
            tsp.parse_response(b"\x00" * (tsp.MAX_TOKEN_BYTES + 1))

    def test_wrong_shapes_are_refused(self):
        for data in (
            der.encode_int(1),
            der.encode_seq(),
            der.encode_seq(der.encode_seq(der.encode_oid("1.2.3"))),
            der.encode_seq(der.encode_seq(der.encode_int(0)), der.encode_seq(), der.encode_null()),
            der.encode_seq(der.encode_oid(oids.CMS_DATA)),
            der.encode_seq(der.encode_oid(oids.CMS_SIGNED_DATA)),
        ):
            with self.subTest(data=data):
                with self.assertRaises((DerError, TokenFormatError)):
                    tsp.parse_response(data)

    def test_tst_info_with_time_offset_or_extra_field_is_refused(self):
        good = forge.make_tst_info(bytes(32))
        self.assertEqual(tsp.parse_tst_info(good).version, 1)
        with self.assertRaises(DerError):
            tsp.parse_tst_info(der.encode_tlv(0x30, der.parse(good).content + der.encode_utf8("extra")))


class Show(unittest.TestCase):
    def test_plain_language(self):
        with pinned(load_certificates(LOCAL / "root-rsa.crt")[0]):
            text = showing.render_text(showing.describe((LOCAL / "token-rsa.tsr").read_bytes()))
        self.assertIn("existed by", text)
        self.assertIn("SHA-256", text)
        self.assertIn("Policy: 1.2.3.4.1", text)
        self.assertIn("built in as the TEST ONLY root", text)
        self.assertIn("Nothing above has been verified", text)

    def test_rejection_says_it_proves_nothing(self):
        data = showing.describe(forge.rejection())
        self.assertFalse(data["granted"])
        text = showing.render_text(data)
        self.assertIn("rejected", text)
        self.assertIn("proves nothing", text)

    def test_time_is_plain_utc(self):
        data = showing.describe(forge.Authority("s", seed=3).token(b"x"))
        self.assertEqual(data["time"], "2026-03-01 12:00:00 UTC")
        self.assertTrue(data["granted"])


if __name__ == "__main__":
    unittest.main()
