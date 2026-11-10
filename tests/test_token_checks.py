"""Every way a token can be wrong must end in a non-passing result."""

import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from evidence_seal import der, hashes, oids, tokencheck, tsp
from evidence_seal.errors import DerError
from evidence_seal.results import Status, overall_of
from evidence_seal.tokencheck import CHAIN, HASH, NAME, QUERY, SIGNATURE, STATUS, STRUCTURE, TIME
from evidence_seal.trust import Authority, TrustStore
from evidence_seal.x509 import Certificate, load_certificates
from tests import forge
from tests.support import HANDMADE_MANIFEST, LOCAL, SAMPLE_MANIFEST, requires_openssl

DATA = b"synthetic manifest bytes\n"
NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)


def store_of(*names):
    paths = [LOCAL / name for name in names]
    return TrustStore.from_files(paths)


def store_with(*ders):
    certificates = [Certificate(raw) for raw in ders]
    return TrustStore(certificates, ["test root"] * len(certificates))


def statuses(report):
    return {check.key: check.status for check in report.checks}


class FixtureTokens(unittest.TestCase):
    manifest = SAMPLE_MANIFEST.read_bytes()

    def check(self, name, *roots, untrusted=(), query=None):
        report = tokencheck.check_token(
            (LOCAL / name).read_bytes(),
            self.manifest,
            store_of(*roots),
            untrusted=untrusted,
            query_bytes=query,
            now=NOW,
        )
        return report

    def assert_all_pass(self, report):
        bad = [check for check in report.checks if check.status is not Status.PASS]
        self.assertEqual(bad, [], [f"{check.key}: {check.detail}" for check in bad])

    def test_rsa_token_passes_with_its_root(self):
        report = self.check("token-rsa.tsr", "root-rsa.crt")
        self.assert_all_pass(report)
        methods = {check.key: check.method for check in report.checks}
        self.assertIn("pure Python RSA", methods[SIGNATURE])
        self.assertEqual(report.facts.policy, "1.2.3.4.1")
        self.assertEqual(report.facts.hash_algorithm, "SHA-256")
        self.assertIn("TEST ONLY tsa-rsa", report.facts.authority)

    def test_ec_token_uses_pure_python(self):
        report = self.check("token-ec.tsr", "root-ec.crt")
        self.assert_all_pass(report)
        self.assertIn("pure Python ECDSA P-384", [c for c in report.checks if c.key == SIGNATURE][0].method)

    def test_pss_signed_certificate_uses_pure_python(self):
        report = self.check("token-pss-chain.tsr", "root-rsa.crt")
        self.assert_all_pass(report)
        self.assertIn("PSS", [c for c in report.checks if c.key == CHAIN][0].method)

    def test_sha512_imprint(self):
        self.assert_all_pass(self.check("token-sha512-imprint.tsr", "root-rsa.crt"))

    def test_bare_token_passes_and_says_it_is_bare(self):
        report = self.check("token-bare.tst", "root-rsa.crt")
        self.assert_all_pass(report)
        self.assertTrue(report.facts.is_bare_token)

    def test_token_without_certificates_is_not_a_pass_until_certificate_given(self):
        report = self.check("token-nocerts.tsr", "root-rsa.crt")
        self.assertEqual(statuses(report)[SIGNATURE], Status.NOT_CHECKED)
        self.assertEqual(statuses(report)[CHAIN], Status.NOT_CHECKED)
        self.assertEqual(overall_of(report.checks), "INCOMPLETE")
        given = load_certificates(LOCAL / "tsa-rsa.crt")
        self.assert_all_pass(self.check("token-nocerts.tsr", "root-rsa.crt", untrusted=given))

    def test_saved_request_is_compared(self):
        good = (LOCAL / "token-rsa.tsq").read_bytes()
        self.assertEqual(statuses(self.check("token-rsa.tsr", "root-rsa.crt", query=good))[QUERY], Status.PASS)
        other = (LOCAL / "token-ec.tsq").read_bytes()
        self.assertEqual(statuses(self.check("token-rsa.tsr", "root-rsa.crt", query=other))[QUERY], Status.FAIL)
        self.assertEqual(statuses(self.check("token-rsa.tsr", "root-rsa.crt", query=b"junk"))[QUERY], Status.FAIL)

    def test_sha1_imprint_is_not_a_pass_even_when_it_matches(self):
        report = self.check("token-sha1-imprint.tsr", "root-rsa.crt")
        self.assertEqual(statuses(report)[HASH], Status.NOT_CHECKED)
        self.assertEqual(overall_of(report.checks), "INCOMPLETE")

    def test_tampered_manifest_fails_only_the_hash_check(self):
        report = tokencheck.check_token(
            (LOCAL / "token-rsa.tsr").read_bytes(), self.manifest + b"x", store_of("root-rsa.crt"), now=NOW
        )
        found = statuses(report)
        self.assertEqual(found[HASH], Status.FAIL)
        self.assertEqual(found[SIGNATURE], Status.PASS)
        self.assertEqual(found[CHAIN], Status.PASS)
        self.assertEqual(overall_of(report.checks), "FAILED")

    def test_token_for_another_manifest_fails(self):
        report = self.check("token-handmade.tsr", "root-ec.crt")
        self.assertEqual(statuses(report)[HASH], Status.FAIL)
        matched = tokencheck.check_token(
            (LOCAL / "token-handmade.tsr").read_bytes(),
            HANDMADE_MANIFEST.read_bytes(),
            store_of("root-ec.crt"),
            now=NOW,
        )
        self.assert_all_pass(matched)

    def test_wrong_root_fails(self):
        report = self.check("token-rsa.tsr", "other-root.crt")
        self.assertEqual(statuses(report)[CHAIN], Status.FAIL)
        self.assertEqual(statuses(report)[SIGNATURE], Status.PASS)
        self.assertEqual(overall_of(report.checks), "FAILED")

    def test_unknown_root_without_ca_is_not_checked_rather_than_passed(self):
        report = tokencheck.check_token((LOCAL / "token-rsa.tsr").read_bytes(), self.manifest, TrustStore(), now=NOW)
        self.assertEqual(statuses(report)[CHAIN], Status.NOT_CHECKED)
        self.assertEqual(overall_of(report.checks), "INCOMPLETE")

    def test_truncated_token_at_every_scale_fails(self):
        whole = (LOCAL / "token-rsa.tsr").read_bytes()
        for size in (0, 1, 2, 3, 10, 50, 300, 1000, len(whole) // 2, len(whole) - 1):
            with self.subTest(size=size):
                report = tokencheck.check_token(whole[:size], self.manifest, store_of("root-rsa.crt"), now=NOW)
                self.assertEqual(statuses(report)[STRUCTURE], Status.FAIL)
                self.assertEqual(overall_of(report.checks), "FAILED")

    def test_trailing_bytes_fail(self):
        whole = (LOCAL / "token-rsa.tsr").read_bytes() + b"\x00"
        report = tokencheck.check_token(whole, self.manifest, store_of("root-rsa.crt"), now=NOW)
        self.assertEqual(overall_of(report.checks), "FAILED")

    def test_not_a_token_fails(self):
        for junk in (b"", b"hello", self.manifest, (LOCAL / "tsa-rsa.crt").read_bytes()):
            report = tokencheck.check_token(junk, self.manifest, store_of("root-rsa.crt"), now=NOW)
            self.assertEqual(overall_of(report.checks), "FAILED")

    def test_flipping_bytes_in_what_is_signed_or_certified_never_passes(self):
        whole = (LOCAL / "token-rsa.tsr").read_bytes()
        node = der.parse(whole)
        signed = node.children[1].children[1].children[0]
        # Skip the unsigned envelope fields ahead of the content: digest list and versions.
        encap = signed.children[2]
        start = whole.index(encap.raw)
        # The copy of the root in the token is not used when the verifier holds the real one.
        root_copy = signed.children[3].children[1]
        skip = range(whole.index(root_copy.raw), whole.index(root_copy.raw) + len(root_copy.raw))
        store = store_of("root-rsa.crt")
        for index in range(start, len(whole), 11):
            if index in skip:
                continue
            for mask in (0x01, 0x80):
                damaged = bytearray(whole)
                damaged[index] ^= mask
                report = tokencheck.check_token(bytes(damaged), self.manifest, store, now=NOW)
                self.assertNotEqual(overall_of(report.checks), "VERIFIED", f"byte {index} mask {mask}")


class CurvesOnlyOpensslCovers(unittest.TestCase):
    manifest = SAMPLE_MANIFEST.read_bytes()

    def run_brainpool(self):
        return tokencheck.check_token(
            (LOCAL / "token-brainpool.tsr").read_bytes(), self.manifest, store_of("root-brainpool.crt"), now=NOW
        )

    @requires_openssl
    def test_brainpool_uses_openssl_and_says_so(self):
        report = self.run_brainpool()
        found = {check.key: check for check in report.checks}
        self.assertEqual(found[SIGNATURE].status, Status.PASS)
        self.assertIn("openssl", found[SIGNATURE].method)
        self.assertEqual(found[CHAIN].status, Status.PASS)
        self.assertIn("openssl", found[CHAIN].method)

    def test_brainpool_without_openssl_is_not_checked(self):
        with mock.patch("evidence_seal.openssl_bridge.find_openssl", return_value=None):
            report = self.run_brainpool()
        found = statuses(report)
        self.assertEqual(found[SIGNATURE], Status.NOT_CHECKED)
        self.assertEqual(found[CHAIN], Status.NOT_CHECKED)
        self.assertEqual(overall_of(report.checks), "INCOMPLETE")

    def test_openssl_that_cannot_run_is_not_a_failure_or_a_pass(self):
        with mock.patch("evidence_seal.openssl_bridge.find_openssl", return_value="/no/such/openssl"):
            report = self.run_brainpool()
        self.assertEqual(statuses(report)[SIGNATURE], Status.NOT_CHECKED)


class BuiltInFingerprint(unittest.TestCase):
    """A P-384 signer under an RSA root, trusted only through a built-in fingerprint."""

    @classmethod
    def setUpClass(cls):
        cls.authority = forge.mixed_authority()
        cls.root = Certificate(cls.authority.root)
        cls.token = cls.authority.token(DATA, digest_name="sha512", nonce=77)
        known = Authority("TEST ONLY", "https://tsa.invalid/", "https://tsa.invalid/", "https://tsa.invalid/", cls.root.sha256)
        cls.pinned = mock.patch("evidence_seal.trust.KNOWN_AUTHORITIES", (known,))

    def test_passes_through_the_built_in_fingerprint(self):
        query = tsp.build_request(hashes.SHA256, hashes.SHA256.digest(DATA), nonce=77, cert_req=True)
        with self.pinned:
            report = tokencheck.check_token(self.token, DATA, TrustStore(), query_bytes=query, now=NOW)
        self.assertEqual({check.status for check in report.checks}, {Status.PASS})
        found = {check.key: check for check in report.checks}
        self.assertIn("pure Python ECDSA P-384", found[SIGNATURE].method)
        self.assertIn("pure Python RSA 2048", found[CHAIN].method)
        self.assertIn("built-in fingerprint", found[CHAIN].detail)

    def test_without_the_fingerprint_the_chain_is_not_a_pass(self):
        report = tokencheck.check_token(self.token, DATA, TrustStore(), now=NOW)
        self.assertEqual(statuses(report)[SIGNATURE], Status.PASS)
        self.assertEqual(statuses(report)[CHAIN], Status.NOT_CHECKED)
        self.assertEqual(overall_of(report.checks), "INCOMPLETE")

    def test_explicit_root_replaces_the_built_in_fingerprint(self):
        with self.pinned:
            report = tokencheck.check_token(self.token, DATA, store_of("root-ec.crt"), now=NOW)
        self.assertEqual(statuses(report)[CHAIN], Status.FAIL)


class HashMismatchNote(unittest.TestCase):
    def check(self, data):
        token = (LOCAL / "token-rsa.tsr").read_bytes()
        return tokencheck.check_token(token, data, store_of("root-rsa.crt"), now=NOW)

    def test_mismatch_stays_a_failure_and_says_what_it_means(self):
        report = self.check(SAMPLE_MANIFEST.read_bytes().replace(b"\n", b"\r\n"))
        self.assertEqual(statuses(report)[HASH], Status.FAIL)
        self.assertEqual(overall_of(report.checks), "FAILED")
        self.assertIn(tokencheck.HASH_MISMATCH_NOTE, report.notes)
        for phrase in ("these exact bytes", "not by itself proof of tampering", "other line endings", "footer"):
            self.assertIn(phrase, tokencheck.HASH_MISMATCH_NOTE)

    def test_no_note_when_the_hash_matches(self):
        self.assertNotIn(tokencheck.HASH_MISMATCH_NOTE, self.check(SAMPLE_MANIFEST.read_bytes()).notes)

    def test_no_note_when_another_check_fails(self):
        token = forge.Authority("note", seed=9).token(DATA, corrupt_signature=True)
        report = tokencheck.check_token(token, DATA, TrustStore(), now=NOW)
        self.assertEqual(statuses(report)[SIGNATURE], Status.FAIL)
        self.assertNotIn(tokencheck.HASH_MISMATCH_NOTE, report.notes)


class ForgedTokens(unittest.TestCase):
    """Tokens that are validly signed, but wrong in one specific way."""

    @classmethod
    def setUpClass(cls):
        cls.authority = forge.Authority("good", seed=1)
        cls.store = store_with(cls.authority.root)

    def check(self, token, store=None, data=DATA, now=NOW):
        return tokencheck.check_token(token, data, store or self.store, now=now)

    def assert_fails(self, token, key, store=None):
        report = self.check(token, store)
        self.assertEqual(statuses(report)[key], Status.FAIL, [c.detail for c in report.checks if c.key == key])
        self.assertEqual(overall_of(report.checks), "FAILED")
        return report

    def authority_with(self, label, seed, **options):
        return forge.Authority(label, seed=seed, **options)

    def test_control_token_passes(self):
        report = self.check(self.authority.token(DATA))
        self.assertEqual({check.status for check in report.checks}, {Status.PASS})

    def test_self_made_root_in_the_token_is_never_trusted_by_itself(self):
        attacker = self.authority_with("attacker", 9)
        report = self.check(attacker.token(DATA), store=TrustStore())
        found = statuses(report)
        self.assertEqual(found[SIGNATURE], Status.PASS)
        self.assertEqual(found[CHAIN], Status.NOT_CHECKED)
        self.assertEqual(overall_of(report.checks), "INCOMPLETE")

    def test_self_made_root_fails_against_the_real_root(self):
        attacker = self.authority_with("attacker", 9)
        self.assert_fails(attacker.token(DATA), CHAIN)

    def test_attacker_reusing_the_real_authority_names_fails(self):
        impostor = forge.Authority("good", seed=7)
        self.assert_fails(impostor.token(DATA), CHAIN)

    def test_signature_from_a_different_key_fails(self):
        other = forge.EcKey(99)
        token = forge.make_response(
            DATA,
            other,
            self.authority.signer,
            self.authority.signer_name,
            self.authority.root_name,
            certificates=(self.authority.signer, self.authority.root),
        )
        self.assert_fails(token, SIGNATURE)

    def test_corrupt_signature_fails(self):
        self.assert_fails(self.authority.token(DATA, corrupt_signature=True), SIGNATURE)

    def test_hash_of_other_data_fails(self):
        self.assert_fails(self.authority.token(b"something else"), HASH)

    def test_wrong_message_digest_attribute_fails(self):
        self.assert_fails(self.authority.token(DATA, wrong_message_digest=True), SIGNATURE)

    def test_wrong_content_type_attribute_fails(self):
        self.assert_fails(self.authority.token(DATA, wrong_content_type=True), SIGNATURE)

    def test_missing_signing_certificate_attribute_fails(self):
        self.assert_fails(self.authority.token(DATA, omit_signing_cert=True), SIGNATURE)

    def test_wrong_signing_certificate_attribute_fails(self):
        self.assert_fails(self.authority.token(DATA, wrong_signing_cert=True), SIGNATURE)

    def test_no_signed_attributes_fails(self):
        self.assert_fails(self.authority.token(DATA, omit_signed_attrs=True), SIGNATURE)

    def test_two_signers_fail(self):
        self.assert_fails(self.authority.token(DATA, second_signer=True), STRUCTURE)

    def test_version_two_fails(self):
        self.assert_fails(self.authority.token(DATA, version=2), STRUCTURE)

    def test_future_time_fails(self):
        self.assert_fails(self.authority.token(DATA, moment=NOW + timedelta(days=30)), TIME)

    def test_authority_name_that_differs_from_the_signer_fails(self):
        self.assert_fails(self.authority.token(DATA, tsa_name=forge.name("Somebody Else")), NAME)

    def test_certificate_without_timestamping_purpose_fails(self):
        for label, extensions in (
            ("none", (forge.basic_constraints(False), forge.key_usage([0]))),
            ("not critical", (forge.basic_constraints(False), forge.extended_key_usage(critical=False))),
            ("wrong usage", (forge.basic_constraints(False), forge.extended_key_usage(("1.3.6.1.5.5.7.3.1",)))),
            (
                "extra usage",
                (
                    forge.basic_constraints(False),
                    forge.extended_key_usage((oids.KP_TIME_STAMPING, "1.3.6.1.5.5.7.3.1")),
                ),
            ),
            ("key usage", (forge.basic_constraints(False), forge.extended_key_usage(), forge.key_usage([5]))),
        ):
            with self.subTest(label):
                authority = self.authority_with("purpose", 2, signer_extensions=extensions)
                self.assert_fails(authority.token(DATA), CHAIN, store_with(authority.root))

    def test_unknown_critical_extension_fails(self):
        extensions = forge.TSA_EXTENSIONS + (forge.unknown_critical_extension(),)
        authority = self.authority_with("critical", 3, signer_extensions=extensions)
        self.assert_fails(authority.token(DATA), CHAIN, store_with(authority.root))

    def test_certificate_expired_at_the_token_time_fails(self):
        authority = self.authority_with("expired", 4, not_after=forge.TOKEN_TIME - timedelta(days=1))
        self.assert_fails(authority.token(DATA), CHAIN, store_with(authority.root))

    def test_certificate_not_yet_valid_at_the_token_time_fails(self):
        authority = self.authority_with("early", 5, not_before=forge.TOKEN_TIME + timedelta(days=1))
        self.assert_fails(authority.token(DATA), CHAIN, store_with(authority.root))

    def test_certificate_that_expired_later_passes_and_says_so(self):
        authority = self.authority_with("later", 6, not_after=forge.TOKEN_TIME + timedelta(days=30))
        report = self.check(authority.token(DATA), store_with(authority.root))
        self.assertEqual(statuses(report)[CHAIN], Status.PASS)
        self.assertTrue(any("expired since" in note for note in report.notes), report.notes)

    def test_issuer_that_is_not_a_certificate_authority_fails(self):
        root_key = forge.EcKey(301)
        signer_key = forge.EcKey(302)
        root = forge.make_certificate(
            "TEST ONLY bad root",
            root_key,
            "TEST ONLY bad root",
            root_key,
            extensions=(forge.basic_constraints(False),),
        )
        signer = forge.make_certificate("TEST ONLY s", signer_key, "TEST ONLY bad root", root_key, serial=2)
        token = forge.make_response(
            DATA, signer_key, signer, "TEST ONLY s", "TEST ONLY bad root", certificates=(signer, root)
        )
        self.assert_fails(token, CHAIN, store_with(root))

    def test_ordinary_certificate_cannot_issue_a_timestamp_signer(self):
        """A leaf under the real root signs a new cert: its issuer flag must be checked."""
        leaf_key = forge.EcKey(401)
        leaf = forge.make_certificate(
            "TEST ONLY leaf",
            leaf_key,
            self.authority.root_name,
            self.authority.root_key,
            serial=40,
            extensions=(forge.basic_constraints(False), forge.key_usage([0])),
        )
        rogue_key = forge.EcKey(402)
        rogue = forge.make_certificate("TEST ONLY rogue", rogue_key, "TEST ONLY leaf", leaf_key, serial=41)
        token = forge.make_response(
            DATA, rogue_key, rogue, "TEST ONLY rogue", "TEST ONLY leaf", certificates=(rogue, leaf, self.authority.root)
        )
        self.assert_fails(token, CHAIN)

    def test_path_length_limit_is_enforced(self):
        root_key = forge.EcKey(501)
        middle_key = forge.EcKey(502)
        signer_key = forge.EcKey(503)
        root = forge.make_certificate(
            "TEST ONLY limited",
            root_key,
            "TEST ONLY limited",
            root_key,
            extensions=(forge.basic_constraints(True, path_length=0), forge.key_usage([5])),
        )
        middle = forge.make_certificate(
            "TEST ONLY middle",
            middle_key,
            "TEST ONLY limited",
            root_key,
            serial=2,
            extensions=(forge.basic_constraints(True), forge.key_usage([5])),
        )
        signer = forge.make_certificate("TEST ONLY s2", signer_key, "TEST ONLY middle", middle_key, serial=3)
        token = forge.make_response(
            DATA, signer_key, signer, "TEST ONLY s2", "TEST ONLY middle", certificates=(signer, middle, root)
        )
        self.assert_fails(token, CHAIN, store_with(root))

    def test_valid_intermediate_passes(self):
        root_key = forge.EcKey(601)
        middle_key = forge.EcKey(602)
        signer_key = forge.EcKey(603)
        root = forge.make_certificate(
            "TEST ONLY top", root_key, "TEST ONLY top", root_key, extensions=forge.CA_EXTENSIONS
        )
        middle = forge.make_certificate(
            "TEST ONLY mid", middle_key, "TEST ONLY top", root_key, serial=2, extensions=forge.CA_EXTENSIONS
        )
        signer = forge.make_certificate("TEST ONLY s3", signer_key, "TEST ONLY mid", middle_key, serial=3)
        token = forge.make_response(DATA, signer_key, signer, "TEST ONLY s3", "TEST ONLY mid", certificates=(signer, middle))
        report = self.check(token, store_with(root))
        self.assertEqual({check.status for check in report.checks}, {Status.PASS})

    def test_certificates_that_issue_each_other_end_cleanly(self):
        key_a = forge.EcKey(701)
        key_b = forge.EcKey(702)
        cert_a = forge.make_certificate(
            "TEST ONLY a", key_a, "TEST ONLY b", key_b, serial=1, extensions=forge.CA_EXTENSIONS
        )
        cert_b = forge.make_certificate(
            "TEST ONLY b", key_b, "TEST ONLY a", key_a, serial=2, extensions=forge.CA_EXTENSIONS
        )
        signer_key = forge.EcKey(703)
        signer = forge.make_certificate("TEST ONLY s4", signer_key, "TEST ONLY a", key_a, serial=3)
        token = forge.make_response(
            DATA, signer_key, signer, "TEST ONLY s4", "TEST ONLY a", certificates=(signer, cert_a, cert_b)
        )
        report = self.check(token, TrustStore())
        self.assertNotEqual(overall_of(report.checks), "VERIFIED")

    def test_intermediate_alone_is_not_a_root(self):
        root_key = forge.EcKey(801)
        middle_key = forge.EcKey(802)
        signer_key = forge.EcKey(803)
        middle = forge.make_certificate(
            "TEST ONLY mid2", middle_key, "TEST ONLY top2", root_key, serial=2, extensions=forge.CA_EXTENSIONS
        )
        signer = forge.make_certificate("TEST ONLY s5", signer_key, "TEST ONLY mid2", middle_key, serial=3)
        token = forge.make_response(DATA, signer_key, signer, "TEST ONLY s5", "TEST ONLY mid2", certificates=(signer,))
        self.assert_fails(token, CHAIN, store_with(middle))

    def test_status_is_enforced_even_with_a_valid_token_inside(self):
        for status in (2, 3, 4, 5):
            with self.subTest(status=status):
                self.assert_fails(self.authority.token(DATA, status=status), STATUS)

    def test_granted_with_modifications_is_accepted(self):
        report = self.check(self.authority.token(DATA, status=1))
        self.assertEqual(statuses(report)[STATUS], Status.PASS)
        self.assertEqual(report.facts.status, "granted with modifications")

    def test_rejection_without_a_token_fails_and_gives_the_reason(self):
        report = self.check(forge.rejection())
        found = {check.key: check for check in report.checks}
        self.assertEqual(found[STATUS].status, Status.FAIL)
        self.assertIn("rejected", found[STATUS].detail)
        self.assertIn("request refused", found[STATUS].detail)
        self.assertIn("unsupported hash algorithm", found[STATUS].detail)
        self.assertEqual(found[HASH].status, Status.NOT_CHECKED)
        self.assertEqual(overall_of(report.checks), "FAILED")

    def test_granted_response_without_a_token_fails(self):
        token = der.encode_seq(der.encode_seq(der.encode_int(0)))
        self.assert_fails(token, STRUCTURE)

    def test_sha1_signature_is_not_a_pass(self):
        report = self.check(self.authority.token(DATA, digest_name="sha1"))
        self.assertEqual(statuses(report)[SIGNATURE], Status.NOT_CHECKED)
        self.assertEqual(overall_of(report.checks), "INCOMPLETE")

    def test_sha1_certificate_signature_is_not_a_pass(self):
        authority = self.authority_with("sha1cert", 8, sign_hash="sha1")
        report = self.check(authority.token(DATA), store_with(authority.root))
        self.assertEqual(statuses(report)[CHAIN], Status.NOT_CHECKED)

    def test_short_rsa_key_is_not_a_pass(self):
        key = forge.RsaKey(11, bits=1024)
        authority = forge.Authority("shortrsa", seed=12, signer_key=key)
        report = self.check(authority.token(DATA), store_with(authority.root))
        self.assertEqual(statuses(report)[SIGNATURE], Status.NOT_CHECKED)
        self.assertEqual(overall_of(report.checks), "INCOMPLETE")

    def test_unknown_imprint_hash_is_not_checked(self):
        token = self.authority.token(DATA, hash_oid="1.2.3.4.5", data_hash=b"\x01" * 32)
        report = self.check(token)
        self.assertEqual(statuses(report)[HASH], Status.NOT_CHECKED)

    def test_ber_outer_layers_still_verify_and_tampering_still_fails(self):
        good = self.authority.token(DATA)
        ber = _indefinite_outer(good)
        self.assertNotEqual(ber, good)
        report = self.check(ber)
        self.assertEqual({check.status for check in report.checks}, {Status.PASS})
        self.assertEqual(statuses(self.check(ber, data=b"other"))[HASH], Status.FAIL)

    def test_non_der_inside_the_signed_content_is_refused(self):
        tst = forge.make_tst_info(b"\x00" * 32)
        bad = b"\x30\x80" + der.parse(tst).content + b"\x00\x00"
        with self.assertRaises(DerError):
            tsp.parse_tst_info(bad)


def _indefinite_outer(token):
    """Rewrites the unsigned wrapper layers of a response with BER indefinite lengths."""
    top = der.parse(token)
    status, content_info = top.children
    oid, wrapper = content_info.children
    signed = wrapper.children[0]

    def indefinite(identifier, *parts):
        return bytes([identifier, 0x80]) + b"".join(parts) + b"\x00\x00"

    signed_ber = indefinite(0x30, *[child.raw for child in signed.children])
    wrapper_ber = indefinite(0xA0, signed_ber)
    info_ber = indefinite(0x30, oid.raw, wrapper_ber)
    return indefinite(0x30, status.raw, info_ber)


if __name__ == "__main__":
    unittest.main()
