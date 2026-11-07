"""Every verdict is compared with what openssl ts -verify says about the same files."""

import unittest
from datetime import datetime, timedelta, timezone

from evidence_seal import der, tokencheck
from evidence_seal.results import Status
from evidence_seal.tokencheck import CHAIN, HASH, SIGNATURE
from evidence_seal.trust import TrustStore
from evidence_seal.x509 import Certificate, load_certificates
from evidence_seal.openssl_bridge import UNAVAILABLE, YES, ts_verify
from tests import forge
from tests.support import HANDMADE_MANIFEST, LOCAL, SAMPLE_MANIFEST, TempFolderTestCase, requires_openssl

DATA = b"synthetic manifest bytes for the agreement test\n"
NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)
ROOT_FILES = ("root-rsa.crt", "root-ec.crt", "root-brainpool.crt")


@requires_openssl
class Agreement(TempFolderTestCase):
    def compare(self, token_bytes, data, roots, untrusted=(), bare=False, expect=None):
        manifest = self.write("manifest.bin", data)
        token = self.write("token.bin", token_bytes)
        store = TrustStore(roots, ["test root"] * len(roots))
        report = tokencheck.check_token(token_bytes, data, store, untrusted=untrusted, now=NOW)
        found = {check.key: check.status for check in report.checks}
        at_time = None
        if report.response is not None and report.response.tst_info is not None:
            at_time = report.response.tst_info.gen_time
        answer = ts_verify(manifest, token, roots, untrusted, at_time, token_in=bare)
        self.assertNotEqual(answer.answer, UNAVAILABLE, answer.output)
        ours = all(found.get(key) is Status.PASS for key in (HASH, SIGNATURE, CHAIN))
        theirs = answer.answer == YES
        self.assertEqual(ours, theirs, f"ours {found}, openssl says: {answer.output[:400]}")
        if expect is not None:
            self.assertEqual(ours, expect)
        return ours

    def test_committed_tokens(self):
        sample = SAMPLE_MANIFEST.read_bytes()
        roots = [load_certificates(LOCAL / name)[0] for name in ROOT_FILES]
        for name, bare in (
            ("token-rsa.tsr", False),
            ("token-ec.tsr", False),
            ("token-pss-chain.tsr", False),
            ("token-brainpool.tsr", False),
            ("token-sha512-imprint.tsr", False),
            ("token-bare.tst", True),
        ):
            with self.subTest(name):
                self.compare((LOCAL / name).read_bytes(), sample, roots, bare=bare, expect=True)

    def test_hand_made_pair(self):
        roots = [load_certificates(LOCAL / "root-ec.crt")[0]]
        token = (LOCAL / "token-handmade.tsr").read_bytes()
        self.compare(token, HANDMADE_MANIFEST.read_bytes(), roots, expect=True)
        self.compare(token, HANDMADE_MANIFEST.read_bytes().replace(b"\r\n", b"\n"), roots, expect=False)

    def test_p384_signer_under_an_rsa_root(self):
        authority = forge.mixed_authority()
        token = authority.token(DATA, digest_name="sha512")
        roots = [Certificate(authority.root)]
        self.compare(token, DATA, roots, expect=True)
        self.compare(token, DATA + b" ", roots, expect=False)

    def test_tampered_manifest(self):
        roots = [load_certificates(LOCAL / "root-rsa.crt")[0]]
        self.compare((LOCAL / "token-rsa.tsr").read_bytes(), b"tampered", roots, expect=False)

    def test_wrong_root(self):
        roots = [load_certificates(LOCAL / "other-root.crt")[0]]
        self.compare((LOCAL / "token-rsa.tsr").read_bytes(), SAMPLE_MANIFEST.read_bytes(), roots, expect=False)

    def test_token_without_certificates_given_its_certificate(self):
        roots = [load_certificates(LOCAL / "root-rsa.crt")[0]]
        extra = load_certificates(LOCAL / "tsa-rsa.crt")
        self.compare((LOCAL / "token-nocerts.tsr").read_bytes(), SAMPLE_MANIFEST.read_bytes(), roots, extra, expect=True)

    def test_byte_flips_in_signed_regions(self):
        whole = (LOCAL / "token-rsa.tsr").read_bytes()
        sample = SAMPLE_MANIFEST.read_bytes()
        roots = [load_certificates(LOCAL / "root-rsa.crt")[0]]
        node = der.parse(whole)
        signed = node.children[1].children[1].children[0]
        start = whole.index(signed.children[2].raw)
        root_copy = signed.children[3].children[1]
        unused = range(whole.index(root_copy.raw), whole.index(root_copy.raw) + len(root_copy.raw))
        for index in range(start, len(whole), 97):
            damaged = bytearray(whole)
            damaged[index] ^= 0x01
            with self.subTest(index=index):
                # A damaged copy of the root is unused when the verifier holds the real root.
                # Either way both tools must give the same answer.
                self.compare(bytes(damaged), sample, roots, expect=None if index in unused else False)

    def test_forged_tokens(self):
        authority = forge.Authority("agree", seed=21)
        root = Certificate(authority.root)
        cases = [
            ("control", authority.token(DATA), [root], True),
            ("granted with modifications", authority.token(DATA, status=1), [root], True),
            ("other data", authority.token(b"other"), [root], False),
            ("corrupt signature", authority.token(DATA, corrupt_signature=True), [root], False),
            ("wrong message digest", authority.token(DATA, wrong_message_digest=True), [root], False),
            ("wrong signing cert", authority.token(DATA, wrong_signing_cert=True), [root], False),
            ("no signing cert", authority.token(DATA, omit_signing_cert=True), [root], False),
            ("no signed attributes", authority.token(DATA, omit_signed_attrs=True), [root], False),
            ("attacker root", forge.Authority("attacker", seed=22).token(DATA), [root], False),
            ("same names, other keys", forge.Authority("agree", seed=23).token(DATA), [root], False),
        ]
        for label, token, roots, expected in cases:
            with self.subTest(label):
                self.compare(token, DATA, roots, expect=expected)

    def test_forged_certificates(self):
        no_eku = (forge.basic_constraints(False), forge.key_usage([0]))
        soft_eku = (forge.basic_constraints(False), forge.extended_key_usage(critical=False))
        extra_eku = (forge.basic_constraints(False), forge.extended_key_usage(("1.3.6.1.5.5.7.3.8", "1.3.6.1.5.5.7.3.1")))
        critical = forge.TSA_EXTENSIONS + (forge.unknown_critical_extension(),)
        for label, options in (
            ("no extended key usage", {"signer_extensions": no_eku}),
            ("not critical", {"signer_extensions": soft_eku}),
            ("extra usage", {"signer_extensions": extra_eku}),
            ("unknown critical extension", {"signer_extensions": critical}),
            ("expired at token time", {"not_after": forge.TOKEN_TIME - timedelta(days=1)}),
            ("not yet valid at token time", {"not_before": forge.TOKEN_TIME + timedelta(days=1)}),
        ):
            with self.subTest(label):
                authority = forge.Authority("cert", seed=31, **options)
                self.compare(authority.token(DATA), DATA, [Certificate(authority.root)], expect=False)

    def test_status_values(self):
        authority = forge.Authority("status", seed=41)
        root = Certificate(authority.root)
        for status in (2, 3, 4, 5):
            with self.subTest(status=status):
                manifest = self.write("m.bin", DATA)
                token = self.write("t.bin", authority.token(DATA, status=status))
                answer = ts_verify(manifest, token, [root], [], forge.TOKEN_TIME)
                self.assertNotEqual(answer.answer, YES)
                report = tokencheck.check_token(
                    authority.token(DATA, status=status), DATA, TrustStore([root], ["t"]), now=NOW
                )
                self.assertEqual({c.key: c.status for c in report.checks}[tokencheck.STATUS], Status.FAIL)


if __name__ == "__main__":
    unittest.main()
