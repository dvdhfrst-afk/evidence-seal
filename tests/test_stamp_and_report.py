"""The stamp command with a fake network, and the report."""

import html.parser
import json
import shlex
import shutil
import subprocess
import unittest
import urllib.error
from unittest import mock

from evidence_seal import hashes, manifest, openssl_bridge, stamping, tsp
from evidence_seal.errors import UsageError
from evidence_seal.trust import TrustStore
from evidence_seal.x509 import Certificate
from tests import forge
from tests.support import LOCAL, TempFolderTestCase, requires_openssl, run_cli


class FakeAnswer:
    def __init__(self, body):
        self.body = body

    def read(self, limit=-1):
        return self.body[:limit] if limit >= 0 else self.body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


class FakeAuthority:
    """Stands in for urlopen. Answers from the request it receives, like a real authority."""

    def __init__(self, seed=61, **options):
        self.authority = forge.Authority("fake", seed=seed)
        self.options = options
        self.requests = []
        self.mutate = None

    def __call__(self, request, timeout=None):
        self.requests.append(request)
        parsed = tsp.parse_request(request.data)
        options = dict(self.options)
        options.setdefault("nonce", parsed.nonce)
        options.setdefault("hash_oid", parsed.hash_oid)
        options.setdefault("data_hash", parsed.digest)
        body = self.authority.token(b"", **options)
        if self.mutate:
            body = self.mutate(body)
        return FakeAnswer(body)


class Stamp(TempFolderTestCase):
    def setUp(self):
        super().setUp()
        self.manifest = self.write("m.txt", b"manifest bytes\n")

    def run_stamp(self, fake, *extra):
        with mock.patch("evidence_seal.stamping._open_url", fake):
            return run_cli("stamp", self.manifest, *extra)

    def store(self, fake):
        return TrustStore([Certificate(fake.authority.root)], ["test root"])

    def saved(self):
        return sorted(path.name for path in self.temp.iterdir())

    def test_good_answer_is_saved(self):
        fake = FakeAuthority()
        code, out, err = self.run_stamp(fake)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.saved(), ["m.ca.crt", "m.tsq", "m.tsr", "m.txt"])
        self.assertIn("[PASS] Signature is valid", out)
        self.assertIn("[NOT CHECKED] Certificate chain", out)
        request = tsp.parse_request((self.temp / "m.tsq").read_bytes())
        self.assertEqual(request.digest, hashes.SHA256.digest(b"manifest bytes\n"))
        self.assertTrue(request.cert_req)
        self.assertGreater(request.nonce, 2 ** 40)

    def test_request_shape(self):
        fake = FakeAuthority()
        self.run_stamp(fake, "--tsa-url", "http://authority.example/tsr")
        request = fake.requests[0]
        self.assertEqual(request.full_url, "http://authority.example/tsr")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.get_header("Content-type"), "application/timestamp-query")
        self.assertRegex(request.get_header("User-agent"), r"^evidence-seal/\d")
        self.assertNotIn(b"manifest bytes", request.data)

    def test_two_requests_use_different_nonces(self):
        fake = FakeAuthority()
        self.run_stamp(fake)
        self.run_stamp(fake, "--force")
        nonces = {tsp.parse_request(item.data).nonce for item in fake.requests}
        self.assertEqual(len(nonces), 2)

    def test_stronger_hash_option(self):
        fake = FakeAuthority()
        self.run_stamp(fake, "--hash", "sha512")
        self.assertEqual(len(tsp.parse_request(fake.requests[0].data).digest), 64)

    def test_weak_or_unknown_hash_is_refused_before_any_request(self):
        fake = FakeAuthority()
        for name in ("sha1", "md5", "crc32"):
            code, _, err = self.run_stamp(fake, "--hash", name)
            self.assertEqual(code, 2)
            self.assertIn("--hash", err)
        self.assertEqual(fake.requests, [])

    def assert_nothing_saved(self, fake, phrase, *extra):
        code, _, err = self.run_stamp(fake, *extra)
        self.assertEqual(code, 1, err)
        self.assertIn(phrase, err)
        self.assertEqual(self.saved(), ["m.txt"])

    def test_answer_for_other_data_is_not_saved(self):
        self.assert_nothing_saved(FakeAuthority(data_hash=b"\x01" * 32), "not saved")

    def test_wrong_nonce_is_not_saved(self):
        self.assert_nothing_saved(FakeAuthority(nonce=5), "nonce")

    def test_no_nonce_in_the_answer_is_not_saved(self):
        fake = FakeAuthority()
        fake.options["nonce"] = None
        self.assert_nothing_saved(fake, "nonce")

    def test_bad_signature_is_not_saved(self):
        self.assert_nothing_saved(FakeAuthority(corrupt_signature=True), "Signature")

    def test_rejection_is_not_saved_and_shows_the_reason(self):
        fake = FakeAuthority()
        fake.mutate = lambda _body: forge.rejection()
        self.assert_nothing_saved(fake, "request refused")

    def test_html_error_page_with_status_200_is_not_saved(self):
        fake = FakeAuthority()
        fake.mutate = lambda _body: b"<html>Service down for maintenance</html>"
        self.assert_nothing_saved(fake, "not saved")

    def test_empty_answer_is_not_saved(self):
        fake = FakeAuthority()
        fake.mutate = lambda _body: b""
        self.assert_nothing_saved(fake, "empty answer")

    def test_truncated_answer_is_not_saved(self):
        fake = FakeAuthority()
        fake.mutate = lambda body: body[:len(body) // 2]
        self.assert_nothing_saved(fake, "not saved")

    def test_http_error_is_reported(self):
        def fail(_request, timeout=None):
            raise urllib.error.HTTPError("u", 503, "Service Unavailable", {}, None)

        self.assert_nothing_saved(fail, "HTTP 503")

    def test_network_failure_is_reported(self):
        def fail(_request, timeout=None):
            raise urllib.error.URLError("no route to host")

        self.assert_nothing_saved(fail, "no route to host")

    def test_url_scheme_is_checked(self):
        with self.assertRaises(UsageError):
            stamping.post_request("file:///etc/hosts", b"x", 1)
        code, _, err = self.run_stamp(FakeAuthority(), "--tsa-url", "ftp://x/y")
        self.assertEqual(code, 2)

    def test_existing_token_is_kept_without_force(self):
        token = self.write("m.tsr", b"my old token")
        fake = FakeAuthority()
        code, _, err = self.run_stamp(fake)
        self.assertEqual(code, 1)
        self.assertIn("already exists", err)
        self.assertEqual(token.read_bytes(), b"my old token")
        self.assertEqual(fake.requests, [])

    def test_custom_output_names(self):
        code, out, _ = self.run_stamp(FakeAuthority(), "--out", self.temp / "other" / "x.tsr")
        self.assertEqual(code, 0)
        self.assertTrue((self.temp / "other" / "x.tsr").is_file())
        self.assertTrue((self.temp / "other" / "x.tsq").is_file())
        self.assertIn("--token", out)

    def test_missing_manifest_is_a_usage_error(self):
        code, _, err = self.run_stamp(FakeAuthority(), "--out", self.temp / "t.tsr")
        self.assertEqual(code, 0, err)
        self.manifest = self.temp / "gone.txt"
        code, _, _ = self.run_stamp(FakeAuthority())
        self.assertEqual(code, 2)

    def test_stamped_token_verifies_with_the_right_root(self):
        fake = FakeAuthority()
        self.run_stamp(fake)
        root = self.write("root.der", fake.authority.root)
        self.write("work/a.txt")
        code, out, _ = run_cli("verify", self.manifest, "--skip-files", "--ca", root)
        self.assertEqual(code, 3, out)
        self.assertIn("[PASS] Certificate chain", out)
        self.assertIn("[PASS] Token answers the saved request", out)

    def test_only_this_module_uses_the_network(self):
        with mock.patch("evidence_seal.stamping._open_url", side_effect=AssertionError("network used")):
            self.assertEqual(run_cli("show", LOCAL / "token-rsa.tsr")[0], 0)
            self.assertEqual(run_cli("verify", self.manifest, "--skip-files")[0], 3)
            self.assertEqual(run_cli("seal", self.temp, "--purpose", "p", "--out", self.temp / "n" / "m.txt")[0], 0)
            with self.assertRaises(AssertionError):
                stamping.post_request("https://x/", b"", 1)


class ShowCommand(TempFolderTestCase):
    def test_reads_tokens(self):
        code, out, _ = run_cli("show", LOCAL / "token-ec.tsr")
        self.assertEqual(code, 0)
        self.assertIn("existed by", out)
        code, out, _ = run_cli("show", LOCAL / "token-bare.tst")
        self.assertEqual(code, 0)
        self.assertIn("bare token", out)

    def test_json(self):
        code, out, _ = run_cli("show", LOCAL / "token-rsa.tsr", "--json")
        data = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(data["policy"], "1.2.3.4.1")
        self.assertEqual(data["hash_algorithm"], "SHA-256")
        self.assertEqual(len(data["certificates"]), 2)

    def test_rejection_exits_non_zero(self):
        path = self.write("r.tsr", forge.rejection())
        code, out, _ = run_cli("show", path)
        self.assertEqual(code, 1)
        self.assertIn("proves nothing", out)

    def test_junk_and_missing_files(self):
        path = self.write("j.tsr", b"not a token")
        code, _, err = run_cli("show", path)
        self.assertEqual(code, 1)
        self.assertIn("could not be read", err)
        self.assertEqual(run_cli("show", self.temp / "none.tsr")[0], 2)


class _TagCounter(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.text = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)

    def handle_data(self, data):
        self.text.append(data)


class Report(TempFolderTestCase):
    def setUp(self):
        super().setUp()
        self.folder, self.manifest = self.copy_sample()
        self.manifest.with_suffix(".tsr").write_bytes((LOCAL / "token-rsa.tsr").read_bytes())
        self.ca = LOCAL / "root-rsa.crt"

    def report(self, *extra):
        return run_cli("report", self.manifest, "--out", "-", "--ca", self.ca, *extra)

    def test_text_report_for_a_good_seal(self):
        code, out, _ = self.report()
        self.assertEqual(code, 0, out)
        for phrase in (
            "RESULT: VERIFIED",
            "Synthetic test folder",
            "Files listed: 4, 373 bytes",
            "[PASS] Files match the manifest",
            "[PASS] Signature is valid",
            "Policy: 1.2.3.4.1",
            "Hash algorithm: SHA-256",
            "openssl ts -verify -data sample-manifest.txt -in sample-manifest.tsr -CAfile root-rsa.crt",
            "Who wrote the files",
            "not legal advice",
            "continued credibility",
            "revocation",
        ):
            self.assertIn(phrase, out)

    def test_report_is_about_one_page(self):
        _, out, _ = self.report()
        self.assertLess(len(out.splitlines()), 70)

    def test_report_leaks_no_absolute_paths(self):
        _, out, _ = self.report()
        self.assertNotIn(str(self.temp), out)

    def test_failed_seal_says_so_first(self):
        (self.folder / "notes.txt").write_bytes(b"changed")
        code, out, _ = self.report()
        self.assertEqual(code, 1)
        self.assertIn("RESULT: FAILED", out)
        self.assertIn("[FAIL] Files match the manifest", out)
        self.assertNotIn("RESULT: VERIFIED", out)

    def test_hash_mismatch_says_what_it_does_and_does_not_mean(self):
        phrase = "not by itself proof of tampering"
        self.assertNotIn(phrase, run_cli("verify", self.manifest, "--ca", self.ca)[1])
        self.manifest.write_bytes(self.manifest.read_bytes().replace(b"\n", b"\r\n"))
        code, out, _ = run_cli("verify", self.manifest, "--ca", self.ca)
        self.assertEqual(code, 1)
        self.assertIn("[FAIL] Token covers this manifest", out)
        self.assertIn("RESULT: FAILED", out)
        self.assertIn(phrase, out)
        self.assertIn(phrase, self.report()[1])
        self.assertIn(phrase, self.report("--format", "html")[1])

    def test_incomplete_seal_is_not_called_verified(self):
        code, out, _ = run_cli("report", self.manifest, "--out", "-")
        self.assertEqual(code, 3)
        self.assertIn("RESULT: INCOMPLETE", out)
        self.assertIn("This is not a pass", out)
        self.assertNotIn("Every check passed", out)
        self.assertIn("authority-root.crt", out)

    def test_report_with_no_token_says_so(self):
        self.manifest.with_suffix(".tsr").unlink()
        code, out, _ = run_cli("report", self.manifest, "--out", "-")
        self.assertEqual(code, 3)
        self.assertIn("none found", out)
        self.assertNotIn("openssl ts -verify", out)

    def test_html_report_escapes_everything_it_quotes(self):
        hostile = "<script>alert(1)</script> & 'quotes'"
        rows = [("a.txt", "0" * 64, 1)]
        path = self.write("h.txt", manifest.render(rows, hostile, "2026-01-01", "x"))
        code, out, _ = run_cli("report", path, "--format", "html", "--out", "-")
        self.assertNotIn("<script>", out)
        self.assertIn("&lt;script&gt;", out)
        parser = _TagCounter()
        parser.feed(out)
        self.assertNotIn("script", parser.tags)
        self.assertIn(hostile, "".join(parser.text))
        self.assertTrue(out.startswith("<!doctype html>"))
        self.assertNotIn("http://", out.split("</style>")[0])

    def test_html_report_has_the_same_verdict(self):
        code, out, _ = self.report("--format", "html")
        self.assertEqual(code, 0)
        self.assertIn("Result: VERIFIED", out)
        self.assertIn("openssl ts -verify", out)
        (self.folder / "notes.txt").write_bytes(b"changed")
        code, out, _ = self.report("--format", "html")
        self.assertEqual(code, 1)
        self.assertIn("Result: FAILED", out)
        self.assertNotIn("Result: VERIFIED", out)

    def test_written_to_a_file_beside_the_manifest(self):
        code, out, _ = run_cli("report", self.manifest, "--ca", self.ca)
        self.assertEqual(code, 0)
        target = self.manifest.with_suffix(".report.txt")
        self.assertIn("RESULT: VERIFIED", target.read_text(encoding="utf-8"))
        self.assertIn("Result: VERIFIED", out)
        code, _, err = run_cli("report", self.manifest, "--ca", self.ca)
        self.assertEqual(code, 1)
        self.assertIn("already exists", err)
        self.assertEqual(run_cli("report", self.manifest, "--ca", self.ca, "--force")[0], 0)
        self.assertEqual(run_cli("report", self.manifest, "--ca", self.ca, "--format", "html")[0], 0)
        self.assertTrue(self.manifest.with_suffix(".report.html").is_file())

    def test_bare_token_commands_say_so(self):
        self.manifest.with_suffix(".tsr").unlink()
        bare = self.write("bare.tst", (LOCAL / "token-bare.tst").read_bytes())
        _, out, _ = run_cli("report", self.manifest, "--token", bare, "--ca", self.ca, "--out", "-")
        self.assertIn("-in bare.tst -token_in", out)

    def test_paths_with_spaces_are_quoted(self):
        renamed = self.temp / "my manifest.txt"
        self.manifest.rename(renamed)
        self.manifest.with_suffix(".tsr").rename(renamed.with_suffix(".tsr"))
        _, out, _ = run_cli(
            "report", renamed, "--folder", self.folder, "--ca", self.ca, "--out", "-", "--skip-files"
        )
        self.assertIn('-data "my manifest.txt" -in "my manifest.tsr"', out)

    def _commands(self, report_text):
        return [line.strip() for line in report_text.splitlines() if line.strip().startswith("openssl ts -")]

    @requires_openssl
    def test_the_printed_commands_really_work(self):
        code, out, _ = self.report()
        self.assertEqual(code, 0)
        shutil.copyfile(self.ca, self.temp / self.ca.name)
        commands = self._commands(out)
        self.assertGreaterEqual(len(commands), 3)
        program = openssl_bridge.find_openssl()
        verified = 0
        for command in commands:
            parts = shlex.split(command)
            done = subprocess.run([program] + parts[1:], capture_output=True, text=True, cwd=str(self.temp))
            self.assertEqual(done.returncode, 0, f"{command}\n{done.stdout}\n{done.stderr}")
            if "-verify" in parts:
                self.assertIn("Verification: OK", done.stdout)
                verified += 1
        self.assertEqual(verified, 2)
        fingerprint = [line.strip() for line in out.splitlines() if "-fingerprint" in line][0]
        done = subprocess.run(
            [program] + shlex.split(fingerprint)[1:], capture_output=True, text=True, cwd=str(self.temp)
        )
        self.assertEqual(done.returncode, 0, done.stderr)
        printed = done.stdout.split("=")[-1].strip().replace(":", "").lower()
        self.assertIn(printed, out)

    @requires_openssl
    def test_openssl_flag_reports_its_own_answer(self):
        code, out, _ = run_cli("verify", self.manifest, "--ca", self.ca, "--openssl")
        self.assertEqual(code, 0, out)
        self.assertIn("[PASS] openssl ts -verify agrees", out)

    @requires_openssl
    def test_extra_certificates_in_a_path_with_spaces(self):
        folder = self.temp / "a folder, with spaces"
        folder.mkdir()
        extra = folder / "my tsa.crt"
        shutil.copyfile(LOCAL / "tsa-rsa.crt", extra)
        token = folder / "no certs.tsr"
        shutil.copyfile(LOCAL / "token-nocerts.tsr", token)
        shutil.copyfile(self.ca, folder / self.ca.name)
        shutil.copyfile(self.manifest, folder / self.manifest.name)
        arguments = (self.manifest, "--skip-files", "--token", token, "--ca", self.ca, "--untrusted", extra)
        code, out, _ = run_cli("verify", *arguments, "--openssl")
        self.assertEqual(code, 3, out)
        self.assertIn("[PASS] openssl ts -verify agrees", out)
        self.assertNotIn("[FAIL]", out)
        _, out, _ = run_cli("report", *arguments, "--out", "-")
        command = [line.strip() for line in out.splitlines() if "-untrusted" in line][0]
        self.assertIn("-untrusted extra-1.crt", command)
        self.assertIn("First copy my tsa.crt to extra-1.crt", out)
        shutil.copyfile(extra, folder / "extra-1.crt")
        program = openssl_bridge.find_openssl()
        done = subprocess.run([program] + shlex.split(command)[1:], capture_output=True, text=True, cwd=str(folder))
        self.assertIn("Verification: OK", done.stdout, done.stderr)

    def test_openssl_flag_without_openssl_is_not_a_pass(self):
        with mock.patch("evidence_seal.openssl_bridge.find_openssl", return_value=None):
            code, out, _ = run_cli("verify", self.manifest, "--ca", self.ca, "--openssl")
        self.assertEqual(code, 3)
        self.assertIn("[NOT CHECKED] openssl ts -verify agrees", out)


if __name__ == "__main__":
    unittest.main()
