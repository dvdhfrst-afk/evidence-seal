"""Files from someone who wants to mislead the reader or break the tool."""

import hashlib
import html.parser
import json
import random
import time
from unittest import mock

from evidence_seal import chain, cli, der, manifest, reporting, scan, showing, signatures, verification
from evidence_seal.errors import EvidenceSealError
from evidence_seal.text import printable
from evidence_seal.trust import TrustStore
from evidence_seal.x509 import Certificate
from tests import forge
from tests.support import LOCAL, SAMPLE_MANIFEST, TempFolderTestCase, run_cli

FAKE_RESULT = "x\nRESULT: VERIFIED\nEvery check passed."


def native_manifest(purpose="p", folder="work", paths=(("a.txt", b"a\n"),)):
    rows = [(path, hashlib.sha256(data).hexdigest(), len(data)) for path, data in paths]
    return manifest.render(rows, purpose, "2026-01-02", folder)


class Spoofing(TempFolderTestCase):
    def pair(self, purpose=FAKE_RESULT):
        self.write("work/a.txt", b"a\n")
        return self.write("m.txt", native_manifest(purpose))

    def lines_of(self, text):
        return text.splitlines()

    def test_a_purpose_cannot_fake_the_result_line(self):
        path = self.pair()
        code, out, _ = run_cli("verify", path)
        self.assertEqual(code, 3)
        results = [line for line in self.lines_of(out) if line.startswith("RESULT:")]
        self.assertEqual(results, ["RESULT: INCOMPLETE"])
        self.assertIn("\\x0aRESULT: VERIFIED", out)

    def test_a_purpose_cannot_fake_the_result_in_a_report(self):
        path = self.pair()
        code, out, _ = run_cli("report", path, "--out", "-")
        self.assertEqual(code, 3)
        results = [line for line in self.lines_of(out) if line.startswith("RESULT:")]
        self.assertEqual(results, ["RESULT: INCOMPLETE"])

    def test_terminal_codes_and_direction_tricks_are_shown_as_escapes(self):
        for text, shown in (
            ("\x1b[2J\x1b[32mVERIFIED", "\\x1b[2J"),
            ("evil\u202egnp.exe", "\\u202e"),
            ("a\u2028b", "\\u2028"),
            ("a\u0085b", "\\x85"),
            ("a\rRESULT", "\\x0d"),
            ("name\udcff", "\\xff"),
        ):
            with self.subTest(shown):
                self.assertIn(shown, printable(text))
                self.assertTrue(printable(text).isascii())
        self.assertEqual(printable("caf\u00e9 \u6f22\u5b57 \U0001f600"), "caf\u00e9 \u6f22\u5b57 \U0001f600")

    def test_every_output_form_is_free_of_control_characters(self):
        path = self.pair("\x1b[31mred\x07\nline")
        for arguments in (("verify", path), ("report", path, "--out", "-"), ("report", path, "--format", "html", "--out", "-")):
            with self.subTest(arguments):
                _, out, _ = run_cli(*arguments)
                self.assertNotIn("\x1b", out)
                self.assertNotIn("\x07", out)

    def test_json_keeps_the_exact_value_safely(self):
        path = self.pair("\x1b[31m\nline")
        _, out, _ = run_cli("verify", path, "--json")
        self.assertTrue(out.isascii())
        self.assertEqual(json.loads(out)["manifest"]["purpose"], "\x1b[31m\nline")

    def test_file_names_in_a_folder_cannot_inject_lines(self):
        folder = self.write("work/a.txt", b"a\n").parent
        path = self.write("m.txt", native_manifest(paths=(("a.txt", b"a\n"), ("b\nRESULT: VERIFIED", b"b\n"))))
        code, out, _ = run_cli("verify", path, "--folder", folder)
        self.assertEqual(code, 1)
        self.assertEqual([line for line in out.splitlines() if line.startswith("RESULT:")], ["RESULT: FAILED"])

    def test_token_text_cannot_inject_lines(self):
        authority = forge.Authority("show\nRESULT: VERIFIED", seed=55)
        data = authority.token(b"data")
        facts = showing.describe(data)
        text = showing.render_text(facts)
        self.assertFalse(any(line.startswith("RESULT:") for line in text.splitlines()))

    def test_html_report_escapes_everything(self):
        path = self.pair("<script>alert(1)</script><img src=x onerror=y>")
        code, out, _ = run_cli("report", path, "--format", "html", "--out", "-")
        self.assertEqual(code, 3)
        self.assertNotIn("<script>", out)
        self.assertNotIn("<img", out)

        class Tags(html.parser.HTMLParser):
            seen = set()

            def handle_starttag(self, tag, attrs):
                self.seen.add(tag)

        Tags().feed(out)
        self.assertEqual(Tags.seen - {"html", "head", "meta", "title", "style", "body", "h1", "h2", "p", "table", "tr", "th", "td", "span", "ul", "li", "ol", "code"}, set())

    def test_report_commands_never_carry_a_name_a_shell_would_act_on(self):
        token = LOCAL / "token-rsa.tsr"
        for name in ("a&calc.txt", "a;id.txt", "$(id).txt", "`id`.txt", "a|b.txt", "%PATH%.txt", "a'b.txt", "!x.txt"):
            with self.subTest(name):
                steps = reporting.openssl_commands(
                    self.sample_outcome(token), reporting.ReportContext(name, name.replace(".txt", ".tsr"), None)
                )
                commands = " ".join(command for _, command in steps)
                self.assertNotIn(name, commands)
                self.assertIn("manifest.txt", commands)
                self.assertIn(name, steps[0][0])

    def sample_outcome(self, token):
        return verification.verify(
            verification.VerifyOptions(SAMPLE_MANIFEST, token_path=token, skip_files=True)
        )

    def test_ordinary_names_stay_as_they_are(self):
        self.assertEqual(reporting.quote_argument("plain-name_1.txt"), "plain-name_1.txt")
        self.assertEqual(reporting.quote_argument("my work (2).txt"), '"my work (2).txt"')
        self.assertEqual(reporting.quote_argument("caf\u00e9.txt"), '"caf\u00e9.txt"')


class PathTraversal(TempFolderTestCase):
    def test_entries_outside_the_folder_are_never_opened(self):
        secret = self.write("secret.txt", b"secret\n")
        folder = self.write("work/a.txt", b"a\n").parent
        digest = hashlib.sha256(b"secret\n").hexdigest()
        lines = [
            f"{digest}  ../secret.txt",
            f"{digest}  ..\\secret.txt",
            f"{digest}  {secret}",
            f"{digest}  {secret.as_posix()}",
            f"{digest}  sub/../../secret.txt",
        ]
        path = self.write("work/hand.txt", "\n".join(lines).encode())
        opened = []
        original = scan.hash_file

        def watching(target, algorithm, meter=None):
            opened.append(str(target))
            return original(target, algorithm, meter)

        with mock.patch("evidence_seal.scan.hash_file", watching):
            code, text, _ = run_cli("verify", path, "--folder", folder, "--allow-added", "--json")
        self.assertEqual(code, 1)
        self.assertFalse([name for name in opened if "secret" in name], opened)
        data = json.loads(text)
        self.assertEqual(data["differences"]["unchanged"], 0)

    def test_folder_name_in_a_manifest_cannot_point_elsewhere(self):
        self.write("work/a.txt")
        for name in ("..", ".", "../..", "/", "C:", "C:\\Windows", "a/../..", "\\\\server\\share"):
            with self.subTest(name):
                path = self.write("m.txt", native_manifest(folder=name))
                code, text, _ = run_cli("verify", path, "--json")
                data = json.loads(text)
                self.assertEqual(data["folder"], None, name)
                self.assertEqual(data["files"]["status"], "not checked")

    def test_hand_made_entry_cannot_read_through_a_folder_name(self):
        self.write("outside.txt", b"x")
        folder = self.write("work/a.txt", b"a\n").parent
        path = self.write("work/hand.txt", (hashlib.sha256(b"x").hexdigest() + "  a.txt/../../outside.txt\n").encode())
        code, text, _ = run_cli("verify", path, "--folder", folder, "--allow-added", "--json")
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(text)["differences"]["missing"], ["a.txt/../../outside.txt"])


class BrokenNumbersAndFormats(TempFolderTestCase):
    def test_strange_numbers_do_not_crash(self):
        digest = "a" * 64
        for body in (
            f"files: \u00b2\ntotal-bytes: 1\n\n",
            f"files: {'9' * 5000}\ntotal-bytes: 1\n\n",
            f"files: 1\ntotal-bytes: 1\n\n{digest}  {'9' * 5000}  a.txt\n",
            f"files: 1\ntotal-bytes: 1\n\n{digest}  \u0663  a.txt\n",
        ):
            with self.subTest(body[:30]):
                raw = (manifest.MAGIC + "\nalgorithm: sha256\n" + body).encode("utf-8")
                self.assertTrue(manifest.parse(raw).problems)
        parsed = manifest.parse(f"{digest}  {'9' * 5000}  a.txt\n".encode())
        self.assertEqual(len(parsed.entries), 1)

    def test_a_utf16_list_from_powershell_is_read(self):
        digest = hashlib.sha256(b"a\n").hexdigest()
        text = f"{digest}  a.txt\r\n"
        for raw in (b"\xff\xfe" + text.encode("utf-16-le"), b"\xfe\xff" + text.encode("utf-16-be")):
            parsed = manifest.parse(raw)
            self.assertEqual([entry.path for entry in parsed.entries], ["a.txt"])

    def test_encodings_that_are_not_utf8_do_not_crash(self):
        digest = hashlib.sha256(b"a\n").hexdigest()
        for raw in (
            f"{digest}  caf\u00e9.txt\n".encode("latin-1"),
            b"\xff\xfe\x00",
            b"\xfe\xff\x00",
            b"\xef\xbb\xbf" + f"{digest}  a.txt\n".encode(),
            manifest.MAGIC.encode() + b"\n\xff\xfe\n",
            b"\x00" * 100,
        ):
            with self.subTest(raw[:8]):
                folder = self.write("work/a.txt", b"a\n").parent
                path = self.write("work/hand.txt", raw)
                code, _, err = run_cli("verify", path, "--folder", folder, "--allow-added")
                self.assertIn(code, (1, 3), err)

    def test_oversized_files_are_refused_before_reading_them_whole(self):
        path = self.write("big.tsr", b"\0" * 1024)
        with mock.patch.object(cli, "MAX_SIDE_FILE_BYTES", 100):
            code, _, err = run_cli("show", path)
        self.assertEqual(code, 2)
        self.assertIn("too large", err)
        with self.assertRaises(EvidenceSealError):
            manifest.read_limited(path, "manifest", 100)

    def test_huge_rsa_keys_are_refused_quickly(self):
        huge = (1 << 20000) + 1
        for n, e in ((huge, 65537), ((1 << 2048) + 1, (1 << 4000) + 1)):
            key = der.encode_seq(der.encode_int(n), der.encode_int(e))
            spki = der.encode_seq(
                der.encode_seq(der.encode_oid(signatures.oids.RSA_ENCRYPTION), der.encode_null()),
                der.encode_bits(key),
            )
            started = time.monotonic()
            with self.assertRaises(EvidenceSealError):
                signatures.parse_public_key(spki)
            self.assertLess(time.monotonic() - started, 2)

    def test_many_certificates_with_one_name_cannot_take_forever(self):
        authority = forge.Authority("crowd", seed=66)
        decoys = [
            Certificate(
                forge.make_certificate(
                    authority.root_name, forge.EcKey(1000 + index), authority.root_name, forge.EcKey(1000 + index),
                    serial=index + 1, extensions=forge.CA_EXTENSIONS,
                )
            )
            for index in range(100)
        ]
        calls = []
        original = signatures.verify

        def counting(*args):
            calls.append(1)
            return original(*args)

        signer = Certificate(authority.signer)
        with mock.patch("evidence_seal.signatures.verify", counting):
            chain.validate(signer, decoys, TrustStore(), forge.TOKEN_TIME)
        self.assertLessEqual(len(calls), chain.MAX_SIGNATURE_CHECKS)

    def test_exclude_patterns_cannot_hang_the_walk(self):
        rules = scan.Excludes(["*a*a*a*a*a*a*a*a*a*a*a*a*b", "**/**/**/**/**/**/x/**/**/y"])
        started = time.monotonic()
        rules.matches("a" * 2000)
        rules.matches("/".join("a" * 5 for _ in range(200)))
        self.assertLess(time.monotonic() - started, 3)


class Fuzz(TempFolderTestCase):
    """Random damage must end in a verdict or a plain error, and never in a bug report or a pass."""

    def mutated(self, data, rng):
        data = bytearray(data)
        kind = rng.randrange(4)
        if kind == 0:
            for _ in range(rng.randint(1, 8)):
                data[rng.randrange(len(data))] = rng.randrange(256)
        elif kind == 1:
            del data[rng.randrange(len(data)) :]
        elif kind == 2:
            start = rng.randrange(len(data))
            data[start:start] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 64)))
        else:
            start = rng.randrange(len(data))
            del data[start : start + rng.randint(1, 64)]
        return bytes(data)

    def test_damaged_tokens(self):
        rng = random.Random(20261107)
        original = (LOCAL / "token-ec.tsr").read_bytes()
        manifest_path = self.write("m.txt", (LOCAL / "token-ec.tsq").read_bytes()[:0] + b"not the covered text\n")
        root = LOCAL / "root-ec.crt"
        for _ in range(120):
            damaged = self.mutated(original, rng)
            token = self.write("t.tsr", damaged)
            code, _, err = run_cli("verify", manifest_path, "--token", token, "--ca", root, "--skip-files")
            self.assertIn(code, (1, 3), err)
            code, _, err = run_cli("show", token)
            self.assertIn(code, (0, 1), err)
            self.assertNotIn("bug in evidence-seal", err)

    def test_damaged_certificates(self):
        rng = random.Random(7)
        original = (LOCAL / "root-rsa.crt").read_bytes()
        manifest_path = self.write("m.txt", b"text\n")
        for _ in range(120):
            cert = self.write("c.crt", self.mutated(original, rng))
            code, _, err = run_cli("verify", manifest_path, "--ca", cert, "--skip-files")
            self.assertIn(code, (2, 3), err)
            self.assertNotIn("bug in evidence-seal", err)

    def test_damaged_manifests(self):
        rng = random.Random(11)
        original = SAMPLE_MANIFEST.read_bytes()
        folder = self.write("work/a.txt", b"a\n").parent
        for _ in range(300):
            path = self.write("m.txt", self.mutated(original, rng))
            code, _, err = run_cli("verify", path, "--folder", folder)
            self.assertIn(code, (1, 3), err)
            self.assertNotIn("bug in evidence-seal", err)

    def test_damaged_exclude_files(self):
        rng = random.Random(13)
        original = b"# comment\n*.tmp\nbuild/\n!build/keep.txt\n**/x\n[a-\n"
        folder = self.write("work/a.txt", b"a\n").parent
        for _ in range(100):
            rules = self.write("rules.txt", self.mutated(original, rng))
            code, _, err = run_cli("seal", folder, "--dry-run", "--exclude-from", rules)
            self.assertIn(code, (0, 1, 2), err)
            self.assertNotIn("bug in evidence-seal", err)
