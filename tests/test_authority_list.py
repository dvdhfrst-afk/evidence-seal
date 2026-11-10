"""The authority list: its file, its commands, and the trust verify and report take from it."""

import json
import os
from unittest import mock

from evidence_seal import authorities
from evidence_seal.trust import Authority
from evidence_seal.x509 import Certificate, load_certificates
from tests import forge
from tests.support import LOCAL, HomeTestCase, run_cli

ROOT_EC = LOCAL / "root-ec.crt"
ROOT_RSA = LOCAL / "root-rsa.crt"
URL = "http://tsa.example.test/tsr"


def fingerprint(path):
    return load_certificates(path)[0].sha256


class ListFile(HomeTestCase):
    def list_file(self):
        return self.home / "authorities.json"

    def write_list(self, document):
        self.home.mkdir(parents=True, exist_ok=True)
        data = document if isinstance(document, bytes) else json.dumps(document).encode("utf-8")
        self.list_file().write_bytes(data)
        return data

    def test_an_empty_home_lists_only_the_built_ins(self):
        code, out, err = run_cli("authority", "list")
        self.assertEqual(code, 0, err)
        self.assertIn("FreeTSA", out)
        self.assertIn("built in", out)
        self.assertFalse(self.home.exists(), "listing writes nothing")

    def test_round_trip(self):
        code, out, err = run_cli("authority", "add", "example", URL, "--root", ROOT_EC, "--policy", "1.2.3.4", "--hash", "sha384", "--note", "terms on paper")
        self.assertEqual(code, 0, err)
        self.assertIn(fingerprint(ROOT_EC), out)
        self.assertIn("channel you trust", out)
        stored = json.loads(self.list_file().read_text(encoding="utf-8"))
        self.assertEqual(stored["format"], 1)
        entry = stored["authorities"][0]
        self.assertEqual(
            {key: entry[key] for key in ("name", "url", "policy", "hash", "note", "test")},
            {"name": "example", "url": URL, "policy": "1.2.3.4", "hash": "sha384", "note": "terms on paper", "test": False},
        )
        self.assertRegex(entry["added"], r"^\d{4}-\d{2}-\d{2}$")
        copy = self.home / "authorities" / f"{fingerprint(ROOT_EC)}.pem"
        self.assertEqual(Certificate(load_certificates(copy)[0].raw).sha256, fingerprint(ROOT_EC))
        code, out, _ = run_cli("authority", "show", "EXAMPLE", "--json")
        self.assertEqual(code, 0)
        shown = json.loads(out)
        self.assertEqual(shown["roots"][0]["sha256"], fingerprint(ROOT_EC))
        self.assertRegex(shown["roots"][0]["valid_to"], r"^\d{4}-\d{2}-\d{2}$")
        self.assertFalse(shown["builtin"])
        code, out, _ = run_cli("authority", "list", "--json")
        self.assertEqual([item["name"] for item in json.loads(out)["authorities"]], ["FreeTSA", "example"])

    def test_show_in_text(self):
        run_cli("authority", "add", "example", URL, "--root", ROOT_EC)
        code, out, _ = run_cli("authority", "show", "example")
        self.assertEqual(code, 0)
        for phrase in ("URL: " + URL, "Policy: the authority chooses", fingerprint(ROOT_EC), "valid "):
            self.assertIn(phrase, out)
        code, out, _ = run_cli("authority", "show", "freetsa")
        self.assertIn("Terms of use: https://freetsa.org/freetsa.html", out)
        self.assertIn("built in by fingerprint only", out)
        self.assertEqual(run_cli("authority", "show", "nobody")[0], 2)

    def test_damaged_file_is_named_and_left_alone(self):
        for label, data in (
            ("not json", b"{not json"),
            ("not utf-8", b'{"format": 1, "authorities": [], "x": "\xff"}'),
            ("not an object", b"[1, 2]"),
            ("no format", b'{"authorities": []}'),
            ("format text", b'{"format": "1"}'),
            ("format true", b'{"format": true}'),
            ("format zero", b'{"format": 0}'),
            ("huge number", b'{"format": ' + b"9" * 100000 + b"}"),
            ("deep nesting", b'{"format": 1, "x": ' + b"[" * 100000 + b"]" * 100000 + b"}"),
            ("authorities not a list", b'{"format": 1, "authorities": {}}'),
            ("entry not an object", b'{"format": 1, "authorities": [3]}'),
        ):
            with self.subTest(label):
                self.write_list(data)
                for command in (("authority", "list"), ("authority", "add", "x", URL)):
                    code, _, err = run_cli(*command)
                    self.assertEqual(code, 2, err)
                    self.assertIn(str(self.list_file()), err)
                    self.assertIn("damaged", err)
                    self.assertNotIn("Traceback", err)
                self.assertEqual(self.list_file().read_bytes(), data)

    def test_a_newer_format_is_refused_and_never_rewritten(self):
        data = self.write_list({"format": 2, "authorities": [{"anything": "new"}]})
        for command in (("authority", "list"), ("authority", "add", "x", URL), ("authority", "remove", "x")):
            code, _, err = run_cli(*command)
            self.assertEqual(code, 2)
            self.assertIn("uses format 2", err)
            self.assertIn("left unchanged", err)
        self.assertEqual(self.list_file().read_bytes(), data)

    def test_a_huge_file_is_refused_without_reading_it(self):
        self.write_list(b'{"format": 1, "authorities": [' + b" " * (authorities.MAX_LIST_BYTES + 1) + b"]}")
        code, _, err = run_cli("authority", "list")
        self.assertEqual(code, 2)
        self.assertIn("too large", err)

    def entry(self, **changes):
        item = {"name": "hand", "url": URL, "roots": [], "policy": None, "hash": "sha256", "note": "", "test": False, "added": "2026-01-01"}
        item.update(changes)
        return item

    def test_hostile_entries_are_damage(self):
        missing = "a" * 64
        cases = {
            "path in name": self.entry(name="../../outside"),
            "built-in name": self.entry(name="freetsa"),
            "long name": self.entry(name="n" * 49),
            "control in name": self.entry(name="a\nb"),
            "bad url": self.entry(url="file:///etc/passwd"),
            "huge url": self.entry(url="http://example.test/" + "a" * 5000),
            "bad policy": self.entry(policy="1.2.abc"),
            "weak hash": self.entry(hash="sha1"),
            "note not text": self.entry(note=["x"]),
            "test not a flag": self.entry(test="yes"),
            "bad date": self.entry(added="soon"),
            "root not hex": self.entry(roots=[{"sha256": "../../../x"}]),
            "root copy missing": self.entry(roots=[{"sha256": missing}]),
            "too many roots": self.entry(roots=[{"sha256": missing}] * (authorities.MAX_ROOTS + 1)),
        }
        for label, item in cases.items():
            with self.subTest(label):
                self.write_list({"format": 1, "authorities": [item]})
                code, _, err = run_cli("authority", "list")
                self.assertEqual(code, 2, err)
                self.assertIn("damaged", err)
                self.assertNotIn("\n", err.strip(), "one plain line")
        self.write_list({"format": 1, "authorities": [self.entry(), self.entry(name="HAND")]})
        self.assertIn("used twice", run_cli("authority", "list")[2])

    def test_a_stored_root_that_was_swapped_is_damage(self):
        run_cli("authority", "add", "example", URL, "--root", ROOT_EC)
        copy = self.home / "authorities" / f"{fingerprint(ROOT_EC)}.pem"
        copy.write_bytes(ROOT_RSA.read_bytes())
        code, _, err = run_cli("authority", "list")
        self.assertEqual(code, 2)
        self.assertIn("does not match its fingerprint", err)
        copy.write_bytes(b"garbage")
        self.assertIn("cannot be read", run_cli("authority", "list")[2])

    def test_unknown_keys_are_ignored_and_hand_written_entries_work(self):
        self.write_list({"format": 1, "comment": "mine", "authorities": [self.entry(extra=1)]})
        code, out, err = run_cli("authority", "list")
        self.assertEqual(code, 0, err)
        self.assertIn("hand", out)


class Commands(HomeTestCase):
    def test_hostile_and_bad_names_change_nothing(self):
        for name in ("../x", "a/b", "a\\b", "", "-x", ".x", "x" * 49, "na me", "caf" + chr(0xE9), "a\nb", "FreeTSA", "freetsa"):
            with self.subTest(repr(name)):
                code, _, err = run_cli("authority", "add", name, URL)
                self.assertEqual(code, 2, err)
                self.assertNotIn("Traceback", err)
        self.assertFalse((self.home / "authorities.json").exists())

    def test_bad_arguments_change_nothing(self):
        cases = (
            (URL, "--policy", "abc"),
            (URL, "--policy", "9.1"),
            (URL, "--hash", "sha1"),
            (URL, "--hash", "md5"),
            (URL, "--hash", "nonsense"),
            (URL, "--note", "two\nlines"),
            (URL, "--note", "x" * 501),
            ("ftp://example.test/",),
            ("http://",),
            ("http://exa mple.test/",),
            (URL, "--root", LOCAL / "tsa-ec.crt"),
            (URL, "--root", LOCAL / "missing.crt"),
            (URL, "--root", LOCAL / "token-ec.tsr"),
        )
        for extra in cases:
            with self.subTest(extra):
                code, _, err = run_cli("authority", "add", "x", *extra)
                self.assertEqual(code, 2, err)
                self.assertNotIn("Traceback", err)
        self.assertFalse((self.home / "authorities.json").exists())
        self.assertIn("not a root", run_cli("authority", "add", "x", URL, "--root", LOCAL / "tsa-ec.crt")[2])

    def test_roots_that_cannot_anchor_are_refused(self):
        key = forge.EcKey(901)
        not_ca = self.write("not-ca.der", forge.make_certificate("TEST ONLY leaf", key, "TEST ONLY leaf", key))
        root = forge.Authority("bad signature", seed=91).root
        broken = self.write("broken.der", root[:-8] + bytes(8))
        no_sign = self.write(
            "no-sign.der",
            forge.make_certificate("TEST ONLY nosign", key, "TEST ONLY nosign", key, extensions=(forge.basic_constraints(True), forge.key_usage([0]))),
        )
        huge = self.write("huge.pem", b"x" * (authorities.MAX_ROOT_FILE_BYTES + 1))
        for path, phrase in (
            (not_ca, "not marked as a certificate authority"),
            (broken, "does not verify against its own key"),
            (no_sign, "not allowed to sign certificates"),
            (huge, "too large"),
        ):
            with self.subTest(path.name):
                code, _, err = run_cli("authority", "add", "x", URL, "--root", path)
                self.assertEqual(code, 2, err)
                self.assertIn(phrase, err)

    def test_a_root_on_a_curve_pure_python_does_not_cover_is_accepted(self):
        code, _, err = run_cli("authority", "add", "x", URL, "--root", LOCAL / "root-brainpool.crt")
        self.assertEqual(code, 0, err)

    def test_adding_without_a_root_says_what_stamp_will_do(self):
        code, out, _ = run_cli("authority", "add", "bare", URL)
        self.assertEqual(code, 0)
        self.assertIn("No root is trusted", out)
        self.assertIn("authority trust bare --root FILE", out)
        self.assertEqual(run_cli("authority", "add", "BARE", URL)[0], 2, "names are unique ignoring case")

    def test_built_ins_cannot_be_changed(self):
        for command in (("remove", "FreeTSA"), ("trust", "freetsa", "--root", ROOT_EC), ("untrust", "FreeTSA", "a" * 64)):
            with self.subTest(command[0]):
                code, _, err = run_cli("authority", *command)
                self.assertEqual(code, 2)
                self.assertIn("built in", err)

    def test_trust_untrust_and_remove(self):
        run_cli("authority", "add", "one", URL, "--root", ROOT_EC)
        run_cli("authority", "add", "two", URL, "--root", ROOT_EC)
        code, out, _ = run_cli("authority", "trust", "one", "--root", ROOT_RSA)
        self.assertEqual(code, 0)
        self.assertIn(fingerprint(ROOT_RSA), out)
        code, out, _ = run_cli("authority", "trust", "one", "--root", ROOT_RSA)
        self.assertIn("already trusts", out)
        self.assertEqual(len(authorities.find("one").roots), 2)
        colons = ":".join(fingerprint(ROOT_RSA)[i:i + 2] for i in range(0, 64, 2)).upper()
        code, out, err = run_cli("authority", "untrust", "one", colons)
        self.assertEqual(code, 0, err)
        self.assertIn("1 root left", out)
        self.assertFalse((self.home / "authorities" / f"{fingerprint(ROOT_RSA)}.pem").exists())
        self.assertEqual(run_cli("authority", "untrust", "one", "b" * 64)[0], 2)
        self.assertIn("not a SHA-256 fingerprint", run_cli("authority", "untrust", "one", "abc")[2])
        shared = self.home / "authorities" / f"{fingerprint(ROOT_EC)}.pem"
        self.assertEqual(run_cli("authority", "remove", "one")[0], 0)
        self.assertTrue(shared.exists(), "two still uses it")
        self.assertEqual(run_cli("authority", "remove", "two")[0], 0)
        self.assertFalse(shared.exists())
        self.assertEqual(run_cli("authority", "remove", "two")[0], 2)
        self.assertEqual(run_cli("authority", "trust", "nobody", "--root", ROOT_EC)[0], 2)

    def test_root_writes_the_stored_copies(self):
        run_cli("authority", "add", "one", URL, "--root", ROOT_EC)
        code, out, _ = run_cli("authority", "root", "one")
        self.assertEqual(code, 0)
        self.assertIn("-----BEGIN CERTIFICATE-----", out)
        target = self.temp / "out.pem"
        self.assertEqual(run_cli("authority", "root", "one", "--out", target)[0], 0)
        self.assertEqual(load_certificates(target)[0].sha256, fingerprint(ROOT_EC))
        self.assertEqual(run_cli("authority", "root", "one", "--out", target)[0], 1, "an existing file needs --force")
        self.assertEqual(run_cli("authority", "root", "one", "--out", target, "--force")[0], 0)
        code, _, err = run_cli("authority", "root", "FreeTSA")
        self.assertEqual(code, 1)
        self.assertIn("https://freetsa.org/files/cacert.pem", err)
        self.assertIn("a6379e7c", err)

    def test_too_many_roots_are_refused(self):
        roots = [self.write(f"r{index}.der", forge.Authority(f"r{index}", seed=200 + index).root) for index in range(authorities.MAX_ROOTS + 1)]
        options = [item for path in roots for item in ("--root", path)]
        code, _, err = run_cli("authority", "add", "many", URL, *options)
        self.assertEqual(code, 2)
        self.assertIn(f"at most {authorities.MAX_ROOTS} roots", err)

    def test_store_for_a_built_in_trusts_only_its_fingerprint(self):
        mine = forge.Authority("pinned", seed=95)
        other = forge.Authority("other", seed=96)
        known = Authority("Pinned", URL, URL, URL, Certificate(mine.root).sha256)
        with mock.patch("evidence_seal.trust.KNOWN_AUTHORITIES", (known,)):
            store = authorities.store_for(authorities.find("pinned"))
            self.assertIn("built-in fingerprint for the Pinned root", store.anchor_label(Certificate(mine.root)))
            self.assertIsNone(store.anchor_label(Certificate(other.root)))
            self.assertTrue(store.explicit)
            self.assertEqual(store.named_roots, "the roots listed for Pinned")


class TrustInVerify(HomeTestCase):
    def setUp(self):
        super().setUp()
        self.forged = forge.Authority("listed", seed=97)
        self.manifest = self.write("m.txt", b"bytes of a manifest\n")
        self.write("m.tsr", self.forged.token(self.manifest.read_bytes()))
        self.root = self.write("listed-root.der", self.forged.root)

    def verify(self, *extra):
        code, out, _ = run_cli("verify", self.manifest, "--skip-files", "--json", *extra)
        return code, json.loads(out)

    def chain(self, data):
        return next(check for check in data["token_checks"] if check["key"] == "chain")

    def test_a_listed_root_is_trusted_and_named(self):
        code, data = self.verify()
        self.assertEqual(self.chain(data)["status"], "not checked")
        self.assertEqual(run_cli("authority", "add", "listed", URL, "--root", self.root)[0], 0)
        code, data = self.verify()
        self.assertEqual(self.chain(data)["status"], "pass")
        self.assertIn("the root of listed in your authority list", self.chain(data)["detail"])
        self.assertIsNone(data["test_authority"])
        code, out, _ = run_cli("report", self.manifest, "--skip-files", "--out", "-")
        self.assertIn("the root of listed in your authority list", out)
        self.assertNotIn("local test authority", out)
        run_cli("authority", "remove", "listed")
        self.assertEqual(self.chain(self.verify()[1])["status"], "not checked")

    def test_ca_still_means_only_the_given_files(self):
        run_cli("authority", "add", "listed", URL, "--root", self.root)
        code, data = self.verify("--ca", ROOT_EC)
        self.assertEqual(code, 1)
        self.assertEqual(self.chain(data)["status"], "fail")
        self.assertIn("the certificates you supplied", self.chain(data)["detail"])

    def test_a_damaged_list_stops_verify_plainly_and_ca_still_works(self):
        self.home.mkdir()
        (self.home / "authorities.json").write_bytes(b"{")
        code, out, err = run_cli("verify", self.manifest, "--skip-files")
        self.assertEqual(code, 2)
        self.assertIn("authorities.json", err)
        self.assertEqual(out, "")
        code, out, _ = run_cli("verify", self.manifest, "--skip-files", "--ca", self.root)
        self.assertEqual(code, 3, "skipping files is never a pass, but the token checks ran")
        self.assertIn("certificate file listed-root.der", out)

    def test_show_names_a_listed_root(self):
        run_cli("authority", "add", "listed", URL, "--root", self.root)
        code, out, _ = run_cli("show", self.manifest.with_suffix(".tsr"))
        self.assertIn("this is the root of listed in your authority list", out)
        code, out, _ = run_cli("show", self.manifest.with_suffix(".tsr"), "--json")
        data = json.loads(out)
        self.assertIn("listed", [cert["listed_root"] for cert in data["certificates"]])
        self.assertIsNone(data["test_authority"])

    def test_a_damaged_list_does_not_stop_show(self):
        self.home.mkdir()
        (self.home / "authorities.json").write_bytes(b"{")
        self.assertEqual(run_cli("show", self.manifest.with_suffix(".tsr"))[0], 0)


class FilePermissions(HomeTestCase):
    def test_the_list_lives_in_the_home_folder_only(self):
        run_cli("authority", "add", "one", URL, "--root", ROOT_EC)
        found = sorted(str(path.relative_to(self.home)).replace(os.sep, "/") for path in self.home.rglob("*"))
        self.assertEqual(found, ["authorities", "authorities.json", f"authorities/{fingerprint(ROOT_EC)}.pem"])
