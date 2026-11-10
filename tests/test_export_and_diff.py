"""The export and diff commands: file lists for other tools, and two lists compared."""

import csv
import hashlib
import io
import json
import os
import shutil
import subprocess
import unicodedata
import unittest
from unittest import mock

from evidence_seal import comparing, manifest
from tests.support import HANDMADE_MANIFEST, LOCAL, TempFolderTestCase, run_cli

SHA256SUM = shutil.which("sha256sum")
ACCENTED = "caf" + chr(0xE9)


def gnu_sha256sum():
    """GNU's sha256sum, which reads escaped names. uutils coreutils 0.8, the default on some Linux
    systems, skips those lines with only a warning, even the ones it wrote itself."""
    for name in ("gnusha256sum", "sha256sum"):
        found = shutil.which(name)
        if found is None:
            continue
        try:
            version = subprocess.run([found, "--version"], capture_output=True, timeout=20).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        if b"GNU coreutils" in version:
            return found
    return None


GNU_SHA256SUM = gnu_sha256sum()


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Export(TempFolderTestCase):
    def setUp(self):
        super().setUp()
        self.folder, self.manifest = self.copy_sample()

    def export(self, *extra, path=None):
        return run_cli("export", path or self.manifest, *extra)

    def test_sha256sum_lines(self):
        code, out, err = self.export()
        self.assertEqual(code, 0, err)
        self.assertEqual(
            out.splitlines(),
            [
                "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880 *data/blob.bin",
                "5ac55f10a739d5994eb34142bfbcd0b69aaf730cb8cb32282d8628162b93f56c *data/name with spaces.txt",
                "1f049302d98c1c4a1dcac2bc95e86b75d52c05be57b33544f7d32e41e2235385 *notes.txt",
                "704e5583c9401d0963efb9e7f6c530c186ee547ef00678e9f95fe679afe926ee *windows-endings.txt",
            ],
        )
        self.assertIn("checks no token and proves no date", err)

    def test_bsd_lines(self):
        _, out, _ = self.export("--format", "bsd")
        self.assertEqual(
            out.splitlines()[0], "SHA256 (data/blob.bin) = 40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880"
        )
        self.assertEqual(len(out.splitlines()), 4)

    def test_csv_and_json_carry_path_size_and_hash(self):
        _, out, _ = self.export("--format", "csv")
        rows = list(csv.reader(io.StringIO(out, newline="")))
        self.assertEqual(rows[0], ["path", "size", "sha256"])
        self.assertEqual(rows[2], ["data/name with spaces.txt", "30", "5ac55f10a739d5994eb34142bfbcd0b69aaf730cb8cb32282d8628162b93f56c"])
        _, out, _ = self.export("--format", "json")
        data = json.loads(out)
        self.assertEqual(data["export_schema"], 1)
        self.assertEqual(data["manifest"]["kind"], "native")
        self.assertTrue(data["sizes_recorded"])
        self.assertEqual(data["files"][0], {"path": "data/blob.bin", "size": 256, "sha256": "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880"})

    def test_hand_made_lists_without_sizes_say_so(self):
        path = self.write("list.txt", f"{digest(b'one')}  one.txt\n{digest(b'two')} *two.txt\n".encode("ascii"))
        code, out, err = self.export("--format", "csv", path=path)
        self.assertEqual(code, 0)
        self.assertEqual(list(csv.reader(io.StringIO(out)))[1], ["one.txt", "", digest(b"one")])
        self.assertIn("does not record every size", err)
        _, out, _ = self.export("--format", "json", path=path)
        data = json.loads(out)
        self.assertFalse(data["sizes_recorded"])
        self.assertIsNone(data["files"][1]["size"])
        _, out, err = self.export(path=path)
        self.assertNotIn("size", err)
        self.assertEqual(out.splitlines()[1], f"{digest(b'two')} *two.txt")

    def test_the_fixture_hand_made_list(self):
        code, out, _ = self.export("--format", "json", path=HANDMADE_MANIFEST)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["manifest"]["kind"], "hand-made")

    def test_other_hashes_are_refused_and_nothing_is_written(self):
        path = self.write("md5.txt", f"{hashlib.md5(b'x').hexdigest()}  x.txt\n".encode("ascii"))
        target = self.temp / "out.txt"
        code, out, err = self.export("--out", target, path=path)
        self.assertEqual(code, 1)
        self.assertIn("SHA-256", err)
        self.assertIn("MD5", err)
        self.assertFalse(target.exists())
        self.assertEqual(out, "")

    def test_lists_with_nothing_readable_are_refused(self):
        path = self.write("words.txt", b"no hashes here\n")
        code, _, err = self.export(path=path)
        self.assertEqual(code, 1)
        self.assertIn("lists no files", err)
        code, _, err = self.export(path=self.write("v9.txt", b"evidence-seal manifest v9\n"))
        self.assertEqual(code, 1)
        self.assertIn("format v9", err)

    def test_bad_arguments(self):
        self.assertEqual(self.export(path=self.folder)[0], 2)
        self.assertEqual(self.export(path=self.temp / "none.txt")[0], 2)
        self.assertEqual(self.export("--format", "md5sum")[0], 2)

    def test_never_writes_over_the_manifest_or_its_companions(self):
        token = self.manifest.with_suffix(".tsr")
        token.write_bytes(b"token")
        report = self.manifest.with_suffix(".report.pdf")
        report.write_bytes(b"report")
        for target in (self.manifest, token, self.manifest.with_suffix(".tsq"), report, self.manifest.with_suffix(".ca.crt")):
            with self.subTest(target.name):
                before = target.read_bytes() if target.exists() else None
                code, _, err = self.export("--out", target, "--force")
                self.assertEqual(code, 2)
                self.assertIn("would overwrite", err)
                self.assertEqual(target.read_bytes() if target.exists() else None, before)

    def test_writes_a_new_file_and_replaces_only_with_force(self):
        target = self.temp / "list.sha256"
        code, out, _ = self.export("--out", target)
        self.assertEqual(code, 0)
        self.assertIn("Wrote 4 files", out)
        self.assertTrue(target.read_bytes().endswith(b" *windows-endings.txt\n"))
        self.assertNotIn(b"\r", target.read_bytes())
        self.assertEqual(self.export("--out", target, "--format", "bsd")[0], 1)
        self.assertEqual(self.export("--out", target, "--format", "bsd", "--force")[0], 0)
        self.assertTrue(target.read_bytes().startswith(b"SHA256 ("))

    def test_reads_only_the_manifest(self):
        before = self.export()[1]
        self.manifest.with_suffix(".tsr").write_bytes(b"not a token at all")
        shutil.rmtree(self.folder)
        with mock.patch("evidence_seal.tokencheck.check_token", side_effect=AssertionError("the token was read")):
            code, out, _ = self.export()
        self.assertEqual(code, 0)
        self.assertEqual(out, before)

    def test_an_inconsistent_manifest_is_exported_with_a_warning(self):
        data = self.manifest.read_bytes().replace(b"files: 4", b"files: 5")
        path = self.write("altered.txt", data)
        code, out, err = self.export(path=path)
        self.assertEqual(code, 0)
        self.assertIn("inconsistent", err)
        self.assertEqual(len(out.splitlines()), 4)

    def test_names_with_backslashes_and_line_feeds_use_the_gnu_escape(self):
        rows = [("plain.txt", digest(b"p"), 1), ("back\\slash.txt", digest(b"b"), 1), ("two\nlines\r.txt", digest(b"t"), 1)]
        path = self.write("odd.txt", manifest.render(rows, "p", "2026-01-01", "odd"))
        code, out, err = self.export(path=path)
        self.assertEqual(code, 0)
        lines = out.split("\n")
        self.assertIn(f"\\{digest(b'b')} *back\\\\slash.txt", lines)
        self.assertIn(f"\\{digest(b't')} *two\\nlines\\r.txt", lines)
        self.assertIn(f"{digest(b'p')} *plain.txt", lines)
        self.assertIn("2 names holding a backslash", err)
        self.assertIn("make sure every file is reported OK", err)
        _, out, err = self.export("--format", "bsd", path=path)
        self.assertIn(f"\\SHA256 (back\\\\slash.txt) = {digest(b'b')}", out.split("\n"))
        self.assertIn("2 names holding a backslash", err)
        _, _, err = self.export("--format", "json", path=path)
        self.assertNotIn("backslash", err)
        _, _, err = self.export()
        self.assertNotIn("backslash", err)

    def test_csv_cells_cannot_run_as_formulas(self):
        rows = [("=1+2", digest(b"a"), 1), ("@x", digest(b"b"), 1), ("'quoted", digest(b"c"), 1), ("a\tb", digest(b"d"), 1)]
        path = self.write("formulas.txt", manifest.render(rows, "p", "2026-01-01", "f"))
        _, out, _ = self.export("--format", "csv", path=path)
        paths = [row[0] for row in csv.reader(io.StringIO(out, newline=""))][1:]
        self.assertEqual(sorted(paths), sorted(["'=1+2", "'@x", "''quoted", "a\\tb"]))

    def test_a_name_no_checksum_list_can_hold(self):
        rows = [("lone" + chr(0xD800) + ".txt", digest(b"a"), 1)]
        path = self.write("lone.txt", manifest.render(rows, "p", "2026-01-01", "f"))
        code, _, err = self.export(path=path)
        self.assertEqual(code, 1)
        self.assertIn("--format json", err)
        code, out, _ = self.export("--format", "json", path=path)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["files"][0]["path"], "lone" + chr(0xD800) + ".txt")

    @unittest.skipUnless(SHA256SUM, "sha256sum is not on the path")
    def test_sha256sum_checks_the_export(self):
        for form in ("sha256sum", "bsd"):
            with self.subTest(form):
                target = self.temp / f"list-{form}.txt"
                self.assertEqual(self.export("--format", form, "--out", target)[0], 0)
                done = subprocess.run([SHA256SUM, "-c", str(target)], cwd=str(self.folder), capture_output=True)
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                self.assertEqual(done.stdout.count(b": OK"), 4)
        (self.folder / "notes.txt").write_bytes(b"changed")
        done = subprocess.run([SHA256SUM, "-c", str(self.temp / "list-sha256sum.txt")], cwd=str(self.folder), capture_output=True)
        self.assertNotEqual(done.returncode, 0)

    @unittest.skipUnless(SHA256SUM, "sha256sum is not on the path")
    def test_sha256sum_checks_names_from_other_scripts(self):
        folder = self.temp / "named"
        self.write("named/" + ACCENTED + " notes.txt", b"one")
        self.write("named/sub/" + chr(0x4E2D) + ".txt", b"two")
        out = self.temp / "named-manifest.txt"
        self.assertEqual(run_cli("seal", folder, "--purpose", "p", "--out", out)[0], 0)
        target = self.temp / "named.sha256"
        self.assertEqual(self.export("--out", target, path=out)[0], 0)
        done = subprocess.run([SHA256SUM, "-c", str(target)], cwd=str(folder), capture_output=True)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    @unittest.skipUnless(GNU_SHA256SUM and os.name != "nt", "needs GNU sha256sum and a system whose names can hold these")
    def test_sha256sum_checks_names_with_backslashes_and_line_feeds(self):
        folder = self.temp / "odd"
        for name in ("back\\slash.txt", "two\nlines.txt", "plain.txt"):
            self.write("odd/" + name, name.encode("utf-8"))
        out = self.temp / "odd-manifest.txt"
        self.assertEqual(run_cli("seal", folder, "--purpose", "p", "--out", out)[0], 0)
        for form in ("sha256sum", "bsd"):
            target = self.temp / f"odd-{form}.txt"
            self.assertEqual(self.export("--format", form, "--out", target, path=out)[0], 0)
            done = subprocess.run([GNU_SHA256SUM, "-c", str(target)], cwd=str(folder), capture_output=True)
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
            self.assertEqual(done.stdout.count(b": OK"), 3)


class Diff(TempFolderTestCase):
    def setUp(self):
        super().setUp()
        self.folder, self.manifest = self.copy_sample()

    def diff(self, *arguments):
        return run_cli("diff", *arguments)

    def json_diff(self, *arguments):
        code, out, err = self.diff(*arguments, "--format", "json")
        return code, json.loads(out) if out else None, err

    def test_a_manifest_and_its_unchanged_folder_are_identical(self):
        code, out, err = self.diff(self.manifest, self.folder)
        self.assertEqual(code, 0, err)
        self.assertIn("The lists are identical: 4 files, all unchanged.", out)
        self.assertIn("checks no token and proves no date", out)

    def test_every_kind_of_difference(self):
        (self.folder / "notes.txt").write_bytes(b"changed")
        (self.folder / "data" / "blob.bin").rename(self.folder / "blob-moved.bin")
        (self.folder / "windows-endings.txt").unlink()
        (self.folder / "new.txt").write_bytes(b"new")
        code, data, _ = self.json_diff(self.manifest, self.folder)
        self.assertEqual(code, 1)
        self.assertFalse(data["identical"])
        self.assertEqual(data["diff_schema"], 1)
        self.assertEqual(data["counts"], {"unchanged": 1, "changed": 1, "added": 1, "removed": 1, "moved": 1})
        by_path = {change["path"]: change for change in data["changes"]}
        self.assertEqual(by_path["data/blob.bin"]["outcome"], "moved")
        self.assertEqual(by_path["data/blob.bin"]["new_path"], "blob-moved.bin")
        self.assertEqual(by_path["notes.txt"]["new_sha256"], digest(b"changed"))
        self.assertEqual(by_path["notes.txt"]["old_size"], 38)
        self.assertEqual(by_path["notes.txt"]["new_size"], 7)
        self.assertEqual(by_path["new.txt"]["outcome"], "added")
        self.assertEqual(by_path["windows-endings.txt"]["outcome"], "removed")
        self.assertIn("proves no date", data["about"])
        code, out, _ = self.diff(self.manifest, self.folder)
        self.assertEqual(code, 1)
        for line in ("Changed: 1", "  notes.txt", "Added: 1", "  new.txt", "Removed: 1", "  windows-endings.txt", "Moved: 1", "  data/blob.bin -> blob-moved.bin"):
            self.assertIn(line + "\n", out)
        self.assertIn("The lists differ: 1 unchanged, 1 changed, 1 added, 1 removed, 1 moved.", out)

    def test_two_manifests(self):
        code, out, _ = self.diff(self.manifest, HANDMADE_MANIFEST)
        self.assertEqual(code, 0, out)
        later = self.temp / "later.txt"
        self.assertEqual(run_cli("seal", self.folder, "--purpose", "later", "--out", later)[0], 0)
        self.assertEqual(self.diff(self.manifest, later)[0], 0)
        (self.folder / "extra.txt").write_bytes(b"x")
        self.assertEqual(run_cli("seal", self.folder, "--purpose", "later", "--out", later, "--force")[0], 0)
        code, data, _ = self.json_diff(self.manifest, later)
        self.assertEqual(code, 1)
        self.assertEqual(data["counts"]["added"], 1)
        self.assertEqual(data["new"]["kind"], "native manifest")
        code, data, _ = self.json_diff(later, self.manifest)
        self.assertEqual(data["counts"]["removed"], 1)

    def test_a_hand_made_list_without_sizes_compares_by_hash(self):
        lines = "".join(f"{digest((self.folder / name).read_bytes())}  {name}\n" for name in ("notes.txt", "data/blob.bin"))
        path = self.write("list.txt", lines.encode("ascii"))
        code, data, _ = self.json_diff(path, self.manifest)
        self.assertEqual(code, 1)
        self.assertEqual(data["counts"], {"unchanged": 2, "changed": 0, "added": 2, "removed": 0, "moved": 0})

    def test_names_in_another_unicode_form_match_and_are_noted(self):
        composed = unicodedata.normalize("NFC", ACCENTED + ".txt")
        decomposed = unicodedata.normalize("NFD", composed)
        folder = self.temp / "forms"
        self.write("forms/" + decomposed, b"same")
        path = self.write("forms-manifest.txt", manifest.render([(composed, digest(b"same"), 4)], "p", "2026-01-01", "forms"))
        code, out, _ = self.diff(path, folder)
        self.assertEqual(code, 0, out)
        self.assertIn("another Unicode form", out)
        code, data, _ = self.json_diff(path, folder)
        self.assertEqual(data["matched_under_another_unicode_form"], 1)
        self.assertEqual(data["changes"][0]["new_path"], decomposed)

    def test_the_seal_excludes_and_your_own_apply_to_the_folder(self):
        self.write("sample-folder/.git/config", b"x")
        later = self.temp / "excluding.txt"
        self.assertEqual(run_cli("seal", self.folder, "--purpose", "p", "--exclude", ".git", "--out", later)[0], 0)
        (self.folder / ".git" / "more").write_bytes(b"y")
        self.assertEqual(self.diff(later, self.folder)[0], 0)
        (self.folder / "scratch.tmp").write_bytes(b"z")
        self.assertEqual(self.diff(later, self.folder)[0], 1)
        self.assertEqual(self.diff(later, self.folder, "--exclude", "*.tmp")[0], 0)
        rules = self.write("rules.txt", b"# temporary files\n*.tmp\n")
        self.assertEqual(self.diff(later, self.folder, "--exclude-from", rules)[0], 0)
        code, data, _ = self.json_diff(self.manifest, self.folder, "--exclude", "notes.txt", "--exclude", "*.tmp", "--exclude", ".git")
        self.assertEqual(code, 0)
        self.assertEqual(data["counts"]["unchanged"], 3)

    def test_the_manifest_and_its_companions_inside_the_folder_are_left_out(self):
        inside = self.folder / "EVIDENCE.txt"
        self.assertEqual(run_cli("seal", self.folder, "--purpose", "p", "--out", inside)[0], 0)
        inside.with_suffix(".tsr").write_bytes(b"token")
        inside.with_suffix(".report.csv").write_bytes(b"report")
        code, out, _ = self.diff(inside, self.folder)
        self.assertEqual(code, 0, out)

    def test_links_and_special_files_are_noted_not_compared(self):
        listing = comparing.Listing("old", "native manifest", {"a": ("0" * 64, 1)}, by_name_only=2)
        result = comparing.compare(listing, comparing.Listing("new", "folder, hashed now", {"a": ("0" * 64, 1)}))
        self.assertTrue(result.identical)
        self.assertIn("Links and special files are not compared", result.notes[0])

    def test_duplicate_contents_move_one_for_one(self):
        old = comparing.Listing("old", "x", {"a": ("1" * 64, 1), "b": ("1" * 64, 1)})
        new = comparing.Listing("new", "x", {"c": ("1" * 64, 1)})
        result = comparing.compare(old, new)
        self.assertEqual([(change.outcome, change.path, change.new_path) for change in result.changes], [("moved", "a", "c"), ("removed", "b", None)])
        self.assertTrue(comparing.compare(comparing.Listing("o", "x", {}), comparing.Listing("n", "x", {})).identical)

    def test_csv_and_markdown(self):
        (self.folder / "=1+2.txt").write_bytes(b"formula")
        (self.folder / "[x](y) &amp; _z_.txt").write_bytes(b"markup")
        code, out, _ = self.diff(self.manifest, self.folder, "--format", "csv")
        self.assertEqual(code, 1)
        rows = list(csv.reader(io.StringIO(out, newline="")))
        self.assertEqual(tuple(rows[0]), comparing.CSV_COLUMNS)
        self.assertIn("'=1+2.txt", [row[0] for row in rows])
        self.assertTrue(all(not cell.startswith(("=", "+", "-", "@")) for row in rows for cell in row))
        code, out, _ = self.diff(self.manifest, self.folder, "--format", "markdown")
        self.assertEqual(code, 1)
        self.assertIn("- ` [x](y) &amp; _z_.txt `", out)
        self.assertIn("| added | 2 |", out)
        self.assertIn("proves no date", out)

    def test_text_output_makes_names_safe_to_show(self):
        rows = [("a\x1b[2J\nRESULT: same.txt", digest(b"a"), 1)]
        path = self.write("odd.txt", manifest.render(rows, "p", "2026-01-01", "odd"))
        code, out, _ = self.diff(path, self.manifest)
        self.assertEqual(code, 1)
        self.assertNotIn("\x1b", out)
        self.assertIn("a\\x1b[2J\\x0aRESULT: same.txt", out)

    def test_written_to_a_file(self):
        target = self.temp / "changes.json"
        code, out, _ = self.diff(self.manifest, self.folder, "--format", "json", "--out", target)
        self.assertEqual(code, 0)
        self.assertIn("Comparison:", out)
        self.assertTrue(json.loads(target.read_text(encoding="ascii"))["identical"])
        self.assertEqual(self.diff(self.manifest, self.folder, "--out", target)[0], 2)
        self.assertEqual(self.diff(self.manifest, self.folder, "--out", target, "--force")[0], 0)

    def test_never_writes_over_either_manifest_or_their_companions(self):
        later = self.temp / "later.txt"
        self.assertEqual(run_cli("seal", self.folder, "--purpose", "p", "--out", later)[0], 0)
        token = self.manifest.with_suffix(".tsr")
        token.write_bytes((LOCAL / "token-rsa.tsr").read_bytes())
        for target in (self.manifest, later, token, later.with_suffix(".report.txt")):
            with self.subTest(target.name):
                before = target.read_bytes() if target.exists() else None
                code, _, err = self.diff(self.manifest, later, "--out", target, "--force")
                self.assertEqual(code, 2)
                self.assertIn("would overwrite", err)
                self.assertEqual(target.read_bytes() if target.exists() else None, before)

    def test_errors_are_exit_code_2_never_1(self):
        md5 = self.write("md5.txt", f"{hashlib.md5(b'x').hexdigest()}  x.txt\n".encode("ascii"))
        for arguments in (
            (self.folder, self.manifest),
            (self.manifest, self.temp / "none"),
            (self.temp / "none.txt", self.folder),
            (md5, self.folder),
            (self.manifest, md5),
            (self.manifest, self.folder, "--exclude-from", self.temp / "none"),
            (self.manifest, self.folder, "--format", "pdf"),
        ):
            with self.subTest(arguments):
                code, out, err = self.diff(*arguments)
                self.assertEqual(code, 2, out + err)
                self.assertEqual(out, "")

    @unittest.skipIf(os.name == "nt", "Windows cannot take away read permission this way")
    def test_an_unreadable_file_stops_the_folder_hash(self):
        locked = self.folder / "notes.txt"
        locked.chmod(0)
        self.addCleanup(locked.chmod, 0o644)
        if os.access(locked, os.R_OK):
            self.skipTest("running with rights that read any file")
        code, _, err = self.diff(self.manifest, self.folder)
        self.assertEqual(code, 2)
        self.assertIn("notes.txt", err)


if __name__ == "__main__":
    unittest.main()
