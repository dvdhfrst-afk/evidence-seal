"""The seal command and the file half of verify, through the command line."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import unittest
from unittest import mock

from evidence_seal import hashes, manifest, scan, sealing
from evidence_seal.errors import SealError
from tests.support import (
    HANDMADE_MANIFEST,
    LOCAL,
    ROOT_OF_REPO,
    SAMPLE_FOLDER,
    SAMPLE_MANIFEST,
    TempFolderTestCase,
    run_cli,
)


def symlinks_work(folder):
    try:
        os.symlink(folder / "nothing", folder / "probe-link")
    except (OSError, NotImplementedError):
        return False
    os.unlink(folder / "probe-link")
    return True


class ExcludeRules(unittest.TestCase):
    def test_name_pattern_matches_any_depth(self):
        rules = scan.Excludes([".git", "*.tmp"])
        self.assertTrue(rules.matches(".git"))
        self.assertTrue(rules.matches("a/b/.git"))
        self.assertTrue(rules.matches("a/x.tmp"))
        self.assertFalse(rules.matches("a/.gitignore"))
        self.assertFalse(rules.matches("x.tmp.txt"))

    def test_path_pattern_matches_from_the_top(self):
        rules = scan.Excludes(["build/out", "/top.txt"])
        self.assertTrue(rules.matches("build/out"))
        self.assertFalse(rules.matches("src/build/out"))
        self.assertTrue(rules.matches("top.txt"))
        self.assertFalse(rules.matches("a/top.txt"))

    def test_is_case_sensitive_everywhere(self):
        self.assertFalse(scan.Excludes(["*.TMP"]).matches("a.tmp"))

    def test_backslashes_and_trailing_slashes_are_normalized(self):
        self.assertTrue(scan.Excludes(["node_modules/"]).matches("a/node_modules"))
        self.assertTrue(scan.Excludes(["a\\b"]).matches("a/b"))
        self.assertEqual(scan.Excludes(["/", ""]).patterns, [])


class Seal(TempFolderTestCase):
    def folder(self):
        self.write("work/a.txt", b"alpha\n")
        self.write("work/sub/b.bin", bytes(range(256)))
        self.write("work/crlf.txt", b"one\r\ntwo\r\n")
        return self.temp / "work"

    def test_hashes_raw_bytes(self):
        folder = self.folder()
        code, out, _ = run_cli("seal", folder, "--purpose", "test", "--date", "2026-02-03")
        self.assertEqual(code, 0, out)
        path = self.temp / "work-manifest-2026-02-03.txt"
        parsed = manifest.read_manifest(path)
        self.assertEqual(parsed.problems, [])
        by_path = {entry.path: entry for entry in parsed.entries}
        self.assertEqual(by_path["crlf.txt"].hexdigest, hashlib.sha256(b"one\r\ntwo\r\n").hexdigest())
        self.assertEqual(by_path["crlf.txt"].size, 10)
        self.assertEqual(by_path["sub/b.bin"].hexdigest, hashlib.sha256(bytes(range(256))).hexdigest())
        self.assertIn("stamp", out)

    def test_same_folder_gives_the_same_bytes(self):
        folder = self.folder()
        one = self.temp / "one.txt"
        two = self.temp / "two.txt"
        run_cli("seal", folder, "--purpose", "p", "--date", "2026-02-03", "--out", one)
        os.utime(folder / "a.txt", (1, 1))
        run_cli("seal", folder, "--purpose", "p", "--date", "2026-02-03", "--out", two)
        self.assertEqual(one.read_bytes(), two.read_bytes())

    def test_only_purpose_and_date_differ_between_runs(self):
        folder = self.folder()
        one = self.temp / "one.txt"
        two = self.temp / "two.txt"
        run_cli("seal", folder, "--purpose", "first", "--date", "2026-02-03", "--out", one)
        run_cli("seal", folder, "--purpose", "second", "--out", two)
        difference = set(one.read_text().splitlines()) ^ set(two.read_text().splitlines())
        self.assertEqual({line.split(":")[0] for line in difference}, {"purpose", "created"})

    def test_excludes_are_recorded_and_applied(self):
        folder = self.folder()
        self.write("work/x.tmp")
        self.write("work/.git/config")
        out = self.temp / "m.txt"
        run_cli("seal", folder, "--purpose", "p", "--exclude", "*.tmp", "--exclude", ".git", "--out", out)
        parsed = manifest.read_manifest(out)
        self.assertEqual(parsed.excludes, ["*.tmp", ".git"])
        self.assertEqual(sorted(entry.path for entry in parsed.entries), ["a.txt", "crlf.txt", "sub/b.bin"])

    def test_manifest_inside_the_folder_leaves_itself_out(self):
        folder = self.folder()
        out = folder / "evidence" / "seal.txt"
        code, _, err = run_cli("seal", folder, "--purpose", "p", "--out", out)
        self.assertEqual(code, 0, err)
        parsed = manifest.read_manifest(out)
        self.assertNotIn("evidence/seal.txt", [entry.path for entry in parsed.entries])
        self.write("work/evidence/seal.tsr", b"token goes here")
        code, text, _ = run_cli("verify", out, "--folder", folder)
        self.assertIn("0 added", text)
        self.write("work/seal.tsr", b"same name, elsewhere")
        _, text, _ = run_cli("verify", out, "--folder", folder)
        self.assertIn("1 added", text)

    def test_manifest_inside_the_folder_leaves_out_only_exact_companions(self):
        folder = self.folder()
        out = folder / "seal.txt"
        self.write("work/seal.payload", b"present when sealed")
        self.write("work/seal.tsr", b"an old token")
        code, _, err = run_cli("seal", folder, "--purpose", "p", "--out", out, "--date", "2026-02-03")
        self.assertEqual(code, 0, err)
        parsed = manifest.read_manifest(out)
        paths = [entry.path for entry in parsed.entries]
        self.assertIn("seal.payload", paths)
        self.assertNotIn("seal.tsr", paths)
        self.assertNotIn("seal.txt", paths)
        self.assertIn("/seal.tsr", parsed.excludes)
        self.assertNotIn("/seal.*", parsed.excludes)

    def test_will_not_overwrite_without_force(self):
        folder = self.folder()
        out = self.temp / "m.txt"
        out.write_bytes(b"precious")
        code, _, err = run_cli("seal", folder, "--purpose", "p", "--out", out)
        self.assertEqual(code, 1)
        self.assertIn("already exists", err)
        self.assertEqual(out.read_bytes(), b"precious")
        code, _, _ = run_cli("seal", folder, "--purpose", "p", "--out", out, "--force")
        self.assertEqual(code, 0)
        self.assertTrue(out.read_bytes().startswith(b"evidence-seal"))

    def test_purpose_is_required_and_cannot_be_blank(self):
        folder = self.folder()
        code, _, err = run_cli("seal", folder)
        self.assertEqual(code, 2)
        self.assertIn("--purpose", err)
        code, _, err = run_cli("seal", folder, "--purpose", "   ")
        self.assertEqual(code, 2)

    def test_bad_inputs_are_clear_errors(self):
        code, _, err = run_cli("seal", self.temp / "nope", "--purpose", "p")
        self.assertEqual(code, 2)
        self.assertIn("not a folder", err)
        code, _, err = run_cli("seal", self.folder(), "--purpose", "p", "--date", "last week")
        self.assertEqual(code, 2)

    def test_empty_folder_is_refused(self):
        (self.temp / "empty").mkdir()
        code, _, err = run_cli("seal", self.temp / "empty", "--purpose", "p")
        self.assertEqual(code, 1)
        self.assertIn("no files", err)

    def test_everything_excluded_is_refused(self):
        code, _, err = run_cli("seal", self.folder(), "--purpose", "p", "--exclude", "*")
        self.assertEqual(code, 1)
        self.assertIn("no files", err)

    def test_unreadable_file_stops_the_seal_instead_of_being_skipped(self):
        folder = self.folder()
        out = self.temp / "m.txt"
        original = open

        def failing(path, *args, **kwargs):
            if str(path).endswith("a.txt"):
                raise PermissionError(13, "Permission denied")
            return original(path, *args, **kwargs)

        with mock.patch("builtins.open", failing):
            with self.assertRaises(SealError):
                sealing.seal_folder(folder, "p", out=out)
        self.assertFalse(out.exists())

    def test_walk_errors_stop_the_seal(self):
        result = scan.WalkResult(errors=[("x", "denied")])
        with self.assertRaises(SealError):
            scan.require_clean_walk(result)

    def test_links_are_listed_but_not_followed(self):
        folder = self.folder()
        if not symlinks_work(self.temp):
            self.skipTest("this system does not allow creating symbolic links")
        outside = self.write("outside/secret.txt", b"not part of this folder")
        os.symlink(outside, folder / "link.txt")
        os.symlink(outside.parent, folder / "linkdir", target_is_directory=True)
        out = self.temp / "m.txt"
        code, text, _ = run_cli("seal", folder, "--purpose", "p", "--out", out)
        self.assertEqual(code, 0)
        self.assertIn("by name only", text)
        parsed = manifest.read_manifest(out)
        self.assertEqual(parsed.links, ["link.txt", "linkdir"])
        self.assertNotIn("link.txt", [entry.path for entry in parsed.entries])
        self.assertFalse(any("secret" in entry.path for entry in parsed.entries))

    def test_hash_file_reads_large_files_in_chunks(self):
        path = self.write("big.bin", b"x" * (scan.CHUNK * 2 + 5))
        digest, size = scan.hash_file(path, hashes.SHA256)
        self.assertEqual(size, scan.CHUNK * 2 + 5)
        self.assertEqual(digest, hashlib.sha256(b"x" * (scan.CHUNK * 2 + 5)).hexdigest())


class VerifyFiles(TempFolderTestCase):
    def verify_json(self, manifest_path, *extra):
        code, out, err = run_cli("verify", manifest_path, "--json", *extra)
        self.assertEqual(err, "")
        return code, json.loads(out)

    def test_unchanged_folder_without_a_token_is_incomplete_not_a_pass(self):
        _, path = self.copy_sample()
        code, data = self.verify_json(path)
        self.assertEqual(code, 3)
        self.assertEqual(data["overall"], "INCOMPLETE")
        self.assertEqual(data["files"]["status"], "pass")
        self.assertEqual(data["token_checks"][0]["status"], "not checked")

    def test_changed_file_is_reported(self):
        folder, path = self.copy_sample()
        (folder / "notes.txt").write_bytes(b"Plain synthetic notes.\nA second lime.\n")
        code, data = self.verify_json(path)
        self.assertEqual(code, 1)
        self.assertEqual(data["differences"]["changed"], ["notes.txt"])
        self.assertEqual(data["files"]["status"], "fail")

    def test_line_ending_conversion_counts_as_a_change(self):
        folder, path = self.copy_sample()
        target = folder / "windows-endings.txt"
        target.write_bytes(target.read_bytes().replace(b"\r\n", b"\n"))
        code, data = self.verify_json(path)
        self.assertEqual(code, 1)
        self.assertEqual(data["differences"]["changed"], ["windows-endings.txt"])

    def test_same_size_change_is_caught_by_the_hash(self):
        folder, path = self.copy_sample()
        target = folder / "data" / "blob.bin"
        raw = bytearray(target.read_bytes())
        raw[100] ^= 1
        target.write_bytes(bytes(raw))
        code, data = self.verify_json(path)
        self.assertEqual(code, 1)
        self.assertEqual(data["differences"]["changed"], ["data/blob.bin"])

    def test_missing_file_is_reported(self):
        folder, path = self.copy_sample()
        (folder / "notes.txt").unlink()
        code, data = self.verify_json(path)
        self.assertEqual(code, 1)
        self.assertEqual(data["differences"]["missing"], ["notes.txt"])

    def test_added_file_is_reported_and_fails_unless_allowed(self):
        folder, path = self.copy_sample()
        self.write("sample-folder/new.txt")
        code, data = self.verify_json(path)
        self.assertEqual(code, 1)
        self.assertEqual(data["differences"]["added"], ["new.txt"])
        self.assertIn("every listed file still matches", data["files"]["detail"])
        code, data = self.verify_json(path, "--allow-added")
        self.assertEqual(data["files"]["status"], "pass")
        self.assertEqual(data["differences"]["added"], ["new.txt"])
        self.assertEqual(code, 3)

    def test_rename_is_pointed_out(self):
        folder, path = self.copy_sample()
        (folder / "notes.txt").rename(folder / "renamed.txt")
        code, data = self.verify_json(path)
        self.assertEqual(code, 1)
        self.assertEqual(data["differences"]["possible_moves"], {"notes.txt": "renamed.txt"})

    def test_cli_exclude_cannot_hide_a_sealed_file(self):
        folder, path = self.copy_sample()
        (folder / "notes.txt").write_bytes(b"changed")
        code, data = self.verify_json(path, "--exclude", "notes.txt", "--exclude", "*")
        self.assertEqual(code, 1)
        self.assertEqual(data["differences"]["changed"], ["notes.txt"])

    def test_cli_exclude_hides_new_files_only(self):
        folder, path = self.copy_sample()
        self.write("sample-folder/cache.tmp")
        _, data = self.verify_json(path, "--exclude", "*.tmp")
        self.assertEqual(data["differences"]["added"], [])
        self.assertEqual(data["files"]["status"], "pass")

    def test_skip_files_can_never_pass(self):
        _, path = self.copy_sample()
        code, data = self.verify_json(
            path,
            "--skip-files",
            "--token",
            LOCAL / "token-rsa.tsr",
            "--ca",
            LOCAL / "root-rsa.crt",
        )
        self.assertEqual(code, 3)
        self.assertEqual(data["overall"], "INCOMPLETE")
        self.assertEqual(data["files"]["status"], "not checked")

    def test_folder_that_cannot_be_found_is_not_a_pass(self):
        path = self.temp / "m.txt"
        path.write_bytes(SAMPLE_MANIFEST.read_bytes())
        code, data = self.verify_json(path)
        self.assertEqual(code, 3)
        self.assertEqual(data["files"]["status"], "not checked")
        self.assertIn("--folder", data["files"]["detail"])

    def test_folder_name_from_the_manifest_cannot_climb_out(self):
        rows = [("a.txt", hashlib.sha256(b"content\n").hexdigest(), 8)]
        data = manifest.render(rows, "p", "2026-01-01", "../outside")
        path = self.write("inner/m.txt", data)
        self.write("outside/a.txt")
        code, result = self.verify_json(path)
        self.assertEqual(result["files"]["status"], "not checked")

    def test_manifest_paths_cannot_reach_outside_the_folder(self):
        self.write("outside.txt", b"content\n")
        digest = hashlib.sha256(b"content\n").hexdigest()
        self.write("work/inner.txt", b"content\n")
        rows = [("../outside.txt", digest, 8), ("inner.txt", digest, 8)]
        path = self.write("m.txt", manifest.render(rows, "p", "2026-01-01", "work"))
        code, data = self.verify_json(path)
        self.assertEqual(code, 1)
        self.assertEqual(data["differences"]["missing"], ["../outside.txt"])

    def test_altered_native_manifest_fails_even_with_matching_files(self):
        folder, path = self.copy_sample()
        raw = path.read_bytes()
        lines = raw.split(b"\n")
        path.write_bytes(b"\n".join(line for line in lines if not line.endswith(b"notes.txt")))
        (folder / "notes.txt").unlink()
        code, data = self.verify_json(path)
        self.assertEqual(code, 1)
        self.assertEqual(data["files"]["status"], "fail")
        self.assertIn("inconsistent", data["files"]["detail"])

    def test_link_replacing_a_file_is_not_a_match(self):
        folder, path = self.copy_sample()
        if not symlinks_work(self.temp):
            self.skipTest("this system does not allow creating symbolic links")
        keep = self.write("elsewhere/notes.txt", (folder / "notes.txt").read_bytes())
        (folder / "notes.txt").unlink()
        os.symlink(keep, folder / "notes.txt")
        code, data = self.verify_json(path)
        self.assertEqual(code, 1)
        self.assertEqual(data["differences"]["missing"], ["notes.txt"])

    def test_unreadable_file_is_not_a_match_and_not_a_change(self):
        _, path = self.copy_sample()
        original = scan.hash_file

        def failing(target, algorithm):
            if str(target).endswith("notes.txt"):
                raise PermissionError(13, "Permission denied")
            return original(target, algorithm)

        with mock.patch("evidence_seal.scan.hash_file", failing):
            code, data = self.verify_json(path)
        self.assertEqual(code, 3)
        self.assertEqual(data["files"]["status"], "not checked")
        self.assertEqual(data["differences"]["unreadable"], ["notes.txt"])


class HandMadeVerify(TempFolderTestCase):
    def pair(self, data=None):
        folder = self.temp / "sample-folder"
        shutil.copytree(SAMPLE_FOLDER, folder)
        manifest_path = folder / "EVIDENCE.txt"
        manifest_path.write_bytes(data if data is not None else HANDMADE_MANIFEST.read_bytes())
        return folder, manifest_path

    def test_hand_made_manifest_and_token_pass(self):
        _, path = self.pair()
        token = path.with_suffix(".tsr")
        token.write_bytes((LOCAL / "token-handmade.tsr").read_bytes())
        code, out, _ = run_cli("verify", path, "--ca", LOCAL / "root-ec.crt")
        self.assertEqual(code, 0, out)
        self.assertIn("(hand-made)", out)
        self.assertIn("RESULT: VERIFIED", out)
        self.assertIn("free text", out)

    def test_hand_made_changed_file_fails(self):
        folder, path = self.pair()
        path.with_suffix(".tsr").write_bytes((LOCAL / "token-handmade.tsr").read_bytes())
        (folder / "notes.txt").write_bytes(b"different")
        code, out, _ = run_cli("verify", path, "--ca", LOCAL / "root-ec.crt")
        self.assertEqual(code, 1)
        self.assertIn("Changed (1)", out)

    def test_file_named_like_the_manifest_is_not_hidden(self):
        folder, path = self.pair()
        path.with_suffix(".tsr").write_bytes((LOCAL / "token-handmade.tsr").read_bytes())
        (folder / "EVIDENCE.payload").write_bytes(b"undisclosed")
        (folder / "EVIDENCE.tsr.extra").write_bytes(b"undisclosed")
        (folder / "EVIDENCE.report.txt.bak").write_bytes(b"undisclosed")
        code, text, _ = run_cli("verify", path, "--ca", LOCAL / "root-ec.crt", "--json")
        data = json.loads(text)
        self.assertEqual(code, 1)
        self.assertEqual(data["files"]["status"], "fail")
        self.assertEqual(
            data["differences"]["added"],
            ["EVIDENCE.payload", "EVIDENCE.report.txt.bak", "EVIDENCE.tsr.extra"],
        )

    def test_companion_files_are_skipped_by_exact_name_and_disclosed(self):
        _, path = self.pair()
        path.with_suffix(".tsr").write_bytes((LOCAL / "token-handmade.tsr").read_bytes())
        for suffix in (".tsq", ".ca.crt", ".report.txt", ".report.html"):
            source = LOCAL / "token-handmade.tsq" if suffix == ".tsq" else LOCAL / "root-ec.crt"
            path.with_suffix(suffix).write_bytes(source.read_bytes())
        code, text, _ = run_cli("verify", path, "--ca", LOCAL / "root-ec.crt", "--json")
        data = json.loads(text)
        self.assertEqual(data["differences"]["added"], [])
        self.assertEqual(code, 0, text)
        self.assertIn("EVIDENCE.report.html", data["differences"]["own_files_not_compared"])
        self.assertIn("EVIDENCE.txt", data["differences"]["own_files_not_compared"])
        self.assertTrue(any("EVIDENCE.report.html" in note for note in data["notes"]))

    def test_listed_companion_name_is_still_compared(self):
        folder, path = self.pair()
        target = folder / "EVIDENCE.report.txt"
        target.write_bytes(b"listed\n")
        digest = hashlib.sha256(b"listed\n").hexdigest()
        path.write_bytes(f"{digest}  EVIDENCE.report.txt\n".encode("ascii"))
        target.write_bytes(b"altered\n")
        code, text, _ = run_cli("verify", path, "--allow-added", "--json")
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(text)["differences"]["changed"], ["EVIDENCE.report.txt"])

    def test_manifest_with_no_readable_entries_is_not_a_pass(self):
        _, path = self.pair(b"just some words\nabout some files\n")
        code, out, _ = run_cli("verify", path)
        self.assertEqual(code, 3)
        self.assertIn("lists no files", out)

    def test_unreadable_hash_lines_are_not_a_pass(self):
        digest = hashlib.sha256(b"Plain synthetic notes.\nA second line.\n").hexdigest()
        _, path = self.pair(f"{digest}  notes.txt\n{'a' * 50}  other\n".encode("ascii"))
        code, data_text, _ = run_cli("verify", path, "--json", "--exclude", "*")
        data = json.loads(data_text)
        self.assertEqual(data["files"]["status"], "not checked")
        self.assertIn("could not be read", data["files"]["detail"])

    def test_weak_hash_lines_are_not_a_pass(self):
        digest = hashlib.sha1(b"Plain synthetic notes.\nA second line.\n").hexdigest()
        _, path = self.pair(f"{digest}  notes.txt\n".encode("ascii"))
        code, data_text, _ = run_cli("verify", path, "--json", "--exclude", "*")
        data = json.loads(data_text)
        self.assertEqual(data["files"]["status"], "not checked")
        self.assertIn("collision", data["files"]["detail"])

    def test_absolute_paths_inside_and_outside_the_folder(self):
        folder, path = self.pair()
        inside = (folder / "notes.txt").resolve().as_posix()
        outside = "/no/such/place/file.txt"
        digest = hashlib.sha256((folder / "notes.txt").read_bytes()).hexdigest()
        path.write_bytes(f"{digest}  {inside}\n".encode("utf-8"))
        _, text, _ = run_cli("verify", path, "--json", "--exclude", "*")
        self.assertEqual(json.loads(text)["files"]["status"], "pass")
        path.write_bytes(f"{digest}  {outside}\n".encode("utf-8"))
        _, text, _ = run_cli("verify", path, "--json", "--exclude", "*")
        self.assertEqual(json.loads(text)["files"]["status"], "not checked")


class VerifyArguments(TempFolderTestCase):
    def test_missing_files_are_usage_errors(self):
        _, path = self.copy_sample()
        self.assertEqual(run_cli("verify", self.temp / "none.txt")[0], 2)
        self.assertEqual(run_cli("verify", path, "--token", self.temp / "none.tsr")[0], 2)
        self.assertEqual(run_cli("verify", path, "--folder", self.temp / "none")[0], 2)
        code, _, err = run_cli("verify", path, "--ca", self.temp / "none.crt")
        self.assertEqual(code, 2)
        self.assertIn("none.crt", err)
        bad = self.write("bad.crt", b"not a certificate")
        code, _, err = run_cli("verify", path, "--untrusted", bad)
        self.assertEqual(code, 2)

    def test_a_token_is_found_beside_the_manifest(self):
        _, path = self.copy_sample()
        path.with_suffix(".tsr").write_bytes((LOCAL / "token-rsa.tsr").read_bytes())
        code, out, _ = run_cli("verify", path, "--ca", LOCAL / "root-rsa.crt")
        self.assertEqual(code, 0, out)

    def test_saved_request_beside_the_manifest_is_used(self):
        _, path = self.copy_sample()
        path.with_suffix(".tsr").write_bytes((LOCAL / "token-rsa.tsr").read_bytes())
        path.with_suffix(".tsq").write_bytes((LOCAL / "token-ec.tsq").read_bytes())
        code, out, _ = run_cli("verify", path, "--ca", LOCAL / "root-rsa.crt")
        self.assertEqual(code, 1, out)
        self.assertIn("saved request", out)

    def test_every_verdict_word_in_text_output(self):
        _, path = self.copy_sample()
        path.with_suffix(".tsr").write_bytes((LOCAL / "token-rsa.tsr").read_bytes())
        _, out, _ = run_cli("verify", path, "--ca", LOCAL / "root-rsa.crt")
        for phrase in ("Status: granted", "Time:", "Policy: 1.2.3.4.1", "Hash algorithm: SHA-256", "Authority:", "pure Python"):
            self.assertIn(phrase, out)
        self.assertIn("Certificate revocation", out)
        _, out, _ = run_cli("verify", path)
        self.assertIn("RESULT: INCOMPLETE", out)
        self.assertIn("This is not a pass", out)
        self.assertNotIn("RESULT: VERIFIED", out)


class RunsAsAModule(unittest.TestCase):
    def test_python_dash_m_runs_from_the_repository(self):
        done = subprocess.run(
            [sys.executable, "-m", "evidence_seal", "show", str(LOCAL / "token-rsa.tsr")],
            capture_output=True,
            text=True,
            cwd=str(ROOT_OF_REPO),
        )
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("existed by", done.stdout)


if __name__ == "__main__":
    unittest.main()
