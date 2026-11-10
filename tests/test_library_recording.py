"""seal, stamp, verify and report record into the library, and a library problem never changes their result."""

import hashlib
import json
import os
import re
from unittest import mock

from evidence_seal import library
from tests.library_support import LibraryTestCase
from tests.support import run_cli

WARNING = "warning: the seal library did not record this run:"
CHECKED_AT = r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(\.\d+)? UTC"


class Switch(LibraryTestCase):
    def test_the_one_decision(self):
        self.assertTrue(library.recording_wanted(False, {}))
        self.assertTrue(library.recording_wanted(False, {library.SWITCH_VARIABLE: "on"}))
        self.assertFalse(library.recording_wanted(True, {}))
        for word in ("off", "OFF", " Off ", "no", "false", "0"):
            with self.subTest(word):
                self.assertFalse(library.recording_wanted(False, {library.SWITCH_VARIABLE: word}))

    def test_no_library_option_on_each_command_records_nothing(self):
        folder = self.make_folder()
        manifest_path = self.seal(folder, None, "--no-library")
        self.assertEqual(self.stamp(manifest_path, "--no-library")[0], 0)
        self.assertEqual(run_cli("verify", manifest_path, "--ca", self.ca, "--no-library")[0], 0)
        self.assertEqual(run_cli("report", manifest_path, "--ca", self.ca, "--out", "-", "--no-library")[0], 0)
        self.assertFalse(self.home.exists())

    def test_the_environment_turns_recording_off(self):
        with mock.patch.dict(os.environ, {library.SWITCH_VARIABLE: "off"}):
            folder = self.make_folder()
            manifest_path = self.seal(folder)
            self.assertEqual(run_cli("verify", manifest_path)[0], 3)
        self.assertFalse(self.home.exists())

    def test_a_dry_run_records_nothing(self):
        folder = self.make_folder()
        self.assertEqual(run_cli("seal", folder, "--dry-run")[0], 0)
        self.assertFalse(self.home.exists())


class Recording(LibraryTestCase):
    def test_seal_records_the_new_seal(self):
        folder = self.make_folder()
        manifest_path = self.seal(folder)
        row = self.only_seal()
        self.assertEqual(row["manifest_sha256"], hashlib.sha256(manifest_path.read_bytes()).hexdigest())
        self.assertEqual(row["purpose"], "purpose of work")
        self.assertEqual(row["folder_name"], "work")
        self.assertEqual((row["file_count"], row["total_bytes"]), (2, 9))
        self.assertEqual(row["manifest_kind"], "native")
        self.assertEqual(row["manifest_path"], os.path.abspath(manifest_path))
        self.assertEqual(row["folder_path"], str(folder.resolve()))
        self.assertIsNone(row["token_time"])
        events = self.rows("SELECT kind, detail, tool_version FROM events")
        self.assertEqual(events[0][:2], ("sealed", "sealed 2 files"))
        with self.open() as opened:
            self.assertEqual(opened.read_object(row["manifest_sha256"], library.MANIFEST), manifest_path.read_bytes())

    def test_stamp_records_the_token_with_its_request_and_root(self):
        _, manifest_path = self.sealed_and_stamped()
        sha = self.only_seal()["manifest_sha256"]
        with self.open() as opened:
            tokens = opened.tokens(sha)
            self.assertEqual(len(tokens), 1)
            token = tokens[0]
            self.assertTrue(token["is_current"])
            self.assertEqual(token["token_time"], "2026-03-01 12:00:00 UTC")
            self.assertEqual(token["authority"], "O=evidence-seal tests, CN=TEST ONLY fake signer")
            self.assertEqual(token["token_path"], os.path.abspath(manifest_path.with_suffix(".tsr")))
            self.assertEqual(opened.read_object(token["token_sha256"], library.TOKEN), manifest_path.with_suffix(".tsr").read_bytes())
            self.assertEqual(opened.read_object(token["request_sha256"], library.REQUEST), manifest_path.with_suffix(".tsq").read_bytes())
            self.assertEqual(opened.read_object(token["root_sha256"], library.ROOT), manifest_path.with_suffix(".ca.crt").read_bytes())
        self.assertEqual([row[0] for row in self.rows("SELECT kind FROM events ORDER BY id")], ["sealed", "stamped"])

    def test_stamp_force_marks_the_token_it_replaced(self):
        _, manifest_path = self.sealed_and_stamped()
        first = hashlib.sha256(manifest_path.with_suffix(".tsr").read_bytes()).hexdigest()
        code, out, err = self.stamp(manifest_path, "--force")
        self.assertEqual(code, 0, err)
        second = hashlib.sha256(manifest_path.with_suffix(".tsr").read_bytes()).hexdigest()
        kept = [path for path in self.temp.iterdir() if ".replaced-" in path.name and path.suffix == ".tsr"]
        self.assertEqual(len(kept), 1)
        with self.open() as opened:
            tokens = {token["token_sha256"]: token for token in opened.tokens(self.only_seal()["manifest_sha256"])}
        self.assertEqual(set(tokens), {first, second})
        self.assertFalse(tokens[first]["is_current"])
        self.assertEqual(tokens[first]["token_path"], os.path.abspath(kept[0]))
        self.assertTrue(tokens[second]["is_current"])

    def test_stamp_adds_a_seal_the_library_did_not_know(self):
        folder = self.make_folder()
        manifest_path = self.seal(folder, None, "--no-library")
        self.assertEqual(self.stamp(manifest_path)[0], 0)
        row = self.only_seal()
        self.assertIsNotNone(row["token_time"])
        self.assertEqual(self.rows("SELECT kind, detail FROM events ORDER BY id")[0], ("imported", "added by stamp"))

    def test_verify_records_the_run_and_each_check(self):
        folder, manifest_path = self.sealed_and_stamped()
        code, _, err = run_cli("verify", manifest_path, "--ca", self.ca)
        self.assertEqual(code, 0, err)
        self.assertEqual(err, "")
        row = self.only_seal()
        self.assertEqual(row["last_result"], "VERIFIED")
        with self.open() as opened:
            runs = opened.runs(row["manifest_sha256"])
        self.assertEqual(len(runs), 1)
        run = runs[0]
        self.assertEqual((run["command"], run["overall"], run["exit_code"]), ("verify", "VERIFIED", 0))
        self.assertEqual(run["folder_path"], str(folder.resolve()))
        self.assertEqual(run["token_sha256"], hashlib.sha256(manifest_path.with_suffix(".tsr").read_bytes()).hexdigest())
        self.assertEqual(run["checks"][0], {"key": "files", "title": "Files match the manifest", "status": "pass"})
        self.assertEqual(len(run["checks"]), 9)

    def test_verify_adds_the_seal_and_token_it_did_not_know(self):
        folder = self.make_folder()
        manifest_path = self.seal(folder, None, "--no-library")
        self.assertEqual(self.stamp(manifest_path, "--no-library")[0], 0)
        self.assertFalse(self.home.exists())
        self.assertEqual(run_cli("verify", manifest_path, "--ca", self.ca)[0], 0)
        row = self.only_seal()
        self.assertIsNotNone(row["token_time"])
        self.assertEqual(row["last_result"], "VERIFIED")
        kinds = [item[0] for item in self.rows("SELECT kind FROM events ORDER BY id")]
        self.assertEqual(kinds, ["imported", "verified"])

    def test_a_failed_run_does_not_move_the_folder(self):
        folder, manifest_path = self.sealed_and_stamped()
        other = self.make_folder("other", {"a.txt": b"different\n"})
        self.assertEqual(run_cli("verify", manifest_path, "--folder", other, "--ca", self.ca)[0], 1)
        row = self.only_seal()
        self.assertEqual(row["last_result"], "FAILED")
        self.assertEqual(row["folder_path"], str(folder.resolve()))

    def test_a_passing_run_elsewhere_moves_the_folder(self):
        folder, manifest_path = self.sealed_and_stamped()
        moved = self.temp / "moved"
        folder.rename(moved)
        self.assertEqual(run_cli("verify", manifest_path, "--folder", moved, "--ca", self.ca)[0], 0)
        self.assertEqual(self.only_seal()["folder_path"], str(moved))

    def test_a_token_for_another_manifest_is_not_kept_but_the_run_is(self):
        _, manifest_path = self.sealed_and_stamped()
        other_folder = self.make_folder("other")
        other = self.seal(other_folder)
        code, _, _ = run_cli("verify", other, "--token", manifest_path.with_suffix(".tsr"), "--ca", self.ca)
        self.assertEqual(code, 1)
        sha = hashlib.sha256(other.read_bytes()).hexdigest()
        with self.open() as opened:
            self.assertEqual(opened.tokens(sha), [])
            self.assertEqual(opened.runs(sha)[0]["overall"], "FAILED")

    def test_report_records_its_run(self):
        _, manifest_path = self.sealed_and_stamped()
        code, _, err = run_cli("report", manifest_path, "--ca", self.ca)
        self.assertEqual(code, 0, err)
        with self.open() as opened:
            runs = opened.runs(self.only_seal()["manifest_sha256"])
        self.assertEqual(runs[0]["command"], "report")

    def test_verifying_a_kept_copy_records_it_as_replaced(self):
        _, manifest_path = self.sealed_and_stamped()
        self.assertEqual(self.stamp(manifest_path, "--force", "--no-library")[0], 0)
        kept = next(path for path in self.temp.iterdir() if ".replaced-" in path.name and path.suffix == ".tsr")
        run_cli("verify", manifest_path, "--token", kept, "--ca", self.ca)
        with self.open() as opened:
            tokens = opened.tokens(self.only_seal()["manifest_sha256"])
        self.assertEqual([token["is_current"] for token in tokens], [False])


class NeverChangesTheResult(LibraryTestCase):
    """The same run with a broken library gives the same exit code and output, plus one warning line."""

    def break_library(self):
        self.root.mkdir(parents=True, exist_ok=True)
        if self.index.is_file():
            os.unlink(self.index)
        self.index.mkdir(exist_ok=True)

    def assert_same(self, *arguments):
        expected = run_cli(*arguments, "--no-library")
        self.break_library()
        code, out, err = run_cli(*arguments)
        self.assertEqual(code, expected[0])
        self.assertEqual(re.sub(CHECKED_AT, "", out), re.sub(CHECKED_AT, "", expected[1]))
        self.assertEqual(err, expected[2] + err[len(expected[2]):])
        extra = err[len(expected[2]):]
        self.assertEqual(extra.count("\n"), 1, extra)
        self.assertTrue(extra.startswith(WARNING), extra)
        return extra

    def test_verify_text_and_json(self):
        _, manifest_path = self.sealed_and_stamped()
        self.assert_same("verify", manifest_path, "--ca", self.ca)
        self.assert_same("verify", manifest_path, "--json")
        json.loads(run_cli("verify", manifest_path, "--json")[1])

    def test_verify_that_fails(self):
        folder, manifest_path = self.sealed_and_stamped()
        (folder / "a.txt").write_bytes(b"changed\n")
        self.assert_same("verify", manifest_path, "--ca", self.ca)

    def test_report_to_standard_output(self):
        _, manifest_path = self.sealed_and_stamped()
        self.assert_same("report", manifest_path, "--ca", self.ca, "--out", "-")

    def test_seal_and_stamp(self):
        self.break_library()
        folder = self.make_folder()
        code, out, err = run_cli("seal", folder, "--purpose", "p", "--out", self.temp / "m.txt")
        self.assertEqual(code, 0)
        self.assertIn("Sealed 2 files", out)
        self.assertTrue(err.startswith(WARNING) and err.count("\n") == 1, err)
        code, out, err = self.stamp(self.temp / "m.txt")
        self.assertEqual(code, 0)
        self.assertIn("Time in token", out)
        self.assertTrue(err.startswith(WARNING) and err.count("\n") == 1, err)
        self.assertTrue((self.temp / "m.tsr").is_file())

    def test_a_bug_in_the_library_is_still_only_a_warning(self):
        _, manifest_path = self.sealed_and_stamped()
        with mock.patch.object(library.Library, "add_run", side_effect=RuntimeError("boom")):
            code, out, err = run_cli("verify", manifest_path, "--ca", self.ca)
        self.assertEqual(code, 0)
        self.assertIn("RESULT: VERIFIED", out)
        self.assertEqual(err, f"{WARNING} RuntimeError: boom. Nothing else was affected.\n")

    def test_a_failure_while_recording_writes_none_of_that_run(self):
        _, manifest_path = self.sealed_and_stamped()
        before = self.rows("SELECT count(*) FROM events")[0][0]
        with mock.patch.object(library.Library, "add_run", side_effect=RuntimeError("boom")):
            run_cli("verify", manifest_path, "--ca", self.ca)
        self.assertEqual(self.rows("SELECT count(*) FROM events")[0][0], before)

    def test_a_manifest_changed_during_the_run_is_not_recorded(self):
        _, manifest_path = self.sealed_and_stamped()
        real = library.read_bounded

        def changed(path, kind):
            data = real(path, kind)
            return data + b"x" if kind == library.MANIFEST else data

        with mock.patch.object(library, "read_bounded", changed):
            code, _, err = run_cli("verify", manifest_path, "--ca", self.ca)
        self.assertEqual(code, 0)
        self.assertIn("changed while it was being checked", err)
