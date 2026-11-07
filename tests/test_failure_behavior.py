"""When something goes wrong: plain words, the right exit code, and nothing lost."""

import errno
import json
import os
import signal
import stat
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

from evidence_seal import cli, manifest, scan, sealing
from evidence_seal.errors import ManifestError, SealError
from tests.support import ROOT_OF_REPO, TempFolderTestCase, run_cli


def run_process(*arguments, **options):
    """Runs the real program the way a user does, in a separate process."""
    return subprocess.run(
        [sys.executable, "-m", "evidence_seal"] + [str(item) for item in arguments],
        cwd=str(ROOT_OF_REPO),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        **options,
    )


def running_as_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0


class UserErrors(TempFolderTestCase):
    def test_each_mistake_gets_a_plain_message_and_the_usage_code(self):
        folder = self.write("work/a.txt").parent
        file_path = self.write("plain.txt")
        token = self.temp / "missing.tsr"
        cases = [
            (("seal", self.temp / "nope", "--purpose", "p"), "does not exist"),
            (("seal", file_path, "--purpose", "p"), "seal takes a folder"),
            (("seal", folder), "--purpose"),
            (("seal", folder, "--purpose", "   "), "--purpose"),
            (("seal", folder, "--purpose", "p", "--date", "yesterday"), "--date"),
            (("seal", folder, "--purpose", "p", "--out", folder), "is a folder"),
            (("seal", folder, "--purpose", "p", "--exclude-from", self.temp / "none"), "cannot read"),
            (("seal", folder, "--purpose", "p", "--exclude", "/"), "nothing to match"),
            (("stamp", self.temp / "nope.txt"), "cannot read"),
            (("stamp", folder), "is a folder"),
            (("verify", self.temp / "nope.txt"), "does not exist"),
            (("verify", folder), "is a folder"),
            (("verify", file_path, "--token", token), "does not exist"),
            (("verify", file_path, "--folder", self.temp / "nope"), "is not a folder"),
            (("verify", file_path, "--ca", self.temp / "nope.crt"), "cannot read"),
            (("verify", file_path, "--ca", file_path), "certificate"),
            (("show", self.temp / "nope.tsr"), "cannot read"),
            (("show", folder), "is a folder"),
            (("report", self.temp / "nope.txt"), "does not exist"),
        ]
        for arguments, phrase in cases:
            with self.subTest(arguments[:2]):
                code, _, err = run_cli(*arguments)
                self.assertEqual(code, 2, err)
                self.assertIn(phrase, err)
                self.assertNotIn("Traceback", err)

    def test_no_stack_trace_in_a_real_process(self):
        done = run_process("verify", self.temp / "nope.txt")
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stderr.count("\n"), 1)
        self.assertNotIn("Traceback", done.stderr)

    def test_junk_given_as_a_token_or_manifest_is_a_verdict_not_a_crash(self):
        junk = self.write("junk.bin", bytes(range(256)) * 40)
        folder = self.write("work/a.txt").parent
        for path in (junk, self.write("empty.txt", b"")):
            with self.subTest(path.name):
                code, _, err = run_cli("verify", path, "--folder", folder, "--token", junk)
                self.assertIn(code, (1, 3), err)
                self.assertEqual(err, "")
        self.assertEqual(run_cli("show", junk)[0], 1)

    def test_shortened_options_are_refused(self):
        folder = self.write("work/a.txt").parent
        self.assertEqual(run_cli("seal", folder, "--purp", "p")[0], 2)
        self.assertEqual(run_cli("seal", folder, "--purpose", "p", "--for")[0], 2)

    def test_help_and_version(self):
        for arguments in (("--help",), ("seal", "--help"), ("stamp", "--help"), ("verify", "--help"), ("show", "--help"), ("report", "--help")):
            with self.subTest(arguments):
                code, out, _ = run_cli(*arguments)
                self.assertEqual(code, 0)
                self.assertIn("usage:", out)
        code, out, _ = run_cli("--version")
        self.assertEqual(code, 0)
        self.assertRegex(out, r"^evidence-seal \d+\.\d+\.\d+\n$")
        code, _, err = run_cli()
        self.assertEqual(code, 2)
        self.assertIn("COMMAND", err)


class NothingLost(TempFolderTestCase):
    def setUp(self):
        super().setUp()
        self.folder = self.write("work/a.txt", b"a\n").parent
        self.write("work/b.txt", b"b\n")
        self.out = self.temp / "m.txt"

    def leftovers(self):
        return sorted(path.name for path in self.temp.iterdir() if path.name != "work")

    def test_interrupted_seal_writes_nothing(self):
        with mock.patch("evidence_seal.scan.hash_all", side_effect=KeyboardInterrupt):
            code, _, err = run_cli("seal", self.folder, "--purpose", "p", "--out", self.out)
        self.assertEqual(code, 130)
        self.assertIn("Interrupted", err)
        self.assertEqual(self.leftovers(), [])

    def test_interrupt_while_writing_cleans_up_and_keeps_the_old_file(self):
        self.out.write_bytes(b"old manifest")
        with mock.patch("os.replace", side_effect=KeyboardInterrupt):
            code, _, _ = run_cli("seal", self.folder, "--purpose", "p", "--out", self.out, "--force")
        self.assertEqual(code, 130)
        self.assertEqual(self.out.read_bytes(), b"old manifest")
        self.assertEqual(self.leftovers(), ["m.txt"])

    @unittest.skipIf(os.name == "nt", "sending a real interrupt to one process needs POSIX signals")
    def test_a_real_interrupt_during_a_long_seal(self):
        big = self.temp / "big"
        big.mkdir()
        with open(big / "large.bin", "wb") as stream:
            stream.write(b"\0" * (1 << 26))
        process = subprocess.Popen(
            [sys.executable, "-c", "import time,sys;from evidence_seal import cli,scan\n"
             "real=scan.hash_file\n"
             "def slow(*a):\n"
             " print('started',flush=True);time.sleep(30);return real(*a)\n"
             "scan.hash_file=slow\n"
             "sys.exit(cli.main(sys.argv[1:]))", "seal", str(big), "--purpose", "p", "--out", str(self.out)],
            cwd=str(ROOT_OF_REPO),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(process.stdout.readline().strip(), "started")
        process.send_signal(signal.SIGINT)
        _, err = process.communicate(timeout=20)
        self.assertEqual(process.returncode, 130, err)
        self.assertIn("Interrupted", err)
        self.assertNotIn("Traceback", err)
        self.assertEqual(self.leftovers(), ["big"])

    def test_disk_full_while_writing_keeps_the_old_file(self):
        self.out.write_bytes(b"old manifest")
        with mock.patch("os.fsync", side_effect=OSError(errno.ENOSPC, "No space left on device")):
            code, _, err = run_cli("seal", self.folder, "--purpose", "p", "--out", self.out, "--force")
        self.assertEqual(code, 1)
        self.assertIn("No space left", err)
        self.assertIn("left as it was", err)
        self.assertEqual(self.out.read_bytes(), b"old manifest")
        self.assertEqual(self.leftovers(), ["m.txt"])

    def test_no_writable_place_is_found_before_any_hashing(self):
        with mock.patch("tempfile.mkstemp", side_effect=PermissionError(errno.EACCES, "Permission denied")):
            with mock.patch("evidence_seal.scan.hash_all") as hashing:
                code, _, err = run_cli("seal", self.folder, "--purpose", "p", "--out", self.out)
        self.assertEqual(code, 1)
        self.assertIn("--out", err)
        hashing.assert_not_called()

    @unittest.skipIf(os.name == "nt" or running_as_root(), "needs POSIX permissions and a non-root user")
    def test_really_read_only_folder_beside_the_seal(self):
        parent = self.temp / "locked"
        parent.mkdir()
        (parent / "work").mkdir()
        (parent / "work" / "a.txt").write_bytes(b"a\n")
        parent.chmod(0o555)
        self.addCleanup(parent.chmod, 0o755)
        code, _, err = run_cli("seal", parent / "work", "--purpose", "p")
        self.assertEqual(code, 1)
        self.assertIn("--out", err)

    @unittest.skipIf(os.name == "nt" or running_as_root(), "needs POSIX permissions and a non-root user")
    def test_really_unreadable_files_are_all_named_and_stop_the_seal(self):
        for name in ("a.txt", "b.txt"):
            path = self.folder / name
            path.chmod(0)
            self.addCleanup(path.chmod, 0o644)
        code, _, err = run_cli("seal", self.folder, "--purpose", "p", "--out", self.out)
        self.assertEqual(code, 1)
        self.assertIn("a.txt", err)
        self.assertIn("b.txt", err)
        self.assertFalse(self.out.exists())

    def test_every_locked_file_is_named_before_hashing_starts(self):
        original = open

        def locked(path, *args, **kwargs):
            if str(path).endswith((".txt",)) and "work" in str(path):
                raise PermissionError(errno.EACCES, "The process cannot access the file")
            return original(path, *args, **kwargs)

        with mock.patch("evidence_seal.scan.hash_all") as hashing, mock.patch("builtins.open", locked):
            code, _, err = run_cli("seal", self.folder, "--purpose", "p", "--out", self.out)
        self.assertEqual(code, 1)
        self.assertIn("a.txt", err)
        self.assertIn("b.txt", err)
        self.assertIn("--exclude", err)
        self.assertFalse(self.out.exists())
        hashing.assert_not_called()

    def test_a_long_list_of_problems_is_cut_short_with_a_count(self):
        result = scan.WalkResult(errors=[(f"f{index}", "denied") for index in range(25)])
        with self.assertRaises(SealError) as caught:
            scan.require_clean_walk(result)
        self.assertIn("and 5 more", str(caught.exception))

    def test_file_changed_during_sealing_stops_it(self):
        original = scan.hash_file

        def changing(path, algorithm, meter=None):
            answer = original(path, algorithm, meter)
            Path(path).write_bytes(b"different and longer\n")
            return answer

        with mock.patch("evidence_seal.scan.hash_file", changing):
            code, _, err = run_cli("seal", self.folder, "--purpose", "p", "--out", self.out)
        self.assertEqual(code, 1)
        self.assertIn("changed while it was being read", err)
        self.assertFalse(self.out.exists())

    def test_replacing_a_manifest_that_has_a_token_is_refused_even_with_force(self):
        self.assertEqual(run_cli("seal", self.folder, "--purpose", "p", "--out", self.out)[0], 0)
        before = self.out.read_bytes()
        token = self.write("m.tsr", b"a token")
        self.write("work/c.txt", b"c\n")
        code, _, err = run_cli("seal", self.folder, "--purpose", "q", "--out", self.out, "--force")
        self.assertEqual(code, 1)
        self.assertIn("worthless", err)
        self.assertEqual(self.out.read_bytes(), before)
        self.assertEqual(token.read_bytes(), b"a token")

    def test_force_works_when_no_token_depends_on_the_manifest(self):
        self.assertEqual(run_cli("seal", self.folder, "--purpose", "p", "--out", self.out)[0], 0)
        self.assertEqual(run_cli("seal", self.folder, "--purpose", "q", "--out", self.out, "--force")[0], 0)
        self.assertIn(b"purpose: q", self.out.read_bytes())

    def test_report_cannot_overwrite_what_it_reads(self):
        self.assertEqual(run_cli("seal", self.folder, "--purpose", "p", "--out", self.out)[0], 0)
        before = self.out.read_bytes()
        token = self.write("m.tsr", b"a token")
        for target in (self.out, token):
            with self.subTest(target.name):
                code, _, err = run_cli("report", self.out, "--out", target, "--force")
                self.assertEqual(code, 2)
                self.assertIn("overwrite", err)
        self.assertEqual(self.out.read_bytes(), before)
        self.assertEqual(token.read_bytes(), b"a token")

    def test_keep_copy_failure_replaces_nothing(self):
        path = self.write("m.tsq", b"old")
        with mock.patch("shutil.copy2", side_effect=OSError(errno.ENOSPC, "No space left on device")):
            with self.assertRaises(ManifestError):
                sealing.keep_copy_of(path, b"new")
        self.assertEqual(path.read_bytes(), b"old")

    @unittest.skipIf(os.name == "nt", "file modes are a POSIX matter")
    def test_written_files_follow_the_usual_permissions(self):
        previous = os.umask(0o022)
        self.addCleanup(os.umask, previous)
        self.assertEqual(run_cli("seal", self.folder, "--purpose", "p", "--out", self.out)[0], 0)
        self.assertEqual(stat.S_IMODE(os.stat(self.out).st_mode), 0o644)

    @unittest.skipIf(os.name == "nt", "file modes are a POSIX matter")
    def test_replacing_a_file_keeps_its_permissions(self):
        self.out.write_bytes(b"old")
        self.out.chmod(0o600)
        self.assertEqual(run_cli("seal", self.folder, "--purpose", "p", "--out", self.out, "--force")[0], 0)
        self.assertEqual(stat.S_IMODE(os.stat(self.out).st_mode), 0o600)


class BugsAndPipes(TempFolderTestCase):
    def test_a_bug_is_not_a_verdict_and_prints_no_stack_trace(self):
        folder = self.write("work/a.txt").parent
        with mock.patch("evidence_seal.verification.verify", side_effect=RuntimeError("boom")):
            code, _, err = run_cli("verify", self.write("m.txt"), "--folder", folder)
        self.assertEqual(code, 4)
        self.assertIn("bug in evidence-seal", err)
        self.assertNotIn("Traceback", err)

    def test_debug_setting_prints_the_trace(self):
        with mock.patch.dict(os.environ, {"EVIDENCE_SEAL_DEBUG": "1"}):
            with mock.patch("evidence_seal.verification.verify", side_effect=RuntimeError("boom")):
                code, _, err = run_cli("verify", self.write("m.txt"))
        self.assertEqual(code, 4)
        self.assertIn("Traceback", err)

    def test_a_system_error_is_plain_and_reaches_no_verdict(self):
        error = OSError(errno.EIO, "Input/output error", "disk-file")
        with mock.patch("evidence_seal.verification.verify", side_effect=error):
            code, _, err = run_cli("verify", self.write("m.txt"))
        self.assertEqual(code, 2)
        self.assertIn("Input/output error", err)
        self.assertIn("No verdict", err)

    def test_closed_output_pipe_is_quiet(self):
        folder = self.temp / "many"
        folder.mkdir()
        for index in range(3000):
            (folder / f"file-with-a-fairly-long-name-{index:05}.txt").write_bytes(b"")
        process = subprocess.Popen(
            [sys.executable, "-m", "evidence_seal", "seal", str(folder), "--dry-run"],
            cwd=str(ROOT_OF_REPO),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        process.stdout.close()
        err = process.stderr.read()
        process.stderr.close()
        process.wait(timeout=60)
        self.assertEqual(process.returncode, 2, err)
        self.assertEqual(err, "")

    def test_console_that_cannot_show_a_name_does_not_crash(self):
        folder = self.temp / "w"
        folder.mkdir()
        (folder / "caf\u00e9-\u6f22\u5b57-\U0001f600.txt").write_bytes(b"x")
        environment = dict(os.environ, PYTHONIOENCODING="ascii")
        done = run_process("seal", folder, "--dry-run", env=environment)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("caf\\xe9", done.stdout)
        out = self.temp / "m.txt"
        self.assertEqual(run_process("seal", folder, "--purpose", "caf\u00e9", "--out", out, env=environment).returncode, 0)
        done = run_process("verify", out, "--folder", folder, "--json", env=environment)
        self.assertEqual(done.returncode, 3, done.stderr)
        data = json.loads(done.stdout)
        self.assertEqual(data["manifest"]["purpose"], "caf\u00e9")
        self.assertEqual(data["schema_version"], 1)


class FormatVersions(TempFolderTestCase):
    def test_a_newer_manifest_format_is_not_a_failure_or_a_pass(self):
        path = self.write("work-manifest.txt", b"evidence-seal manifest v2\nnew-header: something\n\nnew lines\n")
        self.write("work/a.txt")
        code, text, _ = run_cli("verify", path, "--json")
        data = json.loads(text)
        self.assertEqual(code, 3)
        self.assertEqual(data["files"]["status"], "not checked")
        self.assertIn("format v2", data["files"]["detail"])

    def test_a_newer_format_is_not_mistaken_for_v1_or_for_a_hand_made_list(self):
        for version in (b"v2", b"v12", b"v999"):
            parsed = manifest.parse(b"evidence-seal manifest " + version + b"\n" + b"a" * 64 + b"  f\n")
            self.assertEqual(parsed.kind, manifest.NATIVE)
            self.assertEqual(parsed.entries, [])
            self.assertIsNotNone(parsed.newer_version)

    def test_a_manifest_from_version_one_still_verifies_its_files(self):
        # These bytes are frozen. A later release must keep reading them.
        path = ROOT_OF_REPO / "tests" / "fixtures" / "sample-manifest.txt"
        folder = ROOT_OF_REPO / "tests" / "fixtures" / "sample-folder"
        parsed = manifest.read_manifest(path)
        self.assertEqual(parsed.problems, [])
        code, text, _ = run_cli("verify", path, "--folder", folder, "--json")
        self.assertEqual(json.loads(text)["files"]["status"], "pass", text)
        self.assertEqual(code, 3)


class Progress(TempFolderTestCase):
    def test_nothing_is_shown_unless_output_is_a_terminal(self):
        folder = self.write("w/a.txt", b"x").parent
        done = run_process("seal", folder, "--purpose", "p", "--out", self.temp / "m.txt")
        self.assertEqual(done.returncode, 0)
        self.assertEqual(done.stderr, "")

    def test_a_terminal_sees_counts_at_most_once_a_second(self):
        written = []

        class Terminal:
            def isatty(self):
                return True

            def write(self, text):
                written.append(text)

            def flush(self):
                pass

        with mock.patch.object(sys, "stderr", Terminal()):
            report = cli._progress("Hashed")
            meter = scan.Meter(report, 2, 2048)
            meter.add_bytes(1024)
            self.assertEqual(written, [])
            with mock.patch.object(time, "monotonic", lambda: time.perf_counter() + 1e9):
                meter.add_file()
            cli._clear_progress(report)
        self.assertIn("Hashed 1 of 2 files", written[0])
        self.assertTrue(written[-1].endswith("\r"))
