"""Keeps the documents true: every command in them parses, and the worked examples do what they say."""

import json
import re
import shlex
import shutil
import unittest
from pathlib import Path

import evidence_seal
from evidence_seal import cli
from tests.support import ROOT_OF_REPO, TempFolderTestCase, run_cli

EXAMPLES = ROOT_OF_REPO / "examples"
MY_WORK = EXAMPLES / "my-work"
SEALED = EXAMPLES / "sealed"
SEALED_MANIFEST = SEALED / "my-work-manifest.txt"
SEALED_ROOT = SEALED / "test-authority-root.crt"
DOCUMENTS = ["README.md", "CONTRIBUTING.md", "SECURITY.md", "docs/FORMAT.md", "docs/REPORTS.md", "docs/CI.md", "examples/README.md"]


def fenced_commands(path):
    inside = False
    kind = ""
    for line in (ROOT_OF_REPO / path).read_text(encoding="utf-8").splitlines():
        if line.startswith("```"):
            inside = not inside
            kind = line[3:].strip() if inside else ""
        elif inside and kind == "bash":
            yield line.strip()


class Documents(unittest.TestCase):
    def test_every_documented_command_parses(self):
        count = 0
        for path in DOCUMENTS:
            for line in fenced_commands(path):
                parts = shlex.split(line)
                if parts[:3] == ["python", "-m", "evidence_seal"]:
                    arguments = parts[3:]
                elif parts[:1] == ["evidence-seal"]:
                    arguments = parts[1:]
                else:
                    continue
                count += 1
                with self.subTest(line):
                    if "--help" in arguments or "--version" in arguments:
                        self.assertEqual(run_cli(*arguments)[0], 0)
                    else:
                        cli.build_parser().parse_args(arguments)
        self.assertGreater(count, 12)

    def test_no_document_chains_commands(self):
        for path in DOCUMENTS:
            for line in fenced_commands(path):
                for token in ("&&", "||", "; "):
                    self.assertNotIn(token, line, f"{path}: {line}")

    def test_every_exit_code_is_documented(self):
        text = (ROOT_OF_REPO / "README.md").read_text(encoding="utf-8")
        for row in ("| VERIFIED | 0 |", "| FAILED | 1 |", "| (no verdict) | 2 |", "| INCOMPLETE | 3 |", "| (a bug) | 4 |", "| (interrupted) | 130 |"):
            self.assertIn(row, text)

    def test_the_version_is_stated_once(self):
        project = (ROOT_OF_REPO / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('dynamic = ["version"]', project)
        self.assertIn('version = { attr = "evidence_seal.__version__" }', project)
        self.assertIn(f"## {evidence_seal.__version__} ", (ROOT_OF_REPO / "CHANGELOG.md").read_text(encoding="utf-8"))

    def test_the_readme_says_what_a_timestamp_does_not_prove(self):
        text = " ".join((ROOT_OF_REPO / "README.md").read_text(encoding="utf-8").split())
        for phrase in ("does **not** show", "Who wrote the files", "not legal advice", "What has been tested", "What has not been tested"):
            self.assertIn(phrase, text)

    def test_the_readme_sample_is_what_a_real_run_prints(self):
        text = (ROOT_OF_REPO / "README.md").read_text(encoding="utf-8")
        real = SEALED_MANIFEST.read_bytes().decode("utf-8")
        for line in real.splitlines():
            if re.match(r"^[0-9a-f]{64}  ", line) or line.startswith(("files:", "total-bytes:")):
                self.assertIn(line, text)


class Examples(TempFolderTestCase):
    def test_the_sample_files_kept_their_bytes(self):
        windows = (MY_WORK / "meeting-notes.txt").read_bytes()
        self.assertEqual(windows.count(b"\n"), windows.count(b"\r\n"))
        self.assertGreater(windows.count(b"\r\n"), 0)
        self.assertEqual((MY_WORK / "data" / "readings.bin").read_bytes(), bytes(range(256)))

    def test_the_ready_made_seal_verifies_with_its_root(self):
        code, out, err = run_cli("verify", SEALED_MANIFEST, "--folder", MY_WORK, "--ca", SEALED_ROOT)
        self.assertEqual(code, 0, out + err)
        self.assertIn("RESULT: VERIFIED", out)

    def test_the_test_authority_is_not_trusted_without_being_named(self):
        code, out, _ = run_cli("verify", SEALED_MANIFEST, "--folder", MY_WORK)
        self.assertEqual(code, 3)
        self.assertIn("RESULT: INCOMPLETE", out)

    def test_the_authority_names_itself_as_a_test(self):
        _, out, _ = run_cli("show", SEALED / "my-work-manifest.tsr")
        self.assertIn("TEST ONLY", out)

    def test_changing_any_file_fails_and_names_it(self):
        copy = self.temp / "my-work"
        shutil.copytree(MY_WORK, copy)
        target = copy / "plans.txt"
        target.write_bytes(target.read_bytes() + b"one more line\n")
        code, text, _ = run_cli("verify", SEALED_MANIFEST, "--folder", copy, "--ca", SEALED_ROOT, "--json")
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(text)["differences"]["changed"], ["plans.txt"])

    def test_the_quick_start_folder_seals_to_the_documented_bytes(self):
        out = self.temp / "m.txt"
        code, _, err = run_cli(
            "seal", MY_WORK, "--purpose", "My designs before the Acme meeting", "--date", "2026-11-07", "--out", out
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(out.read_bytes(), SEALED_MANIFEST.read_bytes())

    def test_the_sample_exclude_file_works(self):
        code, out, err = run_cli("seal", MY_WORK, "--dry-run", "--exclude-from", EXAMPLES / "excludes.txt")
        self.assertEqual(code, 0, err)
        self.assertIn("data/readings.bin", out)

    def test_the_seal_keeps_working_after_moving_everything(self):
        shutil.copytree(MY_WORK, self.temp / "elsewhere" / "my-work")
        target = self.temp / "elsewhere"
        for name in ("my-work-manifest.txt", "my-work-manifest.tsr"):
            shutil.copyfile(SEALED / name, target / name)
        code, out, err = run_cli("verify", target / "my-work-manifest.txt", "--ca", SEALED_ROOT)
        self.assertEqual(code, 0, out + err)
        self.assertTrue(Path(target / "my-work").is_dir())
