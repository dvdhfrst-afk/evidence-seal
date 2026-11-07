"""Keeps the repository portable, offline and honest about what it needs."""

import ast
import base64
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOP_FILES = ("README.md", "LICENSE", "pyproject.toml", "check.sh", ".gitignore", ".gitattributes")
TEXT_SUFFIXES = {".py", ".md", ".toml", ".sh"}
SOURCE_DIRS = ("evidence_seal", "tests")
ALLOWED_IMPORTS = {
    "argparse", "ast", "base64", "contextlib", "dataclasses", "datetime", "enum", "fnmatch", "glob", "hashlib",
    "html", "io", "json", "os", "pathlib", "random", "re", "secrets", "shlex", "shutil", "stat", "subprocess",
    "sys", "tempfile", "typing", "unittest", "urllib", "evidence_seal", "tests", "__future__",
}


def repo_files():
    for name in TOP_FILES:
        yield ROOT / name
    for folder in SOURCE_DIRS:
        for path in sorted((ROOT / folder).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and "sample-folder" not in path.parts:
                yield path


def python_files():
    return [path for path in repo_files() if path.suffix == ".py"]


class Sources(unittest.TestCase):
    def test_every_source_parses_as_python_39(self):
        files = python_files()
        self.assertGreater(len(files), 20)
        for path in files:
            with self.subTest(path.name):
                ast.parse(path.read_text(encoding="utf-8"), filename=str(path), feature_version=(3, 9))

    def test_only_the_standard_library_is_imported(self):
        for path in python_files():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    names = [node.module]
                for name in names:
                    self.assertIn(name.split(".")[0], ALLOWED_IMPORTS, f"{path}: {name}")

    def test_network_code_lives_in_one_module(self):
        for path in python_files():
            if path.parts[-2] != "evidence_seal":
                continue
            text = path.read_text(encoding="utf-8")
            if path.name != "stamping.py":
                self.assertNotIn("urllib", text, path.name)
                self.assertNotIn("socket", text, path.name)

    def test_other_programs_are_started_from_one_module(self):
        for path in python_files():
            if path.parts[-2] == "evidence_seal" and path.name != "openssl_bridge.py":
                self.assertNotIn("subprocess", path.read_text(encoding="utf-8"), path.name)

    def test_text_files_have_no_long_dashes_and_use_lf(self):
        long_dashes = (chr(0x2013), chr(0x2014))
        for path in repo_files():
            if path.suffix not in TEXT_SUFFIXES and path.name not in TOP_FILES:
                continue
            data = path.read_bytes()
            self.assertNotIn(b"\r\n", data, f"{path} must use LF line endings")
            text = data.decode("utf-8")
            for dash in long_dashes:
                self.assertNotIn(dash, text, str(path))

    def test_python_sources_are_plain_ascii(self):
        for path in python_files():
            path.read_bytes().decode("ascii")

    def test_no_unfinished_markers(self):
        markers = ("TO" + "DO", "FIX" + "ME", "X" + "XX")
        for path in python_files():
            text = path.read_text(encoding="utf-8")
            for marker in markers:
                self.assertNotIn(marker, text, str(path))

    def test_readme_never_chains_shell_commands(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        inside = False
        blocks = 0
        for line in text.splitlines():
            if line.startswith("```"):
                inside = not inside
                blocks += 1
            elif inside:
                for token in ("&&", "||", "; "):
                    self.assertNotIn(token, line, line)
        self.assertFalse(inside)
        self.assertGreater(blocks, 6)

    def test_git_never_alters_bytes(self):
        self.assertEqual((ROOT / ".gitattributes").read_text(encoding="ascii").split(), ["*", "-text"])

    def test_sample_folder_kept_its_line_endings(self):
        data = (ROOT / "tests" / "fixtures" / "sample-folder" / "windows-endings.txt").read_bytes()
        self.assertIn(b"\r\n", data)
        self.assertEqual(data.count(b"\n"), data.count(b"\r\n"))
        handmade = (ROOT / "tests" / "fixtures" / "handmade-manifest.txt").read_bytes()
        self.assertEqual(handmade.count(b"\n"), handmade.count(b"\r\n"))

    def test_no_private_key_material_is_committed(self):
        begin = b"-----BEGIN"
        for path in (ROOT / "tests" / "fixtures").rglob("*"):
            if path.is_file():
                data = path.read_bytes()
                if begin in data:
                    self.assertNotIn(b"PRIVATE KEY", data, str(path))
        self.assertEqual(list((ROOT / "tests" / "fixtures").rglob("*.key")), [])

    def test_test_authorities_say_test_only(self):
        from evidence_seal.x509 import load_certificates

        for path in (ROOT / "tests" / "fixtures" / "local-authority").glob("*.crt"):
            self.assertIn("TEST ONLY", load_certificates(path)[0].subject.display(), path.name)

    def test_no_file_contains_an_email_address(self):
        pattern = re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
        pem = re.compile(rb"-----BEGIN [A-Z ]+-----(.*?)-----END", re.DOTALL)
        for path in sorted(ROOT.rglob("*")):
            parts = path.relative_to(ROOT).parts
            if not path.is_file() or ".git" in parts or "__pycache__" in parts:
                continue
            data = path.read_bytes()
            forms = [data, data.replace(b"\x00", b"")]
            if path.suffix != ".py":
                forms += [base64.b64decode(block) for block in pem.findall(data)]
            for form in forms:
                self.assertIsNone(pattern.search(form), str(path))

    def test_readme_explains_a_hash_mismatch(self):
        text = " ".join((ROOT / "README.md").read_text(encoding="utf-8").split())
        self.assertIn("not by itself proof of tampering", text)


if __name__ == "__main__":
    unittest.main()
