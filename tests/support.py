"""Helpers shared by the tests."""

import contextlib
import io
import shutil
import tempfile
import unittest
from pathlib import Path

from evidence_seal import cli, openssl_bridge

ROOT_OF_REPO = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"
LOCAL = FIXTURES / "local-authority"
SAMPLE_FOLDER = FIXTURES / "sample-folder"
SAMPLE_MANIFEST = FIXTURES / "sample-manifest.txt"
HANDMADE_MANIFEST = FIXTURES / "handmade-manifest.txt"


def requires_openssl(test):
    """Marks a test that needs openssl, with a clear message when it is absent."""
    available = openssl_bridge.find_openssl() is not None
    return unittest.skipUnless(available, "openssl is not on the path; this test compares against it")(test)


def run_cli(*arguments):
    """Runs the command line in-process. Returns exit code, stdout and stderr."""
    out = io.StringIO()
    err = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main([str(item) for item in arguments])
        except SystemExit as stop:
            code = stop.code
    return code, out.getvalue(), err.getvalue()


class TempFolderTestCase(unittest.TestCase):
    """Gives each test a private folder that is removed afterwards."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="evidence-seal-test-")
        self.addCleanup(self._temp.cleanup)
        self.temp = Path(self._temp.name)

    def write(self, relative, data=b"content\n"):
        path = self.temp / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def copy_sample(self):
        """A private copy of the sample folder and its manifest, side by side."""
        folder = self.temp / "sample-folder"
        shutil.copytree(SAMPLE_FOLDER, folder)
        manifest = self.temp / "sample-manifest.txt"
        shutil.copyfile(SAMPLE_MANIFEST, manifest)
        return folder, manifest
