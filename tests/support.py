"""Helpers shared by the tests."""

import contextlib
import io
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from evidence_seal import cli, home, openssl_bridge

# tests/__init__.py gives every run a home folder of its own; this makes sure of it for a test run alone.
assert os.environ.get(home.ENVIRONMENT_VARIABLE), "the tests must not use a real evidence-seal home folder"

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


class HomeTestCase(TempFolderTestCase):
    """A private folder and a home folder of its own, so the authority list starts empty in every test.

    Proxies are turned off too, because the servers these tests talk to are on this computer.
    """

    def setUp(self):
        super().setUp()
        self.home = self.temp / "home"
        environment = {home.ENVIRONMENT_VARIABLE: str(self.home), "no_proxy": "*", "NO_PROXY": "*"}
        patcher = mock.patch.dict(os.environ, environment)
        patcher.start()
        self.addCleanup(patcher.stop)
