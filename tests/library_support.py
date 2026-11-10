"""Helpers for the seal library tests: a private home folder per test, and offline stamping."""

import os
import sqlite3
from unittest import mock

from evidence_seal import library
from tests.support import TempFolderTestCase, run_cli
from tests.test_stamp_and_report import FakeAuthority


class LibraryTestCase(TempFolderTestCase):
    """Each test gets its own home folder, so its library starts empty, and recording is on."""

    def setUp(self):
        super().setUp()
        self.home = self.temp / "home"
        environment = {key: value for key, value in os.environ.items() if key != library.SWITCH_VARIABLE}
        environment["EVIDENCE_SEAL_HOME"] = str(self.home)
        patcher = mock.patch.dict(os.environ, environment, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.root = self.home / "library"
        self.index = self.root / library.INDEX_NAME
        self.authority = FakeAuthority()
        self.ca = self.write("trusted-root.der", self.authority.authority.root)

    def open(self):
        return library.open_library()

    def make_folder(self, name="work", files=None):
        files = files or {"a.txt": b"first\n", "sub/b.bin": b"\x00\x01\x02"}
        for relative, data in files.items():
            self.write(f"{name}/{relative}", data)
        return self.temp / name

    def seal(self, folder, name=None, *extra):
        out = self.temp / (name or f"{folder.name}-manifest.txt")
        code, _, err = run_cli("seal", folder, "--purpose", f"purpose of {folder.name}", "--out", out, *extra)
        self.assertEqual(code, 0, err)
        return out

    def stamp(self, manifest_path, *extra):
        with mock.patch("evidence_seal.stamping._open_url", self.authority):
            return run_cli("stamp", manifest_path, *extra)

    def sealed_and_stamped(self, name="work"):
        folder = self.make_folder(name)
        manifest_path = self.seal(folder)
        code, _, err = self.stamp(manifest_path)
        self.assertEqual(code, 0, err)
        return folder, manifest_path

    def rows(self, sql, parameters=()):
        connection = sqlite3.connect(str(self.index))
        try:
            return connection.execute(sql, parameters).fetchall()
        finally:
            connection.close()

    def only_seal(self):
        with self.open() as opened:
            found = opened.seals()
        self.assertEqual(len(found), 1, found)
        return found[0]
