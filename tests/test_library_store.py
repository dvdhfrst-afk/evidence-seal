"""The seal library's storage: the index, the copies, schema upgrades, damage and two commands at once."""

import hashlib
import os
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest import mock

from evidence_seal import library
from evidence_seal.library import LibraryError, NewerLibrary
from tests.library_support import LibraryTestCase
from tests.support import ROOT_OF_REPO, run_cli


def _table(name):
    def step(connection):
        connection.execute(f"CREATE TABLE {name} (value TEXT)")
        connection.execute(f"INSERT INTO {name} VALUES ('made by step')")

    return step


def _failing_step(connection):
    connection.execute("CREATE TABLE half_done (value TEXT)")
    raise RuntimeError("step three broke")


TEST_STEPS = ((1, library._create_schema_1), (2, _table("second")), (3, _table("third")))


class Opening(LibraryTestCase):
    def test_first_open_creates_schema_one_and_nothing_else(self):
        with self.open() as opened:
            self.assertEqual(opened.schema_version(), 1)
        self.assertEqual(sorted(path.name for path in self.root.iterdir()), [library.INDEX_NAME])
        with self.open() as opened:
            self.assertEqual(opened.counts(), {"seals": 0, "tokens": 0, "runs": 0, "objects": 0})
        self.assertEqual(sorted(path.name for path in self.root.iterdir()), [library.INDEX_NAME], "no backup at the same schema")

    def test_reading_without_a_library_creates_nothing(self):
        self.assertIsNone(library.open_library(create=False))
        self.assertFalse(self.home.exists())

    def test_the_library_lives_under_the_home_folder(self):
        self.assertEqual(library.library_root(), self.root)

    def test_the_index_path_being_a_folder_is_plain(self):
        self.index.mkdir(parents=True)
        with self.assertRaises(LibraryError) as caught:
            self.open()
        self.assertIn("not a regular file", str(caught.exception))
        self.assertIn("Nothing was changed", str(caught.exception))

    @mock.patch.object(library, "MAX_PATH_LENGTH", 10)
    def test_a_path_too_long_to_keep_is_left_out(self):
        self.assertIsNone(library._path_text(self.temp / "a-long-name"))

    def test_a_name_that_is_not_valid_text_comes_back_exactly(self):
        odd = os.path.abspath(str(self.temp / "bad\udcffname"))
        stored = library._path_text(Path(odd))
        self.assertIsInstance(stored, bytes)
        self.assertEqual(library.path_of(stored), odd)
        plain = os.path.abspath(str(self.temp / "plain name"))
        self.assertEqual(library._path_text(Path(plain)), plain)


class Objects(LibraryTestCase):
    def setUp(self):
        super().setUp()
        self.library = self.open()
        self.addCleanup(self.library.close)

    def store(self, kind, data):
        with self.library.transaction():
            return self.library._store(kind, data)

    def test_copies_are_named_by_their_hash_and_read_back(self):
        sha = self.store(library.ROOT, b"root bytes")
        self.assertEqual(sha, hashlib.sha256(b"root bytes").hexdigest())
        path = self.library.object_path(sha)
        self.assertEqual(path, self.root / "objects" / sha[:2] / sha)
        self.assertEqual(path.read_bytes(), b"root bytes")
        self.assertEqual(self.library.read_object(sha, library.ROOT), b"root bytes")
        self.assertEqual([item.name for item in path.parent.iterdir()], [sha], "no temporary file is left")

    def test_a_damaged_copy_is_refused_when_read_and_repaired_when_seen_again(self):
        sha = self.store(library.ROOT, b"root bytes")
        path = self.library.object_path(sha)
        path.write_bytes(b"root byteS")
        with self.assertRaises(LibraryError) as caught:
            self.library.read_object(sha, library.ROOT)
        self.assertIn("damaged", str(caught.exception))
        self.assertIn(str(path), str(caught.exception))
        self.store(library.ROOT, b"root bytes")
        self.assertEqual(self.library.read_object(sha, library.ROOT), b"root bytes")

    def test_a_missing_copy_is_plain(self):
        sha = self.store(library.ROOT, b"gone soon")
        os.unlink(self.library.object_path(sha))
        with self.assertRaises(LibraryError) as caught:
            self.library.read_object(sha, library.ROOT)
        self.assertIn("missing", str(caught.exception))

    def test_a_copy_grown_past_its_limit_is_refused(self):
        sha = self.store(library.REQUEST, b"small")
        self.library.object_path(sha).write_bytes(b"x" * (library.OBJECT_LIMITS[library.REQUEST] + 1))
        with self.assertRaises(LibraryError):
            self.library.read_object(sha, library.REQUEST)

    def test_sizes_are_bounded(self):
        with self.assertRaises(LibraryError) as caught:
            self.store(library.REQUEST, b"x" * (library.OBJECT_LIMITS[library.REQUEST] + 1))
        self.assertIn("too large", str(caught.exception))
        big = self.write("big.tsr", b"x" * 100)
        with mock.patch.dict(library.OBJECT_LIMITS, {library.TOKEN: 99}):
            with self.assertRaises(LibraryError):
                library.read_bounded(big, library.TOKEN)

    def test_object_names_cannot_leave_the_copies_folder(self):
        for name in ("../../index.sqlite3", "A" * 64, "0" * 63, ""):
            with self.subTest(name), self.assertRaises(LibraryError):
                self.library.object_path(name)

    def test_a_failed_transaction_records_nothing(self):
        with self.assertRaises(RuntimeError):
            with self.library.transaction():
                self.library._store(library.ROOT, b"never committed")
                raise RuntimeError("stop")
        self.assertEqual(self.library.counts()["objects"], 0)


class Migrations(LibraryTestCase):
    def setUp(self):
        super().setUp()
        self.root.mkdir(parents=True)

    def connect(self):
        connection = library._connect(self.index)
        self.addCleanup(connection.close)
        return connection

    def at_schema_one(self):
        connection = self.connect()
        library.migrate(connection, self.index, TEST_STEPS[:1])
        connection.execute("INSERT INTO objects VALUES (?, 'root', 1, 'then')", ("ab" * 32,))
        return connection

    def backups(self):
        return sorted(path for path in self.root.iterdir() if ".backup-" in path.name)

    def test_a_new_index_goes_straight_to_the_newest_schema_with_no_backup(self):
        connection = self.connect()
        self.assertIsNone(library.migrate(connection, self.index, TEST_STEPS))
        self.assertEqual(library._user_version(connection), 3)
        self.assertEqual(connection.execute("SELECT value FROM third").fetchone()[0], "made by step")
        self.assertEqual(self.backups(), [])

    def test_upgrading_one_to_two_then_two_to_three_keeps_a_backup_of_each(self):
        connection = self.at_schema_one()
        first = library.migrate(connection, self.index, TEST_STEPS[:2])
        self.assertEqual(library._user_version(connection), 2)
        self.assertIn("backup-schema1-", first.name)
        second = library.migrate(connection, self.index, TEST_STEPS)
        self.assertEqual(library._user_version(connection), 3)
        self.assertIn("backup-schema2-", second.name)
        self.assertEqual(self.backups(), sorted([first, second]))
        old = sqlite3.connect(str(first))
        try:
            self.assertEqual(old.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertEqual(old.execute("SELECT count(*) FROM objects").fetchone()[0], 1)
        finally:
            old.close()
        self.assertIsNone(library.migrate(connection, self.index, TEST_STEPS), "nothing to do the second time")

    def test_a_failure_in_the_middle_rolls_everything_back_and_keeps_the_backup(self):
        connection = self.at_schema_one()
        steps = (TEST_STEPS[0], TEST_STEPS[1], (3, _failing_step))
        with self.assertRaises(LibraryError) as caught:
            library.migrate(connection, self.index, steps)
        message = str(caught.exception)
        self.assertIn("from schema 1 failed at the step to schema 3", message)
        self.assertIn("step three broke", message)
        self.assertIn("left at schema 1", message)
        self.assertEqual(library._user_version(connection), 1)
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master")}
        self.assertNotIn("second", tables, "step 2 was rolled back too")
        self.assertNotIn("half_done", tables)
        self.assertEqual(connection.execute("SELECT count(*) FROM objects").fetchone()[0], 1)
        self.assertEqual(len(self.backups()), 1)
        self.assertIn(str(self.backups()[0]), message)

    def test_an_interrupt_in_a_step_rolls_back_and_is_not_swallowed(self):
        connection = self.at_schema_one()

        def interrupted(conn):
            conn.execute("CREATE TABLE partial (value TEXT)")
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            library.migrate(connection, self.index, (TEST_STEPS[0], (2, interrupted)))
        self.assertEqual(library._user_version(connection), 1)
        self.assertNotIn("partial", {row[0] for row in connection.execute("SELECT name FROM sqlite_master")})

    def test_a_process_killed_during_an_upgrade_leaves_the_old_schema(self):
        connection = self.at_schema_one()
        connection.close()
        script = (
            "import os, sys\n"
            "from pathlib import Path\n"
            "from evidence_seal import library\n"
            "def dies(connection):\n"
            "    connection.execute('CREATE TABLE doomed (value TEXT)')\n"
            "    connection.executemany('INSERT INTO doomed VALUES (?)', [('x' * 500,)] * 2000)\n"
            "    os._exit(9)\n"
            "index = Path(sys.argv[1])\n"
            "library.migrate(library._connect(index), index, ((1, library._create_schema_1), (2, dies)))\n"
        )
        done = subprocess.run(
            [sys.executable, "-c", script, str(self.index)], cwd=str(ROOT_OF_REPO), timeout=60, capture_output=True
        )
        self.assertEqual(done.returncode, 9, done.stderr)
        reopened = self.connect()
        self.assertEqual(library._user_version(reopened), 1)
        self.assertNotIn("doomed", {row[0] for row in reopened.execute("SELECT name FROM sqlite_master")})
        self.assertEqual(reopened.execute("SELECT count(*) FROM objects").fetchone()[0], 1)
        self.assertEqual(len(self.backups()), 1)
        self.assertEqual(library.migrate(reopened, self.index, TEST_STEPS[:2]).name.count("backup-schema1-"), 1)
        self.assertEqual(library._user_version(reopened), 2)

    def test_a_newer_schema_is_refused_and_never_written(self):
        connection = self.connect()
        library.migrate(connection, self.index, TEST_STEPS)
        connection.close()
        before = self.index.read_bytes()
        with self.assertRaises(NewerLibrary) as caught:
            library.open_library()
        message = str(caught.exception)
        self.assertIn("uses schema 3", message)
        self.assertIn("knows schema 1 at most", message)
        self.assertIn("left exactly as it was", message)
        self.assertEqual(self.index.read_bytes(), before)
        self.assertEqual(self.backups(), [])

    def test_a_command_meeting_a_newer_library_still_does_its_job(self):
        connection = self.connect()
        library.migrate(connection, self.index, TEST_STEPS)
        connection.close()
        before = self.index.read_bytes()
        folder = self.make_folder()
        code, out, err = run_cli("seal", folder, "--purpose", "p", "--out", self.temp / "m.txt")
        self.assertEqual(code, 0)
        self.assertIn("Sealed 2 files", out)
        self.assertEqual(err.count("\n"), 1, err)
        self.assertIn("uses schema 3", err)
        self.assertEqual(self.index.read_bytes(), before)

    def test_another_database_is_not_taken_for_a_library(self):
        connection = self.connect()
        connection.execute("CREATE TABLE someone_elses (value TEXT)")
        connection.close()
        before = self.index.read_bytes()
        with self.assertRaises(LibraryError) as caught:
            library.open_library()
        self.assertIn("not an evidence-seal library", str(caught.exception))
        self.assertEqual(self.index.read_bytes(), before)

    def test_steps_must_be_numbered_in_order(self):
        with self.assertRaises(ValueError):
            library.migrate(self.connect(), self.index, ((1, _table("a")), (3, _table("b"))))

    def test_the_product_ships_schema_one_only(self):
        self.assertEqual([target for target, _ in library.MIGRATIONS], [1])


class DamagedIndex(LibraryTestCase):
    def assert_plain_refusal(self, data):
        self.root.mkdir(parents=True, exist_ok=True)
        self.index.write_bytes(data)
        with self.assertRaises(LibraryError) as caught:
            library.open_library()
        message = str(caught.exception)
        self.assertIn(str(self.index), message)
        self.assertIn("Nothing was changed", message)
        self.assertEqual(self.index.read_bytes(), data)
        return message

    def test_garbage_is_named_and_left_alone(self):
        message = self.assert_plain_refusal(b"this is not a database at all, just some text\n" * 100)
        self.assertIn("damaged", message)

    def test_a_cut_off_index_is_named_and_left_alone(self):
        with self.open() as opened:
            for number in range(40):
                with opened.transaction():
                    opened._store(library.ROOT, b"root %d" % number)
        data = self.index.read_bytes()
        os.unlink(self.index)
        self.assert_plain_refusal(data[:100] + b"\xff" * 4000)

    def test_check_finds_damage_inside_a_readable_index(self):
        with self.open() as opened:
            with opened.transaction():
                opened._store(library.ROOT, b"root")
            opened._run("PRAGMA foreign_keys = OFF")
            opened._run("INSERT INTO tokens VALUES (?, ?, NULL, NULL, NULL, 1, NULL, NULL, NULL, 'now')", ("c" * 64, "d" * 64))
            problems = opened.check()
        self.assertTrue(any("refers to something missing" in problem for problem in problems), problems)

    def test_a_command_with_a_damaged_index_still_does_its_job(self):
        self.root.mkdir(parents=True)
        self.index.write_bytes(b"garbage" * 1000)
        folder = self.make_folder()
        code, out, err = run_cli("seal", folder, "--purpose", "p", "--out", self.temp / "m.txt")
        self.assertEqual(code, 0)
        self.assertTrue(err.startswith("warning: the seal library did not record this run:"), err)
        self.assertIn(str(self.index), err)
        self.assertEqual(self.index.read_bytes(), b"garbage" * 1000)


class TwoAtOnce(LibraryTestCase):
    def test_a_writer_waits_for_another_and_both_land(self):
        with self.open():
            pass
        holding = threading.Event()
        release = threading.Event()

        def hold():
            with library.open_library() as first, first.transaction():
                first._store(library.ROOT, b"first")
                holding.set()
                release.wait(10)

        thread = threading.Thread(target=hold)
        thread.start()
        self.assertTrue(holding.wait(10))
        threading.Timer(0.3, release.set).start()
        started = time.monotonic()
        with self.open() as second, second.transaction():
            second._store(library.ROOT, b"second")
        thread.join(10)
        self.assertGreater(time.monotonic() - started, 0.2, "the second writer waited")
        with self.open() as opened:
            self.assertEqual(opened.counts()["objects"], 2)

    def test_a_writer_that_waits_too_long_gives_up_plainly(self):
        with self.open():
            pass
        holding = threading.Event()
        release = threading.Event()

        def hold():
            with library.open_library() as first, first.transaction():
                holding.set()
                release.wait(10)

        thread = threading.Thread(target=hold)
        thread.start()
        self.addCleanup(thread.join, 10)
        self.addCleanup(release.set)
        self.assertTrue(holding.wait(10))
        with mock.patch.object(library, "BUSY_SECONDS", 0.2), self.open() as second:
            with self.assertRaises(LibraryError) as caught:
                with second.transaction():
                    pass
        self.assertIn("busy", str(caught.exception))
        self.assertIn("Nothing was changed", str(caught.exception))

    def test_many_seals_recorded_from_two_threads_at_once(self):
        manifests = []
        for number in range(12):
            folder = self.make_folder(f"w{number}", {"a.txt": b"%d\n" % number})
            manifests.append((self.seal(folder, None, "--no-library"), folder))
        failures = []

        def record(items):
            for manifest_path, folder in items:
                try:
                    library.record_seal(manifest_path, folder)
                except Exception as exc:  # Collected, so the test can show it
                    failures.append(exc)

        threads = [threading.Thread(target=record, args=(manifests[part::2],)) for part in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)
        self.assertEqual(failures, [])
        with self.open() as opened:
            self.assertEqual(opened.counts()["seals"], 12)
            self.assertEqual(opened.check(), [])
