"""The library command: every action, its errors, and import of odd and hostile folders."""

import hashlib
import json
import os
import shlex
import unittest
from pathlib import Path
from unittest import mock

from evidence_seal import cli, library, library_commands
from tests.library_support import LibraryTestCase
from tests.support import ROOT_OF_REPO, run_cli
from tests.test_docs_and_examples import fenced_commands


def lib_cli(*arguments):
    return run_cli("library", *arguments)


def snapshot(folder):
    """Every file under a folder with its bytes, to show that nothing beside the user's files changed."""
    return {
        path.relative_to(folder).as_posix(): path.read_bytes() for path in sorted(Path(folder).rglob("*")) if path.is_file()
    }


def sha_of(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class ListAndShow(LibraryTestCase):
    def test_an_empty_library_lists_nothing_and_creates_nothing(self):
        code, out, err = lib_cli("list")
        self.assertEqual(code, 0, err)
        self.assertIn("no seals yet", out)
        self.assertEqual(json.loads(lib_cli("list", "--json")[1]), {"schema_version": 1, "seals": []})
        self.assertFalse(self.home.exists())

    def test_list_shows_each_seal_with_its_token_and_last_check(self):
        _, stamped = self.sealed_and_stamped("one")
        self.assertEqual(run_cli("verify", stamped, "--ca", self.ca)[0], 0)
        plain = self.seal(self.make_folder("two"))
        code, out, _ = lib_cli("list")
        self.assertEqual(code, 0)
        self.assertIn(sha_of(stamped)[:12], out)
        self.assertIn(sha_of(plain)[:12], out)
        self.assertIn("2026-03-01 12:00:00 UTC", out)
        self.assertIn("VERIFIED", out)
        self.assertIn("never", out)
        self.assertIn("purpose of one", out)
        self.assertIn("2 seals.", out)
        data = json.loads(lib_cli("list", "--json")[1])["seals"]
        by_id = {item["manifest_sha256"]: item for item in data}
        self.assertEqual(by_id[sha_of(stamped)]["last_result"], "VERIFIED")
        self.assertIsNone(by_id[sha_of(plain)]["token_time"])
        self.assertEqual(by_id[sha_of(plain)]["file_count"], 2)

    def test_list_filters_by_folder_and_by_tag(self):
        first = self.make_folder("one")
        self.seal(first)
        second = self.seal(self.make_folder("two"))
        self.assertEqual(lib_cli("tag", sha_of(second)[:8], "client")[0], 0)
        by_folder = json.loads(lib_cli("list", "--folder", first, "--json")[1])["seals"]
        self.assertEqual([item["folder_name"] for item in by_folder], ["one"])
        by_tag = json.loads(lib_cli("list", "--tag", "client", "--json")[1])["seals"]
        self.assertEqual([item["manifest_sha256"] for item in by_tag], [sha_of(second)])
        self.assertIn("No seal in the library matches", lib_cli("list", "--tag", "nobody")[1])

    def test_show_tells_everything(self):
        _, manifest_path = self.sealed_and_stamped()
        run_cli("verify", manifest_path, "--ca", self.ca)
        lib_cli("tag", sha_of(manifest_path)[:6], "kept")
        code, out, err = lib_cli("show", sha_of(manifest_path)[:6])
        self.assertEqual(code, 0, err)
        for expected in (
            f"Seal {sha_of(manifest_path)}",
            "Purpose: purpose of work",
            "Files: 2, 9 bytes",
            "Tags: kept",
            "Tokens (1):",
            "(current)",
            "also kept: request, root copy",
            "VERIFIED (exit 0) by verify",
            "[PASS] Files match the manifest",
            "sealed: sealed 2 files",
            "stamped: token time 2026-03-01 12:00:00 UTC",
        ):
            self.assertIn(expected, out)
        data = json.loads(lib_cli("show", str(manifest_path), "--json")[1])
        self.assertEqual(data["seal"]["manifest_sha256"], sha_of(manifest_path))
        self.assertEqual(len(data["tokens"]), 1)
        self.assertEqual(data["runs"][0]["checks"][0]["status"], "pass")
        self.assertEqual([event["kind"] for event in data["events"]], ["tagged", "verified", "stamped", "sealed"])

    def test_ids_that_do_not_work_are_plain(self):
        manifest_path = self.seal(self.make_folder())
        cases = {
            "12345": "at least 6 hex digits",
            "not-hex!": "neither a seal ID nor a manifest file",
            "ffffffffff": "no seal in the library has an ID starting with ffffffffff",
        }
        if sha_of(manifest_path).startswith("ffffffffff"):
            self.skipTest("the manifest's hash happens to start with the unknown ID")
        for text, phrase in cases.items():
            with self.subTest(text):
                code, out, err = lib_cli("show", text)
                self.assertEqual(code, 2)
                self.assertIn(phrase, err)
                self.assertEqual(out, "")
        stranger = self.write("stranger.txt", b"not in the library\n")
        code, _, err = lib_cli("show", stranger)
        self.assertEqual(code, 2)
        self.assertIn("is not in the library", err)

    def test_an_ambiguous_prefix_lists_the_matches(self):
        with self.open() as opened, opened.transaction():
            for sha in ("abcdef" + "1" * 58, "abcdef" + "2" * 58):
                opened._run("INSERT INTO objects VALUES (?, 'manifest', 1, 'now')", (sha,))
                opened._run(
                    "INSERT INTO seals (manifest_sha256, purpose, file_count, manifest_kind, added_at)"
                    " VALUES (?, 'made up', 0, 'native', 'now')",
                    (sha,),
                )
        code, _, err = lib_cli("show", "ABCDEF")
        self.assertEqual(code, 2)
        self.assertIn("matches more than one seal", err)
        self.assertIn("abcdef111111", err)
        self.assertIn("abcdef222222", err)
        self.assertEqual(err.count("\n"), 1)
        self.assertEqual(lib_cli("show", "abcdef1")[0], 0)

    def test_asking_about_a_seal_with_no_library(self):
        for arguments in (("show", "abcdef"), ("tag", "abcdef", "x"), ("forget", "abcdef", "--yes"), ("verify", "abcdef")):
            with self.subTest(arguments):
                code, _, err = lib_cli(*arguments)
                self.assertEqual(code, 2)
                self.assertIn("the library is empty", err)
        self.assertFalse(self.home.exists())

    def test_every_action_has_help_with_exit_codes(self):
        for action in library_commands.ACTIONS:
            with self.subTest(action):
                code, out, _ = lib_cli(action, "--help")
                self.assertEqual(code, 0)
                self.assertIn("exit codes:", out)


class TagsLogWhere(LibraryTestCase):
    def test_tag_and_untag_say_what_changed(self):
        manifest_path = self.seal(self.make_folder())
        short = sha_of(manifest_path)[:12]
        self.assertIn(f"Tagged {short} with draft.", lib_cli("tag", short, "draft")[1])
        self.assertIn("already has the tag draft. Nothing changed.", lib_cli("tag", short, "draft")[1])
        self.assertIn("Removed the tag draft", lib_cli("untag", short, "draft")[1])
        self.assertIn("did not have the tag draft. Nothing changed.", lib_cli("untag", short, "draft")[1])
        for bad in ("", "   ", "a" * 65, "line\nbreak", "bell\x07"):
            with self.subTest(bad):
                code, _, err = lib_cli("tag", short, bad)
                self.assertEqual(code, 2)
                self.assertIn("a tag must be", err)

    def test_log_shows_the_journal_newest_first(self):
        manifest_path = self.seal(self.make_folder())
        lib_cli("tag", sha_of(manifest_path)[:6], "one")
        code, out, _ = lib_cli("log")
        self.assertEqual(code, 0)
        lines = out.splitlines()
        self.assertIn("tagged", lines[0])
        self.assertIn("sealed", lines[1])
        self.assertIn(sha_of(manifest_path)[:12], lines[1])
        self.assertEqual(len(lib_cli("log", "--limit", "1")[1].splitlines()), 1)
        events = json.loads(lib_cli("log", sha_of(manifest_path)[:6], "--json")[1])["events"]
        self.assertEqual([event["kind"] for event in events], ["tagged", "sealed"])
        self.assertEqual(events[0]["tool_version"], library.__version__)
        for bad in ("0", "abc", "10001"):
            with self.subTest(bad):
                self.assertEqual(lib_cli("log", "--limit", bad)[0], 2)

    def test_an_empty_journal(self):
        self.assertIn("journal is empty", lib_cli("log")[1])

    def test_where_says_where_and_whether_recording_is_on(self):
        out = lib_cli("where")[1]
        self.assertIn(str(self.root), out)
        self.assertIn("not created yet", out)
        self.assertIn("Recording: on", out)
        self.seal(self.make_folder())
        out = lib_cli("where")[1]
        self.assertIn("schema 1", out)
        self.assertIn("Holds 1 seal, 0 tokens and 0 verification runs.", out)
        self.assertIn("1 file", out)
        with mock.patch.dict(os.environ, {library.SWITCH_VARIABLE: "off"}):
            self.assertIn("Recording: off", lib_cli("where")[1])


class CheckAndForget(LibraryTestCase):
    def test_no_library_is_nothing_to_check(self):
        code, out, _ = lib_cli("check")
        self.assertEqual(code, 0)
        self.assertIn("nothing to check", out)

    def test_a_sound_library(self):
        self.sealed_and_stamped()
        code, out, _ = lib_cli("check")
        self.assertEqual(code, 0, out)
        self.assertIn("The library is sound: 1 seal, 4 copies", out)
        self.assertEqual(json.loads(lib_cli("check", "--json")[1])["sound"], True)

    def test_each_kind_of_problem_is_listed(self):
        _, manifest_path = self.sealed_and_stamped()
        with self.open() as opened:
            token = opened.tokens(sha_of(manifest_path))[0]
            opened.object_path(token["token_sha256"]).write_bytes(b"tampered")
            os.unlink(opened.object_path(token["request_sha256"]))
            with opened.transaction():
                opened._store(library.ROOT, b"nobody uses this")
        (self.root / "objects" / "zz").mkdir()
        (self.root / "objects" / "ab").mkdir(exist_ok=True)
        (self.root / "objects" / "ab" / "ab-something.tmp").write_bytes(b"")
        code, out, _ = lib_cli("check")
        self.assertEqual(code, 1)
        self.assertIn("The library has 5 problems:", out)
        self.assertIn("the token copy", out)
        self.assertIn("is damaged", out)
        self.assertIn("is missing", out)
        self.assertIn("(orphaned)", out)
        self.assertIn("did not make", out)
        self.assertIn("partly written copy", out)
        data = json.loads(lib_cli("check", "--json")[1])
        self.assertFalse(data["sound"])
        self.assertEqual(len(data["problems"]), 5)

    def test_forget_removes_the_seal_and_its_copies_but_not_the_files(self):
        folder, manifest_path = self.sealed_and_stamped()
        before = snapshot(self.temp / "work"), snapshot(self.temp)
        before_files = {name: data for name, data in before[1].items() if not name.startswith("home/")}
        code, out, err = lib_cli("forget", sha_of(manifest_path)[:8], "--yes")
        self.assertEqual(code, 0, err)
        self.assertIn("removed 4 copies", out)
        self.assertIn("were not touched", out)
        after = {name: data for name, data in snapshot(self.temp).items() if not name.startswith("home/")}
        self.assertEqual(after, before_files)
        with self.open() as opened:
            self.assertEqual(opened.counts(), {"seals": 0, "tokens": 0, "runs": 0, "objects": 0})
            self.assertEqual(opened.check(), [])
        self.assertEqual(list((self.root / "objects").rglob("*")), [])
        self.assertEqual(self.rows("SELECT kind, manifest_sha256 FROM events"), [("forgotten", sha_of(manifest_path))])

    def test_a_copy_another_seal_uses_is_kept(self):
        _, first = self.sealed_and_stamped("one")
        _, second = self.sealed_and_stamped("two")
        self.assertEqual(first.with_suffix(".ca.crt").read_bytes(), second.with_suffix(".ca.crt").read_bytes())
        code, out, _ = lib_cli("forget", sha_of(first)[:8], "--yes")
        self.assertEqual(code, 0)
        self.assertIn("removed 3 copies", out)
        with self.open() as opened:
            self.assertEqual(opened.check(), [])
            token = opened.tokens(sha_of(second))[0]
            self.assertEqual(opened.read_object(token["root_sha256"], library.ROOT), second.with_suffix(".ca.crt").read_bytes())

    def test_forget_asks_first(self):
        manifest_path = self.seal(self.make_folder())
        short = sha_of(manifest_path)[:8]
        with mock.patch("sys.stdin") as stdin:
            stdin.isatty.return_value = False
            code, _, err = lib_cli("forget", short)
        self.assertEqual(code, 2)
        self.assertIn("Add --yes", err)
        with mock.patch("sys.stdin") as stdin, mock.patch("builtins.input", return_value="n") as asked:
            stdin.isatty.return_value = True
            code, out, _ = lib_cli("forget", short)
        self.assertEqual(code, 1)
        self.assertIn("Nothing was forgotten", out)
        self.assertIn("purpose of work", asked.call_args[0][0])
        self.assertEqual(len(self.only_seal()["manifest_sha256"]), 64)
        with mock.patch("sys.stdin") as stdin, mock.patch("builtins.input", side_effect=EOFError):
            stdin.isatty.return_value = True
            self.assertEqual(lib_cli("forget", short)[0], 1)
        with mock.patch("sys.stdin") as stdin, mock.patch("builtins.input", return_value=" Yes "):
            stdin.isatty.return_value = True
            self.assertEqual(lib_cli("forget", short)[0], 0)
        with self.open() as opened:
            self.assertEqual(opened.counts()["seals"], 0)


class Verify(LibraryTestCase):
    def test_a_seal_verifies_from_the_library_copies_alone(self):
        folder, manifest_path = self.sealed_and_stamped()
        sha = sha_of(manifest_path)
        for path in self.temp.glob("work-manifest*"):
            os.unlink(path)
        code, out, err = lib_cli("verify", sha[:6], "--ca", self.ca)
        self.assertEqual(code, 0, out + err)
        self.assertIn("VERIFIED", out)
        self.assertIn("2026-03-01 12:00:00 UTC", out)
        self.assertIn("1 verified, 0 failed, 0 incomplete", out)
        with self.open() as opened:
            run = opened.runs(sha)[0]
        self.assertEqual((run["command"], run["overall"]), ("library verify", "VERIFIED"))
        self.assertEqual(run["folder_path"], str(folder.resolve()))
        self.assertEqual(sorted(path.name for path in self.root.iterdir()), [library.INDEX_NAME, "objects"], "scratch removed")

    def test_without_the_root_the_chain_is_not_checked(self):
        _, manifest_path = self.sealed_and_stamped()
        code, out, _ = lib_cli("verify", sha_of(manifest_path)[:6])
        self.assertEqual(code, 3)
        self.assertIn("INCOMPLETE", out)
        self.assertIn("Certificate chain reaches a trusted root", out)

    def test_a_changed_file_fails(self):
        folder, manifest_path = self.sealed_and_stamped()
        (folder / "a.txt").write_bytes(b"changed\n")
        code, out, _ = lib_cli("verify", sha_of(manifest_path)[:6], "--ca", self.ca)
        self.assertEqual(code, 1)
        self.assertIn("FAILED", out)
        self.assertIn("Files match the manifest: 1 of 2 listed files unchanged, 1 changed", out)

    def test_a_folder_that_is_gone_is_incomplete_and_says_why(self):
        folder, manifest_path = self.sealed_and_stamped()
        moved = self.temp / "moved"
        folder.rename(moved)
        code, out, _ = lib_cli("verify", sha_of(manifest_path)[:6], "--ca", self.ca)
        self.assertEqual(code, 3)
        self.assertIn("is gone; pass --folder", out)
        data = json.loads(lib_cli("verify", sha_of(manifest_path)[:6], "--ca", self.ca, "--json")[1])
        result = data["results"][0]
        self.assertEqual(result["overall"], "INCOMPLETE")
        self.assertEqual(result["verification"]["files"]["status"], "not checked")
        self.assertTrue(all(check["status"] == "pass" for check in result["verification"]["token_checks"]))
        self.assertEqual(lib_cli("verify", sha_of(manifest_path)[:6], "--ca", self.ca, "--folder", moved)[0], 0)
        self.assertEqual(lib_cli("verify", sha_of(manifest_path)[:6], "--ca", self.ca)[0], 0, "the new place is remembered")

    def test_a_seal_with_no_token_is_incomplete(self):
        manifest_path = self.seal(self.make_folder())
        code, out, _ = lib_cli("verify", sha_of(manifest_path)[:6])
        self.assertEqual(code, 3)
        self.assertIn("the library has no token for this seal", out)

    def test_a_damaged_copy_is_incomplete_and_says_so(self):
        _, manifest_path = self.sealed_and_stamped()
        with self.open() as opened:
            opened.object_path(sha_of(manifest_path)).write_bytes(b"damaged")
        code, out, _ = lib_cli("verify", sha_of(manifest_path)[:6], "--ca", self.ca)
        self.assertEqual(code, 3)
        self.assertIn("damaged", out)

    def test_the_worst_result_sets_the_exit_code(self):
        _, good = self.sealed_and_stamped("one")
        bad_folder, bad = self.sealed_and_stamped("two")
        (bad_folder / "a.txt").write_bytes(b"changed\n")
        code, out, _ = lib_cli("verify", "--all", "--ca", self.ca)
        self.assertEqual(code, 1)
        self.assertIn("1 verified, 1 failed, 0 incomplete", out)
        data = json.loads(lib_cli("verify", sha_of(good)[:6], sha_of(bad)[:6], "--ca", self.ca, "--json")[1])
        self.assertEqual(data["exit_code"], 1)
        self.assertEqual({item["manifest_sha256"]: item["overall"] for item in data["results"]}, {sha_of(good): "VERIFIED", sha_of(bad): "FAILED"})

    def test_bad_arguments(self):
        _, manifest_path = self.sealed_and_stamped()
        short = sha_of(manifest_path)[:6]
        junk = self.write("junk.crt", b"not a certificate")
        cases = (
            ((), "give one or more IDs, or --all"),
            ((short, "--all"), "not both"),
            (("--all", "--folder", self.temp), "one seal at a time"),
            ((short, "--folder", self.temp / "nowhere"), "is not a folder"),
            ((short, "--ca", junk), "junk.crt"),
        )
        for arguments, phrase in cases:
            with self.subTest(arguments):
                code, _, err = lib_cli("verify", *arguments)
                self.assertEqual(code, 2, err)
                self.assertIn(phrase, err)

    def test_an_empty_library_verifies_nothing_and_does_not_pass(self):
        code, out, _ = lib_cli("verify", "--all")
        self.assertEqual(code, 3)
        self.assertIn("nothing was verified", out)

    def test_a_hand_made_manifest_inside_its_folder(self):
        folder = self.make_folder("hand", {"one.txt": b"1\n", "two.txt": b"2\n"})
        listing = "".join(f"{sha_of(folder / name)}  {name}\n" for name in ("one.txt", "two.txt"))
        manifest_path = self.write("hand/SHA256SUMS.txt", listing.encode("ascii"))
        self.write("hand/SHA256SUMS.tsr", self.authority.authority.token(manifest_path.read_bytes()))
        code, out, err = lib_cli("import", folder)
        self.assertEqual(code, 0, out + err)
        code, out, _ = lib_cli("verify", sha_of(manifest_path)[:6], "--ca", self.ca)
        self.assertEqual(code, 0, out)


class Import(LibraryTestCase):
    def earlier_seal(self, name="work"):
        """A seal made before the library existed: sealed, stamped, then stamped again with --force."""
        folder = self.make_folder(name)
        manifest_path = self.seal(folder, None, "--no-library")
        self.assertEqual(self.stamp(manifest_path, "--no-library")[0], 0)
        self.assertEqual(self.stamp(manifest_path, "--no-library", "--force")[0], 0)
        return folder, manifest_path

    def test_earlier_seals_come_in_with_every_token(self):
        _, manifest_path = self.earlier_seal()
        self.assertFalse(self.home.exists())
        before = snapshot(self.temp)
        code, out, err = lib_cli("import", self.temp)
        self.assertEqual(code, 0, out + err)
        self.assertIn(f"Added      {sha_of(manifest_path)[:12]}", out)
        self.assertIn("(2 tokens)", out)
        self.assertIn("Added 1 seal and 2 tokens; 0 already known; 0 skipped.", out)
        self.assertEqual({name: data for name, data in snapshot(self.temp).items() if not name.startswith("home/")}, before)
        with self.open() as opened:
            tokens = opened.tokens(sha_of(manifest_path))
            self.assertEqual(sorted(token["is_current"] for token in tokens), [False, True])
            self.assertTrue(all(token["request_sha256"] for token in tokens))
            self.assertEqual(opened.check(), [])
            self.assertEqual(opened.seals()[0]["folder_path"], str(self.temp / "work"))
        code, out, _ = lib_cli("import", manifest_path)
        self.assertEqual(code, 0)
        self.assertIn("Known", out)
        self.assertIn("(0 new tokens)", out)

    def test_a_dry_run_writes_nothing(self):
        self.earlier_seal()
        code, out, _ = lib_cli("import", self.temp, "--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("Dry run: nothing was written", out)
        self.assertIn("Would add 1 seal and 2 tokens", out)
        self.assertFalse(self.home.exists())
        data = json.loads(lib_cli("import", self.temp, "--dry-run", "--json")[1])
        self.assertTrue(data["dry_run"])
        self.assertEqual(data["results"][0]["tokens_added"], 2)

    def test_folders_inside_need_recursive(self):
        nested = self.temp / "deep" / "deeper"
        nested.mkdir(parents=True)
        folder = self.make_folder("deep/deeper/work")
        self.seal(folder, "deep/deeper/m.txt", "--no-library")
        out = lib_cli("import", self.temp / "deep")[1]
        self.assertIn("No manifests were found. Add --recursive", out)
        code, out, _ = lib_cli("import", self.temp / "deep", "--recursive")
        self.assertEqual(code, 0)
        self.assertIn("Added 1 seal and 0 tokens", out)

    def test_odd_and_hostile_files_are_skipped_with_a_reason(self):
        mess = self.temp / "mess"
        mess.mkdir()
        (mess / "damaged.txt").write_bytes(b"evidence-seal manifest v1\npurpose: x\n\nnot an entry\n")
        (mess / "newer.txt").write_bytes(b"evidence-seal manifest v9\nwhatever\n")
        (mess / "random.bin").write_bytes(os.urandom(300))
        (mess / "list.txt").write_bytes(b"0" * 64 + b"  some-file\n")
        (mess / "list.tsr").write_bytes(self.authority.authority.token(b"other data"))
        (mess / "garbage.txt").write_bytes(b"just words\n")
        (mess / "garbage.tsr").write_bytes(b"\x30\x82\xff\xff" + os.urandom(64))
        (mess / "folder.txt").mkdir()
        before = snapshot(mess)
        code, out, err = lib_cli("import", mess)
        self.assertEqual(code, 1, out + err)
        self.assertNotIn("Traceback", err)
        self.assertIn("damaged.txt: it is damaged", out)
        self.assertIn("newer.txt: it uses manifest format v9", out)
        self.assertIn("list.txt: no token beside it covers it", out)
        self.assertIn("the token list.tsr was skipped: it does not cover this manifest", out)
        self.assertIn("garbage.txt: it lists no hashes", out)
        self.assertIn("the token garbage.tsr was skipped: it is not a timestamp token", out)
        self.assertNotIn("random.bin", out)
        self.assertIn("Added 0 seals and 0 tokens; 0 already known; 4 skipped.", out)
        self.assertEqual(snapshot(mess), before)
        with self.open() as opened:
            self.assertEqual(opened.counts()["seals"], 0)

    def test_a_manifest_too_large_to_keep_is_skipped(self):
        self.seal(self.make_folder(), None, "--no-library")
        with mock.patch.dict(library.OBJECT_LIMITS, {library.MANIFEST: 50}):
            code, out, _ = lib_cli("import", self.temp)
        self.assertEqual(code, 1)
        self.assertIn("too large for the library to keep", out)

    def test_an_explicit_hand_made_list_needs_no_token(self):
        listing = self.write("sums.txt", b"a" * 64 + b"  file.txt\n")
        code, out, _ = lib_cli("import", listing)
        self.assertEqual(code, 0, out)
        self.assertEqual(self.only_seal()["manifest_kind"], "hand-made")

    def test_the_library_itself_is_never_imported(self):
        self.seal(self.make_folder())
        code, out, _ = lib_cli("import", self.home, "--recursive")
        self.assertEqual(code, 0)
        self.assertIn("No manifests were found", out)
        copy = next(path for path in (self.root / "objects").rglob("*") if path.is_file())
        code, out, _ = lib_cli("import", copy)
        self.assertEqual(code, 1)
        self.assertIn("it is one of the library's own copies", out)

    def test_a_huge_folder_is_looked_through_only_so_far(self):
        for number in range(10):
            self.write(f"many/file{number}.txt", b"x")
        with mock.patch.object(library_commands, "MAX_IMPORT_ENTRIES", 5):
            out = lib_cli("import", self.temp / "many")[1]
        self.assertIn("stopped looking after 5 files and folders", out)

    def test_a_missing_path_is_a_usage_error(self):
        code, _, err = lib_cli("import", self.temp / "nowhere")
        self.assertEqual(code, 2)
        self.assertIn("does not exist", err)
        self.assertFalse(self.home.exists())

    def test_json_lists_each_result(self):
        _, manifest_path = self.earlier_seal()
        data = json.loads(lib_cli("import", manifest_path, "--json")[1])
        self.assertEqual(data["results"][0]["status"], "added")
        self.assertEqual(data["results"][0]["manifest_sha256"], sha_of(manifest_path))

    @unittest.skipIf(os.name == "nt", "these names and links need a POSIX file system")
    def test_control_characters_in_names_and_link_loops(self):
        folder = self.make_folder("evil")
        manifest_path = self.seal(folder, "evil\x1b[31m\nRESULT: VERIFIED.txt", "--no-library")
        os.symlink(str(self.temp), str(self.temp / "loop"))
        code, out, _ = lib_cli("import", self.temp, "--recursive")
        self.assertEqual(code, 0, out)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\nRESULT: VERIFIED", out)
        self.assertIn("Added 1 seal", out)
        self.assertEqual(self.only_seal()["manifest_path"], os.path.abspath(manifest_path))


class Documentation(LibraryTestCase):
    def test_every_command_in_the_library_guide_parses_and_none_chains(self):
        count = 0
        for line in fenced_commands("docs/LIBRARY.md"):
            parts = shlex.split(line)
            self.assertEqual(parts[:3], ["python", "-m", "evidence_seal"], line)
            for token in ("&&", "||", "; "):
                self.assertNotIn(token, line)
            cli.build_parser().parse_args(parts[3:])
            count += 1
        self.assertGreater(count, 10)

    def test_the_guide_names_every_action(self):
        text = (ROOT_OF_REPO / "docs" / "LIBRARY.md").read_text(encoding="utf-8")
        for action in library_commands.ACTIONS:
            self.assertIn(f"library {action}", text)

    def test_the_guide_import_example_does_what_it_says(self):
        code, out, _ = lib_cli("import", ROOT_OF_REPO / "examples" / "sealed", "--dry-run")
        self.assertEqual(code, 0, out)
        self.assertIn("Would add 1 seal and 1 token", out)
        self.assertFalse(self.home.exists())
