"""The settings file and profiles: reading, changing without losing a byte, and what each command takes from them."""

import json
import os
import re
import shutil
import time
import unittest
from pathlib import Path
from unittest import mock

import shlex

from evidence_seal import authorities, cli, report_formats, reporting, settings
from evidence_seal.errors import StampError, UsageError
from tests import test_docs_and_examples as documents
from tests.support import LOCAL, ROOT_OF_REPO, TempFolderTestCase, run_cli

EXAMPLES = ROOT_OF_REPO / "examples"
MY_WORK = EXAMPLES / "my-work"
SEALED_MANIFEST = EXAMPLES / "sealed" / "my-work-manifest.txt"
SEALED_ROOT = EXAMPLES / "sealed" / "test-authority-root.crt"
OTHER_ROOT = LOCAL / "other-root.crt"


def ini(*lines):
    return "\n".join(lines) + "\n"


class SettingsCase(TempFolderTestCase):
    """Each test gets a home folder of its own, so a settings file never leaks into another test."""

    def setUp(self):
        super().setUp()
        self.home = self.temp / "home"
        patcher = mock.patch.dict(os.environ, {"EVIDENCE_SEAL_HOME": str(self.home)})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.ini = self.home / "settings.ini"

    def write_settings(self, text):
        self.home.mkdir(exist_ok=True)
        data = text if isinstance(text, bytes) else text.encode("utf-8")
        self.ini.write_bytes(data)
        return data

    def document(self, text):
        data = text if isinstance(text, bytes) else text.encode("utf-8")
        return settings.Document(self.temp / "settings.ini", data)

    def problems(self, text):
        return [(problem.line, problem.message) for problem in self.document(text).problems]

    def assert_problem(self, text, line, phrase):
        found = self.problems(text)
        self.assertTrue(any(number == line and phrase in message for number, message in found), found)

    def ok(self, *arguments):
        code, out, err = run_cli(*arguments)
        self.assertEqual(code, 0, out + err)
        return out

    def refused(self, *arguments, code=2):
        got, out, err = run_cli(*arguments)
        self.assertEqual(got, code, out + err)
        self.assertNotIn("Traceback", err)
        return out + err


class Reading(SettingsCase):
    def test_a_clean_file_gives_its_values_with_lines(self):
        document = self.document(ini("[settings]", "version = 1", "", "[defaults]", "timeout = 30", "exclude =", "    .git", "    *.tmp", "[profile lab]", "hash = sha512"))
        self.assertEqual(document.problems, [])
        self.assertEqual(document.values[("[defaults]", "timeout")], 30.0)
        self.assertEqual(document.values[("[defaults]", "exclude")], [".git", "*.tmp"])
        self.assertEqual(document.values[("[profile lab]", "hash")], "sha512")
        exclude = document.section("defaults").find("exclude")[0]
        self.assertEqual([index + 1 for index in exclude.value_lines], [7, 8])
        self.assertEqual([found.name for found in document.profiles()], ["lab"])

    def test_every_byte_comes_back_unchanged(self):
        samples = [
            b"",
            b"\n\n",
            b"[defaults]\ntimeout = 3",
            b"[defaults]\r\ntimeout = 3\r\n",
            b"[defaults]\r\ntimeout = 3\n# mixed endings\r\n",
            b"\xef\xbb\xbf[defaults]\n\ttimeout=3  \n",
            b"; only a comment\n   \n\t\n",
            "[defaults]\npurpose = R\u00e9sum\u00e9 for {folder}\n".encode("utf-8"),
        ]
        samples.append(b"\xff\xfe" + "[defaults]\r\ntimeout = 3\r\n".encode("utf-16-le"))
        samples.append(b"\xfe\xff" + "[defaults]\ntimeout = 3\n".encode("utf-16-be"))
        for data in samples:
            with self.subTest(data):
                document = self.document(data)
                self.assertEqual(document.render(document.lines), data)

    def test_lists_may_hold_comments_and_blank_lines_and_a_first_value(self):
        document = self.document(ini("[defaults]", "exclude = .git", "    # temporary files", "", "    *.tmp", "ca =", "timeout = 5"))
        self.assertEqual(document.problems, [])
        self.assertEqual(document.values[("[defaults]", "exclude")], [".git", "*.tmp"])
        self.assertEqual(document.values[("[defaults]", "ca")], [])

    def test_relative_paths_are_relative_to_the_settings_folder(self):
        document = self.document(ini("[defaults]", "ca =", "    certs/root.crt", "    " + str(SEALED_ROOT)))
        self.assertEqual(document.values[("[defaults]", "ca")], [self.temp / "certs" / "root.crt", SEALED_ROOT])
        home_path = self.document(ini("[defaults]", "ca = ~/root.crt")).values[("[defaults]", "ca")][0]
        self.assertEqual(home_path, Path("~/root.crt").expanduser())

    def test_names_that_are_allowed(self):
        for name in ("a", "lab", "Lab.2026", "a-b_c.d", "9", "x" * 64):
            with self.subTest(name):
                self.assertEqual(self.problems(ini(f"[profile {name}]")), [])

    def test_names_that_are_refused(self):
        for name, phrase in (
            ("x" * 65, "longer than 64"),
            ("caf\u00e9", "only letters"),
            ("-lab", "only letters"),
            (".hidden", "only letters"),
            ('"lab"', "only letters"),
            ("lab/2", "only letters"),
        ):
            with self.subTest(name):
                self.assert_problem(ini(f"[profile {name}]"), 1, phrase)


class Problems(SettingsCase):
    def test_sections_that_do_not_exist_get_a_suggestion(self):
        for header, phrase in (
            ("[default]", "did you mean [defaults]?"),
            ("[Defaults]", "did you mean [defaults]?"),
            ("[setting]", "did you mean [settings]?"),
            ("[profiles lab]", "did you mean [profile lab]?"),
            ("[lab]", "did you mean [profile lab]?"),
            ("[profile]", "needs a name"),
            ("[profile a b]", "there is no section [profile a b]"),
            ("[]", "there is no section []"),
            ("[defaults", "must end with ]"),
            ("[defaults] # the usual", "comment goes on a line of its own"),
        ):
            with self.subTest(header):
                self.assert_problem(ini(header, "timeout = 3"), 1, phrase)

    def test_keys_under_an_unreadable_section_are_not_reported_again(self):
        self.assertEqual(len(self.problems(ini("[defualts]", "timout = 3", "    more", "[defaults]", "timeout = 3"))), 1)

    def test_keys_that_do_not_exist_get_a_suggestion(self):
        self.assert_problem(ini("[defaults]", "exlude = .git"), 2, "did you mean 'exclude'?")
        self.assert_problem(ini("[defaults]", "Timeout = 3"), 2, "did you mean 'timeout'?")
        self.assert_problem(ini("[defaults]", "allow added = yes"), 2, "did you mean 'allow-added'?")
        self.assert_problem(ini("[defaults]", "zzz = 1"), 2, "[defaults] can hold: authority, timeout")
        self.assert_problem(ini("[settings]", "versoin = 1"), 2, "did you mean 'version'?")
        self.assert_problem(ini("[settings]", "timeout = 1"), 2, "[settings] can hold: version")

    def test_lines_that_cannot_be_read(self):
        self.assert_problem(ini("timeout = 3", "[defaults]"), 1, "above every section")
        self.assert_problem(ini("[defaults]", "timeout 3"), 2, "expected KEY = VALUE")
        self.assert_problem(ini("[defaults]", "= 3"), 2, "expected KEY = VALUE")
        self.assert_problem(ini("    .git", "[defaults]"), 1, "does not follow a key")
        self.assert_problem(ini("[defaults]", "x" * 200), 2, "...")

    def test_a_bad_line_is_reported_once_and_not_for_each_indented_line_after_it(self):
        self.assertEqual(len(self.problems(ini("[defaults]", "exclude:", "    .git", "    *.tmp"))), 1)

    def test_twice_is_a_mistake(self):
        self.assert_problem(ini("[defaults]", "timeout = 3", "[defaults]"), 3, "first is on line 1")
        self.assert_problem(ini("[profile a]", "[profile a]"), 2, "[profile a] appears twice")
        self.assert_problem(ini("[defaults]", "timeout = 3", "timeout = 4"), 3, "timeout is set twice in [defaults]; the first is on line 2")
        self.assertEqual(self.problems(ini("[profile a]", "[profile A]")), [])

    def test_every_bad_value_says_which_key_and_why(self):
        cases = (
            ("timeout = 0", "timeout in [defaults]: must be more than 0"),
            ("timeout = soon", "'soon' is not a number of seconds"),
            ("timeout = nan", "must be more than 0"),
            ("retries = 11", "retries in [defaults]: must be a whole number from 0 to 10"),
            ("retries = -1", "must be a whole number"),
            ("hash = md5", "hash in [defaults]: must be a strong hash"),
            ("hash = whirlpool", "must be a strong hash"),
            ("policy = 1", "policy in [defaults]: must be an object identifier"),
            ("policy = 3.1", "must be a valid object identifier"),
            ("authority = https://", "authority in [defaults]: the authority URL"),
            ("authority = http://exa mple.test/", "cannot be read"),
            ("allow-added = true", "allow-added in [defaults]: must be yes or no, not 'true'"),
            ("openssl = on", "must be yes or no"),
            ("library = yes", "library in [defaults]: must be on or off"),
            ("report-format = docx", "report-format in [defaults]: must be one of text, html, json, markdown, csv, junit, pdf"),
            ("purpose = {nope}", "may use {folder} and {date} only, not {nope}"),
            ("purpose = {date:%Y}", "may use {folder} and {date} only"),
            ("purpose = {0}", "may use {folder} and {date} only"),
            ("purpose = a { b", "opens or closes nothing"),
            ("purpose =", "has no value"),
            ("timeout =", "has no value"),
        )
        for line, phrase in cases:
            with self.subTest(line):
                self.assert_problem(ini("[defaults]", line), 2, phrase)

    def test_a_bad_list_value_is_reported_on_its_own_line(self):
        self.assert_problem(ini("[defaults]", "exclude =", "    .git", "    /", "    *.tmp"), 4, "the pattern '/' has nothing to match")

    def test_one_value_keys_refuse_more(self):
        self.assert_problem(ini("[defaults]", "purpose = My work", "    on things"), 2, "takes one value, but has 2")

    def test_values_are_strict_but_not_about_case_where_it_cannot_matter(self):
        document = self.document(ini("[defaults]", "allow-added = YES", "library = Off", "hash = SHA-512"))
        self.assertEqual(document.problems, [])
        self.assertIs(document.values[("[defaults]", "allow-added")], True)
        self.assertIs(document.values[("[defaults]", "library")], False)

    def test_version(self):
        self.assertEqual(self.problems(ini("[settings]", "version = 1")), [])
        self.assert_problem(ini("[settings]", "version = 0"), 2, "version must be 1, not 0")
        self.assert_problem(ini("[settings]", "version = one"), 2, "version must be 1, not one")
        self.assert_problem(ini("[settings]", "version ="), 2, "version must be 1, not empty")

    def test_a_newer_version_is_the_only_problem_reported(self):
        found = self.problems(ini("[settings]", "version = 2", "[schedules]", "weekly: yes", "[defaults]", "new-key = 1"))
        self.assertEqual(len(found), 1, found)
        self.assertEqual(found[0][0], 2)
        self.assertIn("settings version 2, written by a newer evidence-seal", found[0][1])
        self.assertTrue(self.document(ini("[settings]", "version = 2")).problems[0].structural)

    def test_control_characters_and_lone_carriage_returns(self):
        self.assert_problem(ini("[defaults]", "purpose = a\x1bb"), 2, "\\x1b")
        self.assert_problem(ini("[defaults]", "purpose = a\x00b"), 2, "\\x00")
        self.assert_problem(ini("[defaults]", "purpose = a\u202eb"), 2, "\\u202e")
        self.assert_problem("[defaults]\rtimeout = 3\n", 1, "\\x0d")
        self.assertEqual(self.problems(ini("[defaults]", "purpose =\ta\tb")), [])

    def test_text_that_is_not_utf8(self):
        self.assert_problem(b"[defaults]\ntimeout = 3\n\xff\xfe junk\n", 3, "is not UTF-8 text")
        self.assert_problem(b"[defaults]\npurpose = caf\xe9\n", 2, "is not UTF-8 text")
        found = self.problems(b"\xff\xfe\x00\xd8")
        self.assertEqual(found, [(None, "is not readable UTF-16 text. Save the file as UTF-8")])

    def test_a_huge_file_is_refused_without_reading_it_all(self):
        self.write_settings(b"# " + b"x" * settings.MAX_FILE_BYTES + b"\n")
        out = self.refused("config", "check", code=1)
        self.assertIn("larger than 1 MB", out)
        self.assertIn("larger than 1 MB", self.refused("seal", self.temp, "--dry-run"))

    def test_a_file_of_many_sections_reads_quickly(self):
        text = "".join(f"[profile p{number}]\nhash = sha512\n" for number in range(30000))
        self.assertLess(len(text), settings.MAX_FILE_BYTES)
        started = time.monotonic()
        document = self.document(text)
        self.assertEqual(document.problems, [])
        self.assertEqual(len(document.profiles()), 30000)
        self.assertLess(time.monotonic() - started, 10)

    def test_a_file_of_many_mistakes_lists_a_bounded_number(self):
        lines = ["[defaults]"] + [f"key{number} = 1" for number in range(50000)]
        started = time.monotonic()
        found = self.document(ini(*lines)).problems
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(len(found), settings.MAX_PROBLEMS + 1)
        self.assertIn("only some are listed", found[-1].message)
        self.assertEqual(len(self.problems(ini(*(["[nope]", "x"] * 30000)))), settings.MAX_PROBLEMS + 1)

    def test_problems_come_in_line_order_with_the_file(self):
        self.write_settings(ini("[defaults]", "zzz = 1", "timeout = 0", "[nope]"))
        out = self.refused("config", "check", code=1)
        lines = out.splitlines()
        self.assertEqual([re.search(r" line (\d+): ", line).group(1) for line in lines[:3]], ["2", "3", "4"])
        self.assertTrue(all(line.startswith(str(self.ini)) for line in lines[:3]), out)
        self.assertIn("3 problems in", lines[3])


class Changing(SettingsCase):
    ORIGINAL = ini(
        "# top comment",
        "; another",
        "",
        "[settings]",
        "version = 1",
        "",
        "# defaults for every run",
        "[defaults]",
        "timeout = 30   ",
        "# about excludes",
        "exclude =",
        "    .git",
        "    # temporary files",
        "    *.tmp",
        "retries = 1",
        "  # trailing comment in defaults",
        "",
        "# the lab",
        "[profile lab]",
        "hash = sha512",
    )

    def setUp(self):
        super().setUp()
        self.write_settings(self.ORIGINAL)

    def current(self):
        return self.ini.read_text(encoding="utf-8")

    def test_setting_a_value_changes_only_its_line(self):
        self.ok("config", "set", "timeout", "45")
        self.assertEqual(self.current(), self.ORIGINAL.replace("timeout = 30   \n", "timeout = 45\n"))

    def test_setting_a_list_keeps_the_comments_between_its_old_values(self):
        self.ok("config", "set", "exclude", "build", "cache/")
        expected = self.ORIGINAL.replace("    .git\n    # temporary files\n    *.tmp\n", "    build\n    cache/\n    # temporary files\n")
        self.assertEqual(self.current(), expected)

    def test_a_new_key_goes_after_the_last_key_of_its_section(self):
        self.ok("config", "set", "policy", "1.2.3.4")
        self.assertEqual(self.current(), self.ORIGINAL.replace("retries = 1\n", "retries = 1\npolicy = 1.2.3.4\n"))
        self.ok("config", "set", "timeout", "10", "--profile", "lab")
        self.assertTrue(self.current().endswith("[profile lab]\nhash = sha512\ntimeout = 10\n"))

    def test_unset_removes_only_the_key(self):
        self.ok("config", "unset", "retries")
        self.assertEqual(self.current(), self.ORIGINAL.replace("retries = 1\n", ""))
        self.ok("config", "unset", "exclude")
        self.assertIn("# about excludes\n    # temporary files\n  # trailing", self.current())
        out = self.ok("config", "unset", "retries")
        self.assertIn("not set in [defaults], so nothing was changed", out)

    def test_set_and_unset_in_a_profile(self):
        self.ok("config", "set", "hash", "sha384", "--profile", "lab")
        self.assertEqual(self.current(), self.ORIGINAL.replace("hash = sha512", "hash = sha384"))
        self.ok("config", "unset", "hash", "--profile", "lab")
        self.assertTrue(self.current().endswith("# the lab\n[profile lab]\n"))

    def test_a_missing_section_is_added_at_the_end(self):
        self.write_settings("[settings]\nversion = 1")
        self.ok("config", "set", "openssl", "yes")
        self.assertEqual(self.current(), "[settings]\nversion = 1\n\n[defaults]\nopenssl = yes\n")

    def test_duplicates_become_one(self):
        self.write_settings(ini("[defaults]", "timeout = 3", "# keep me", "timeout = 4"))
        self.assertIn("set twice", self.refused("seal", self.temp, "--dry-run"))
        self.ok("config", "set", "timeout", "5")
        self.assertEqual(self.current(), ini("[defaults]", "timeout = 5", "# keep me"))

    def test_line_endings_and_byte_order_marks_are_kept(self):
        data = self.write_settings(b"\xef\xbb\xbf[defaults]\r\ntimeout = 3\r\n")
        self.ok("config", "set", "retries", "4")
        written = self.ini.read_bytes()
        self.assertEqual(written, data + b"retries = 4\r\n")
        self.write_settings(b"\xff\xfe" + "[defaults]\r\ntimeout = 3\r\n".encode("utf-16-le"))
        self.assertEqual(self.ok("config", "get", "timeout"), "3\n")
        self.ok("config", "set", "timeout", "7")
        self.assertEqual(self.ini.read_bytes(), b"\xff\xfe" + "[defaults]\r\ntimeout = 7\r\n".encode("utf-16-le"))

    def test_a_file_without_a_final_line_ending(self):
        self.write_settings("[defaults]\ntimeout = 3")
        self.ok("config", "set", "retries", "1")
        self.assertEqual(self.current(), "[defaults]\ntimeout = 3\nretries = 1\n")

    def test_a_bad_value_is_refused_and_nothing_is_written(self):
        before = self.ini.read_bytes()
        for arguments, phrase in (
            (("timeout", "0"), "timeout: must be more than 0"),
            (("hash", "sha1"), "must be a strong hash"),
            (("purpose", "{when}"), "may use {folder} and {date} only"),
            (("timeout", "1", "2"), "timeout takes one value, not 2"),
            (("timout", "1"), "did you mean 'timeout'?"),
            (("version", "1"), "there is no setting 'version'"),
            (("exclude", "#notes"), "cannot start with #"),
            (("exclude", "  "), "cannot be empty"),
            (("purpose", "two\nlines"), "line breaks"),
            (("ca", "missing.crt"), "is not a file, so ca was not set"),
            (("timeout", "5", "--profile", "nope"), "there is no profile 'nope'"),
        ):
            with self.subTest(arguments):
                self.assertIn(phrase, self.refused("config", "set", *arguments))
                self.assertEqual(self.ini.read_bytes(), before)

    def test_paths_are_stored_in_full(self):
        self.write("certs/root.crt", SEALED_ROOT.read_bytes())
        previous = os.getcwd()
        os.chdir(self.temp)
        self.addCleanup(os.chdir, previous)
        self.ok("config", "set", "ca", "certs/root.crt")
        self.assertIn(f"ca =\n    {os.path.join(os.getcwd(), 'certs', 'root.crt')}\n", self.current())

    def test_a_wrong_value_can_be_fixed_through_the_commands(self):
        self.write_settings(ini("[defaults]", "timeout = never", "timout = 3"))
        self.ok("config", "set", "timeout", "30")
        self.ok("config", "unset", "timout")
        self.assertEqual(self.current(), ini("[defaults]", "timeout = 30"))
        self.assertIn("there is no setting 'zzz'", self.refused("config", "unset", "zzz"))

    def test_a_file_that_cannot_be_read_is_never_changed(self):
        for text in (ini("[defaults]", "timeout 3"), ini("[settings]", "version = 2", "[defaults]")):
            with self.subTest(text):
                data = self.write_settings(text)
                for arguments in (("config", "set", "timeout", "5"), ("config", "unset", "timeout"), ("profile", "create", "x")):
                    self.assertIn("Nothing was changed", self.refused(*arguments))
                    self.assertEqual(self.ini.read_bytes(), data)

    def test_a_failed_write_leaves_the_file_as_it_was(self):
        with mock.patch("evidence_seal.sealing.os.replace", side_effect=PermissionError(13, "Permission denied")):
            out = self.refused("config", "set", "timeout", "5", code=1)
        self.assertIn("was left as it was", out)
        self.assertEqual(self.current(), self.ORIGINAL)
        self.assertEqual(sorted(path.name for path in self.home.iterdir()), ["settings.ini"])

    @unittest.skipIf(os.name == "nt", "making a symbolic link needs extra rights on Windows")
    def test_a_linked_settings_file_stays_a_link(self):
        real = self.write("dotfiles/settings.ini", self.ORIGINAL.encode("utf-8"))
        self.ini.unlink()
        os.symlink(real, self.ini)
        self.ok("config", "set", "timeout", "45")
        self.assertTrue(self.ini.is_symlink())
        self.assertIn("timeout = 45\n", real.read_text(encoding="utf-8"))

    def test_a_file_changed_meanwhile_is_not_overwritten(self):
        with self.assertRaises(UsageError) as caught:
            settings.save(self.ini, b"[defaults]\n", b"[defaults]\ntimeout = 3\n")
        self.assertIn("changed while this command was changing it", str(caught.exception))
        self.assertEqual(self.current(), self.ORIGINAL)

    def test_a_change_that_would_add_a_problem_is_not_written(self):
        original = self.ini.read_bytes()
        with self.assertRaises(UsageError) as caught:
            settings.save(self.ini, original, original + b"zzz = 1\n")
        self.assertIn("would leave a problem", str(caught.exception))
        self.assertIn("'zzz'", str(caught.exception))


class Commands(SettingsCase):
    def test_path(self):
        out = self.ok("config", "path")
        self.assertEqual(out.splitlines()[0], str(self.ini))
        self.assertIn("does not exist yet", out)
        self.write_settings("")
        self.assertIn("It exists.", self.ok("config", "path"))
        other = self.temp / "other.ini"
        self.assertEqual(self.ok("config", "path", "--settings", other).splitlines()[0], str(other))

    def test_set_creates_the_file_with_a_header(self):
        out = self.ok("config", "set", "timeout", "30")
        self.assertIn("Created", out)
        text = self.ini.read_text(encoding="utf-8")
        self.assertTrue(text.startswith(settings.NEW_FILE_TEXT))
        self.assertTrue(text.endswith("\n[defaults]\ntimeout = 30\n"))
        self.assertEqual(self.document(text).problems, [])

    def test_show_says_where_each_value_came_from(self):
        self.write_settings(ini("[defaults]", "timeout = 30", "exclude =", "    .git", "    *.tmp", "[profile lab]", "timeout = 5", "openssl = yes"))
        out = self.ok("config", "show")
        self.assertRegex(out, r"timeout +30  \(defaults, settings.ini line 2\)")
        self.assertRegex(out, r"exclude +\.git  \(defaults, settings.ini line 3\)\n +\*\.tmp\n")
        self.assertRegex(out, r"authority +https://freetsa.org/tsr  \(built-in\)")
        self.assertRegex(out, r"policy +\(none\)  \(built-in\)")
        out = self.ok("config", "show", "--profile", "lab")
        self.assertRegex(out, r"timeout +5  \(profile lab, settings.ini line 7\)")
        self.assertRegex(out, r"openssl +yes  \(profile lab, settings.ini line 8\)")
        data = json.loads(self.ok("config", "show", "--profile", "lab", "--json"))
        self.assertEqual(data["profile"], "lab")
        self.assertTrue(data["exists"])
        self.assertEqual(data["settings"]["timeout"], {"value": 5.0, "source": "profile lab", "file": str(self.ini), "line": 7})
        self.assertEqual(data["settings"]["exclude"]["value"], [".git", "*.tmp"])
        self.assertEqual(data["settings"]["library"], {"value": True, "source": "built-in", "file": None, "line": None})
        self.assertEqual(list(data["settings"]), list(settings.KEYS))

    def test_show_with_no_file(self):
        out = self.ok("config", "show")
        self.assertIn("it does not exist, so built-in values apply", out)
        self.assertEqual(out.count("(built-in)"), len(settings.KEYS))
        self.assertIn("there is no settings file", self.refused("config", "show", "--profile", "lab"))

    def test_get(self):
        self.write_settings(ini("[defaults]", "ca =", f"    {SEALED_ROOT}", f"    {OTHER_ROOT}", "[profile lab]", "retries = 0"))
        self.assertEqual(self.ok("config", "get", "ca"), f"{SEALED_ROOT}\n{OTHER_ROOT}\n")
        self.assertEqual(self.ok("config", "get", "retries"), "2\n")
        self.assertEqual(self.ok("config", "get", "retries", "--profile", "lab"), "0\n")
        self.assertEqual(self.ok("config", "get", "policy"), "")
        self.assertEqual(self.ok("config", "get", "allow-added"), "no\n")
        self.assertIn("did you mean 'retries'?", self.refused("config", "get", "retry"))

    def test_check(self):
        self.assertIn("There is no settings file", self.ok("config", "check"))
        self.assertIn("does not exist", self.refused("config", "check", "--settings", self.temp / "none.ini"))
        self.write_settings(ini("[defaults]", "timeout = 3", "[profile a]", "[profile b]"))
        self.assertIn("No problems in", self.ok("config", "check"))
        self.assertIn("It has 2 profiles", self.ok("config", "check"))

    def test_check_finds_missing_files_and_unknown_authorities(self):
        bad_excludes = self.write("bad-excludes.txt", b"\xff\xfe\x00\xd8")
        self.write_settings(
            ini("[defaults]", "ca =", "    missing.crt", "exclude-from =", f"    {bad_excludes}", "[profile lab]", "authority = Example TSA")
        )
        out = self.refused("config", "check", code=1)
        self.assertIn("line 3: ca in [defaults] names", out)
        self.assertIn("missing.crt, which is not a file", out)
        self.assertIn("line 5: exclude-from in [defaults]", out)
        self.assertIn("line 7: authority in [profile lab]: the authority name 'Example TSA' is not known", out)
        self.assertIn("3 problems", out)

    def test_check_another_file(self):
        other = self.write("other.ini", ini("[defaults]", "timeout = -1").encode())
        out = self.refused("config", "check", "--settings", other, code=1)
        self.assertIn(f"{other} line 2: timeout in [defaults]", out)

    def test_a_damaged_file_stops_the_reading_commands_too(self):
        self.write_settings(ini("[defaults]", "timeout = 0"))
        for arguments in (("config", "show"), ("config", "get", "timeout"), ("profile", "list"), ("profile", "show", "x")):
            with self.subTest(arguments):
                out = self.refused(*arguments)
                self.assertIn("line 2: timeout in [defaults]: must be more than 0", out)
                self.assertIn("config check", out)

    def test_profiles(self):
        self.write_settings(ini("[defaults]", "timeout = 3", "", "# lab work", "[profile lab]", "hash = sha512", "exclude =", "    *.tmp"))
        self.assertEqual(self.ok("profile", "list"), "lab  2 values, line 5\n")
        listed = json.loads(self.ok("profile", "list", "--json"))
        self.assertEqual(listed["profiles"], [{"name": "lab", "line": 5, "keys": ["hash", "exclude"]}])
        out = self.ok("profile", "show", "lab")
        self.assertIn("[profile lab] in", out)
        self.assertRegex(out, r"hash +sha512  \(line 6\)")
        shown = json.loads(self.ok("profile", "show", "lab", "--json"))
        self.assertEqual(shown["settings"]["exclude"], {"value": ["*.tmp"], "line": 7})
        self.assertIn("The profiles are: lab", self.refused("profile", "show", "lba"))
        self.assertIn("did you mean 'lab'?", self.refused("profile", "show", "lba"))

    def test_profile_list_with_none(self):
        self.assertIn("There is no settings file", self.ok("profile", "list"))
        self.write_settings(ini("[defaults]"))
        self.assertIn("There are no profiles", self.ok("profile", "list"))
        self.assertEqual(json.loads(self.ok("profile", "list", "--json"))["profiles"], [])

    def test_create_copy_rename_delete(self):
        self.ok("profile", "create", "lab")
        self.assertTrue(self.ini.read_text(encoding="utf-8").endswith("\n\n[profile lab]\n"))
        self.ok("config", "set", "hash", "sha384", "--profile", "lab")
        self.ok("config", "set", "exclude", "*.tmp", "--profile", "lab")
        self.ok("profile", "create", "travel", "--from", "lab")
        self.ok("profile", "copy", "lab", "home-office")
        text = self.ini.read_text(encoding="utf-8")
        body = "hash = sha384\nexclude =\n    *.tmp\n"
        self.assertIn(f"[profile lab]\n{body}\n[profile travel]\n{body}\n[profile home-office]\n{body}", text)
        self.ok("profile", "rename", "travel", "away")
        self.assertIn("[profile away]\n", self.ini.read_text(encoding="utf-8"))
        self.ok("profile", "delete", "away")
        self.ok("profile", "delete", "home-office")
        self.assertTrue(self.ini.read_text(encoding="utf-8").endswith(f"[profile lab]\n{body}"))
        self.assertEqual(self.ok("profile", "list"), "lab  2 values, line 7\n")

    def test_an_empty_profile_says_so(self):
        self.ok("profile", "create", "lab")
        self.assertIn("It sets nothing", self.ok("profile", "show", "lab"))

    def test_delete_takes_its_own_comments_and_leaves_the_next_ones(self):
        self.write_settings(ini("[defaults]", "timeout = 3", "", "# first", "[profile a]", "hash = sha512", "# end of a", "", "# about b", "[profile b]", "retries = 1"))
        self.ok("profile", "delete", "a")
        self.assertEqual(self.ini.read_text(encoding="utf-8"), ini("[defaults]", "timeout = 3", "", "# about b", "[profile b]", "retries = 1"))

    def test_rename_keeps_everything_else(self):
        data = self.write_settings("[profile a]\r\n# note\r\nhash = sha512\r\n")
        self.ok("profile", "rename", "a", "b")
        self.assertEqual(self.ini.read_bytes(), data.replace(b"[profile a]", b"[profile b]"))

    def test_profile_errors(self):
        self.write_settings(ini("[profile lab]", "[profile other]"))
        before = self.ini.read_bytes()
        for arguments, phrase in (
            (("create", "lab"), "already a profile 'lab'"),
            (("create", "bad name"), "may use only letters"),
            (("create", "x" * 65), "longer than 64"),
            (("create", "new", "--from", "nope"), "there is no profile 'nope'"),
            (("copy", "nope", "new"), "there is no profile 'nope'"),
            (("copy", "lab", "other"), "already a profile 'other'"),
            (("rename", "nope", "new"), "there is no profile 'nope'"),
            (("rename", "lab", "other"), "already a profile 'other'"),
            (("rename", "lab", ".x"), "must start with a letter or digit"),
            (("delete", "nope"), "The profiles are: lab, other"),
        ):
            with self.subTest(arguments):
                self.assertIn(phrase, self.refused("profile", *arguments))
                self.assertEqual(self.ini.read_bytes(), before)

    def test_profile_commands_with_no_file(self):
        for arguments in (("show", "lab"), ("rename", "lab", "x"), ("delete", "lab"), ("create", "x", "--from", "lab")):
            with self.subTest(arguments):
                self.assertIn("there is no settings file", self.refused("profile", *arguments))
        self.assertFalse(self.ini.exists())
        self.assertIn("is not set there", self.ok("config", "unset", "timeout"))
        self.assertFalse(self.ini.exists())

    def test_another_file_can_be_managed(self):
        other = self.temp / "project" / "evidence.ini"
        self.ok("profile", "create", "lab", "--settings", other)
        self.ok("config", "set", "timeout", "9", "--profile", "lab", "--settings", other)
        self.assertEqual(self.ok("config", "get", "timeout", "--profile", "lab", "--settings", other), "9\n")
        self.assertFalse(self.ini.exists())

    def test_every_command_has_help_and_exit_codes(self):
        for arguments in (
            ("config",), ("config", "path"), ("config", "show"), ("config", "get"), ("config", "set"), ("config", "unset"),
            ("config", "check"), ("profile",), ("profile", "list"), ("profile", "show"), ("profile", "create"),
            ("profile", "copy"), ("profile", "rename"), ("profile", "delete"),
        ):
            with self.subTest(arguments):
                code, out, _ = run_cli(*arguments, "--help")
                self.assertEqual(code, 0)
                self.assertIn("usage:", out)
                self.assertIn("exit codes:", out)
        self.assertEqual(run_cli("config")[0], 2)
        self.assertEqual(run_cli("config", "sett", "timeout", "1")[0], 2)
        self.assertEqual(run_cli("config", "set", "timeout")[0], 2)


class Precedence(SettingsCase):
    def setUp(self):
        super().setUp()
        self.folder = self.write("work/a.txt", b"a\n").parent
        self.write("work/b.tmp", b"b\n")
        self.write("work/scratch.tmp", b"s\n")

    def seal(self, *extra):
        out = self.temp / "m.txt"
        if out.exists():
            out.unlink()
        self.ok("seal", self.folder, "--out", out, "--date", "2026-01-31", *extra)
        return out.read_text(encoding="utf-8")

    def test_without_a_settings_file_nothing_changes(self):
        plain = self.seal("--purpose", "p")
        self.assertEqual(self.seal("--purpose", "p", "--no-settings"), plain)
        self.write_settings("")
        self.assertEqual(self.seal("--purpose", "p"), plain)
        code, out, _ = run_cli("stamp", "--help")
        self.assertIn("(default: https://freetsa.org/tsr)", " ".join(out.split()))
        self.assertIn("(default: 60)", out)
        self.assertIn("(default: 2)", " ".join(out.split()))
        self.assertIn("(default: text)", run_cli("report", "--help")[1])
        self.assertIn("needs --purpose", self.refused("seal", self.folder))

    def test_the_four_commands_offer_the_settings_options(self):
        for command in ("seal", "stamp", "verify", "report"):
            with self.subTest(command):
                out = self.ok(command, "--help")
                for option in ("--profile NAME", "--settings FILE", "--no-settings"):
                    self.assertIn(option, out)

    def test_seal_takes_excludes_and_a_purpose_template(self):
        listed = self.write("lists/more.txt", b"scratch.tmp\n")
        self.write_settings(
            ini("[defaults]", "exclude =", "    *.tmp", "[profile lab]", "exclude-from =", "    ../lists/more.txt", "exclude = b.tmp", "purpose = Lab {folder} on {date}")
        )
        text = self.seal("--profile", "lab")
        self.assertIn("purpose: Lab work on 2026-01-31\n", text)
        self.assertIn("exclude: scratch.tmp\nexclude: b.tmp\nfiles: 1\n", text)
        self.assertNotIn("*.tmp", text)
        self.assertTrue(listed.is_file())
        text = self.seal("--purpose", "p")
        self.assertIn("exclude: *.tmp\nfiles: 1\n", text)
        self.assertIn("needs --purpose", self.refused("seal", self.folder, "--out", self.temp / "x.txt"))

    def test_the_command_line_wins_and_its_excludes_come_last(self):
        self.write_settings(ini("[defaults]", "exclude = *.tmp", "purpose = from the settings"))
        text = self.seal("--purpose", "typed", "--exclude", "!scratch.tmp")
        self.assertIn("purpose: typed\n", text)
        self.assertIn("exclude: *.tmp\nexclude: !scratch.tmp\nfiles: 2\n", text)
        self.assertIn("scratch.tmp", text.split("files:")[1])

    def test_the_dry_run_names_the_settings_line(self):
        self.write_settings(ini("[defaults]", "exclude =", "    *.tmp", "    nothing-here"))
        out = self.ok("seal", self.folder, "--dry-run")
        self.assertIn("b.tmp  by *.tmp (settings.ini line 3)", out)
        self.assertIn("nothing-here (settings.ini line 4)", out)

    def test_a_template_date_follows_the_created_field(self):
        self.write_settings(ini("[defaults]", "purpose = {{braces}} {folder} {date}"))
        out = self.temp / "today.txt"
        self.ok("seal", self.folder, "--out", out)
        lines = out.read_text(encoding="utf-8").splitlines()
        created = lines[2].split(": ")[1]
        self.assertEqual(lines[1], f"purpose: {{braces}} work {created[:10]}")

    def test_a_relative_exclude_file_is_found_beside_the_settings(self):
        self.write("home/skip.txt", b"*.tmp\n")
        self.write_settings(ini("[defaults]", "exclude-from = skip.txt"))
        self.assertIn("files: 1\n", self.seal("--purpose", "p"))
        self.write_settings(ini("[defaults]", "exclude-from = gone.txt"))
        out = self.refused("seal", self.folder, "--dry-run")
        self.assertIn("exclude-from in the defaults settings (settings.ini line 2)", out)

    def test_stamp_takes_each_option_in_order(self):
        manifest = self.write("m.txt", b"manifest\n")
        self.write_settings(
            ini(
                "[defaults]",
                "authority = http://defaults.example.test/tsr",
                "timeout = 30",
                "retries = 1",
                f"ca = {LOCAL / 'root-rsa.crt'}",
                "[profile lab]",
                "authority = https://lab.example.test/tsr",
                "hash = sha512",
                "policy = 1.2.3.4",
            )
        )
        calls = []

        def fake(*args, **kwargs):
            calls.append(kwargs)
            raise StampError("stopped by the test")

        with mock.patch("evidence_seal.stamping.stamp_manifest", fake):
            self.refused("stamp", manifest, code=1)
            self.refused("stamp", manifest, "--profile", "lab", code=1)
            self.refused("stamp", manifest, "--profile", "lab", "--tsa-url", "http://typed.example.test/", "--hash", "sha384", "--timeout", "5", "--retries", "0", "--policy", "1.2.5", "--ca", OTHER_ROOT, code=1)
            self.refused("stamp", manifest, "--no-settings", code=1)
        chosen = [
            (call["tsa_url"], call["timeout"], call["retries"], call["hash_name"], call["policy"], call["store"].sources) for call in calls
        ]
        self.assertEqual(chosen[0], ("http://defaults.example.test/tsr", 30.0, 1, "sha256", None, ["root-rsa.crt"]))
        self.assertEqual(chosen[1], ("https://lab.example.test/tsr", 30.0, 1, "sha512", "1.2.3.4", ["root-rsa.crt"]))
        self.assertEqual(chosen[2], ("http://typed.example.test/", 5.0, 0, "sha384", "1.2.5", ["other-root.crt"]))
        self.assertEqual(chosen[3], ("https://freetsa.org/tsr", 60, 2, "sha256", None, []))

    def test_an_authority_name_is_not_known(self):
        manifest = self.write("m.txt", b"manifest\n")
        self.write_settings(ini("[profile lab]", "authority = Example TSA"))
        with mock.patch("evidence_seal.stamping.stamp_manifest", side_effect=StampError("stopped by the test")) as stamp:
            out = self.refused("stamp", manifest, "--profile", "lab")
            self.assertFalse(stamp.called)
            self.refused("stamp", manifest, "--profile", "lab", "--tsa-url", "http://x.example.test/", code=1)
            self.assertEqual(stamp.call_args.kwargs["tsa_url"], "http://x.example.test/")
        self.assertIn("the authority name 'Example TSA' is not known", out)
        self.assertIn("(profile lab, settings.ini line 2)", out)
        self.assertEqual(settings.resolve_authority("HTTPS://tsa.example.test/"), ("HTTPS://tsa.example.test/", None))

    def test_an_authority_name_comes_from_the_authority_list(self):
        manifest = self.write("m.txt", b"manifest\n")
        root = LOCAL / "root-rsa.crt"
        code, _, err = run_cli("authority", "add", "Example-TSA", "https://tsa.example.test/tsr", "--root", root, "--hash", "sha384")
        self.assertEqual(code, 0, err)
        self.write_settings(ini("[defaults]", "ca =", f"    {root}", "[profile lab]", "authority = example-tsa"))
        self.assertEqual(run_cli("config", "check")[0], 0)
        with mock.patch("evidence_seal.stamping.stamp_manifest", side_effect=StampError("stopped by the test")) as stamp:
            self.refused("stamp", manifest, "--profile", "lab", code=1)
        sent = stamp.call_args.kwargs
        self.assertEqual(sent["tsa_url"], "https://tsa.example.test/tsr")
        self.assertEqual(sent["hash_name"], "sha384")
        self.assertEqual([root.sha256 for root in sent["store"].anchor_certificates], [authorities.find("Example-TSA").roots[0].sha256])

    def test_verify_takes_roots_from_the_settings_and_the_command_line_replaces_them(self):
        self.assertEqual(run_cli("verify", SEALED_MANIFEST, "--folder", MY_WORK)[0], 3)
        self.write_settings(ini("[defaults]", "ca =", f"    {SEALED_ROOT}"))
        self.assertIn("RESULT: VERIFIED", self.ok("verify", SEALED_MANIFEST, "--folder", MY_WORK))
        code, out, err = run_cli("verify", SEALED_MANIFEST, "--folder", MY_WORK, "--ca", OTHER_ROOT)
        self.assertNotEqual(code, 0, out + err)
        self.assertNotIn("RESULT: VERIFIED", out)
        self.assertEqual(run_cli("verify", SEALED_MANIFEST, "--folder", MY_WORK, "--no-settings")[0], 3)

    def test_verify_takes_allow_added_and_excludes(self):
        copy = self.temp / "my-work"
        shutil.copytree(MY_WORK, copy)
        (copy / "extra.tmp").write_bytes(b"new\n")
        base = ("verify", SEALED_MANIFEST, "--folder", copy, "--ca", SEALED_ROOT)
        self.assertEqual(run_cli(*base)[0], 1)
        self.write_settings(ini("[profile lenient]", "allow-added = yes", "[profile tidy]", "exclude = *.tmp", "[profile strict]", "allow-added = no"))
        self.ok(*base, "--profile", "lenient")
        self.ok(*base, "--profile", "tidy")
        self.assertEqual(run_cli(*base, "--profile", "strict")[0], 1)
        self.ok(*base, "--profile", "strict", "--allow-added")

    def test_verify_names_a_missing_root_file_by_its_settings_line(self):
        self.write_settings(ini("[defaults]", "untrusted =", "    gone.crt"))
        out = self.refused("verify", SEALED_MANIFEST, "--folder", MY_WORK)
        self.assertIn("untrusted in the defaults settings (settings.ini line 3)", out)
        self.assertIn("gone.crt, which is not a file", out)

    def test_report_takes_its_format(self):
        self.assertEqual(settings.KEYS["report-format"].check("html", self.temp), "html")
        self.assertEqual(report_formats.FORMAT_NAMES[0], settings.built_in("report-format"))
        self.write_settings(ini("[defaults]", f"ca = {SEALED_ROOT}", "[profile pages]", "report-format = html"))
        out = self.ok("report", SEALED_MANIFEST, "--folder", MY_WORK, "--out", "-", "--profile", "pages")
        self.assertIn("<html", out)
        out = self.ok("report", SEALED_MANIFEST, "--folder", MY_WORK, "--out", "-", "--profile", "pages", "--format", "text")
        self.assertIn("RESULT: VERIFIED", out)
        self.assertNotIn("<html", out)
        copy = self.temp / "sealed"
        shutil.copytree(EXAMPLES / "sealed", copy)
        self.ok("report", copy / "my-work-manifest.txt", "--folder", MY_WORK, "--profile", "pages")
        self.assertTrue((copy / "my-work-manifest.report.html").is_file())

    def test_choosing_a_profile_or_file_that_is_not_there(self):
        self.assertIn("there is no settings file at", self.refused("seal", self.folder, "--dry-run", "--profile", "lab"))
        self.write_settings(ini("[profile lab]", "[profile travel]"))
        out = self.refused("verify", SEALED_MANIFEST, "--profile", "nope")
        self.assertIn("there is no profile 'nope'", out)
        self.assertIn("The profiles are: lab, travel", out)
        self.assertIn("cannot be used with --no-settings", self.refused("seal", self.folder, "--dry-run", "--no-settings", "--profile", "lab"))
        self.assertIn("does not exist", self.refused("report", SEALED_MANIFEST, "--settings", self.temp / "none.ini"))
        self.assertIn("not allowed with argument", self.refused("stamp", "m.txt", "--settings", self.ini, "--no-settings"))
        self.assertIn("is a folder", self.refused("seal", self.folder, "--dry-run", "--settings", self.temp))

    def test_another_settings_file_is_used_with_its_own_folder(self):
        self.write("project/excludes.txt", b"*.tmp\n")
        other = self.write("project/evidence.ini", ini("[defaults]", "exclude-from = excludes.txt", "purpose = project").encode())
        self.assertIn("files: 1\n", self.seal("--settings", other))

    def test_a_damaged_file_stops_every_command_until_it_is_fixed_or_ignored(self):
        self.write_settings(ini("[defaults]", "exlude = *.tmp"))
        for arguments in (
            ("seal", self.folder, "--dry-run"),
            ("stamp", self.temp / "m.txt"),
            ("verify", SEALED_MANIFEST),
            ("report", SEALED_MANIFEST, "--out", "-"),
        ):
            with self.subTest(arguments[0]):
                out = self.refused(*arguments)
                self.assertIn("settings.ini line 2: there is no setting 'exlude' in [defaults]; did you mean 'exclude'?", out)
                self.assertIn("add --no-settings", out)
        self.ok("seal", self.folder, "--dry-run", "--no-settings")

    def test_a_newer_file_is_refused_and_left_alone(self):
        data = self.write_settings(ini("[settings]", "version = 3", "[defaults]", "exclude: new syntax"))
        out = self.refused("seal", self.folder, "--dry-run")
        self.assertIn("settings version 3, written by a newer evidence-seal", out)
        self.ok("seal", self.folder, "--dry-run", "--no-settings")
        self.assertIn("settings version 3", self.refused("config", "set", "timeout", "5"))
        self.assertEqual(self.ini.read_bytes(), data)

    def test_the_library_switch_is_resolved(self):
        self.assertTrue(settings.settings_for(None, None, False).library)
        self.write_settings(ini("[defaults]", "library = off", "[profile keep]", "library = on"))
        self.assertFalse(settings.settings_for(None, None, False).library)
        self.assertTrue(settings.settings_for(None, "keep", False).library)
        self.assertTrue(settings.settings_for(None, None, True).library)


class Documentation(SettingsCase):
    TEXT = (ROOT_OF_REPO / "docs" / "SETTINGS.md").read_text(encoding="utf-8")

    def test_every_documented_command_parses(self):
        commands = list(documents.fenced_commands("docs/SETTINGS.md"))
        self.assertGreater(len(commands), 5)
        for line in commands:
            with self.subTest(line):
                self.assertTrue(line.startswith("python -m evidence_seal "))
                for token in ("&&", "||", "; "):
                    self.assertNotIn(token, line)
                cli.build_parser().parse_args(shlex.split(line)[3:])

    def test_the_example_file_reads_cleanly(self):
        example = re.search(r"```ini\n(.*?)```", self.TEXT, re.DOTALL).group(1)
        document = self.document(example)
        self.assertEqual(document.problems, [])
        self.assertEqual(document.values[("[profile lab]", "purpose")], "Lab notebook {folder}, sealed {date}")

    def test_every_key_is_documented(self):
        for name in settings.KEYS:
            self.assertIn(f"| `{name}` |", self.TEXT)

    def test_the_format_document_points_here(self):
        self.assertIn("(SETTINGS.md)", (ROOT_OF_REPO / "docs" / "FORMAT.md").read_text(encoding="utf-8"))
