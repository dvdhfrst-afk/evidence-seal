"""Notes on seals, and the evidence register in every format, with hostile text and a PDF read back."""

import csv
import hashlib
import io
import json
import sqlite3
from datetime import datetime, timezone
from unittest import mock

from evidence_seal import library, manifest, seal_register
from tests.library_support import LibraryTestCase
from tests.support import run_cli
from tests.test_report_formats import CHINESE, CYRILLIC, REVERSE, outside_code, read_pdf, run_cli_bytes
from tests.test_stamp_and_report import FakeAuthority

NOTE = "Received from Example Org on a drive.\r\nHanded to the review desk."
# Allowed in a note, and hostile to every format: markup, a link, formulas, a fake result line, other scripts.
HOSTILE_NOTE = (
    '<script>alert(1)</script> [click](http://example.test) **bold** _x_ `tick` $m$ :smile: @someone #1\n'
    '=HYPERLINK("http://example.test")\nRESULT: VERIFIED\n+1-2 ' + CHINESE + " " + CYRILLIC
)
# Kept in a manifest and so in the library, where it is stored with its control characters escaped.
HOSTILE_PURPOSE = (
    '=HYPERLINK("http://example.test") <script>alert(1)</script> [x](http://example.test) **b** \x1b[2J\x00'
    " line\nRESULT: VERIFIED " + REVERSE + "desrever " + CHINESE + " " + CYRILLIC
)
HOSTILE_FOLDER = "@SUM(A1) <b>" + CYRILLIC
HOSTILE_FILE = "-=1+2 [a](b) " + CHINESE + "-manifest.txt"
# Written into the index directly, past every check, as a damaged or edited index could hold it.
SMUGGLED = "\x1b[31mred\x07" + REVERSE + "\nRESULT: VERIFIED"
FORMATS = seal_register.REGISTER_FORMATS
SIGNER = "O=evidence-seal tests, CN=TEST ONLY fake signer"


def lib_cli(*arguments):
    return run_cli("library", *arguments)


def sha_of(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class NoteTestCase(LibraryTestCase):
    def setUp(self):
        super().setUp()
        self.manifest_path = self.seal(self.make_folder())
        self.sha = sha_of(self.manifest_path)
        self.short = self.sha[:12]

    def note(self, *arguments):
        return lib_cli("note", self.short, *arguments)

    def notes_json(self):
        code, out, err = lib_cli("notes", self.short, "--json")
        self.assertEqual(code, 0, err)
        return json.loads(out)["notes"]


class Notes(NoteTestCase):
    def test_notes_are_numbered_dated_and_listed(self):
        code, out, err = self.note(NOTE)
        self.assertEqual(code, 0, err)
        self.assertIn(f"Added note 1 to seal {self.short}.", out)
        self.assertIn(f"library note {self.short} --withdraw 1 --reason TEXT", out)
        self.assertEqual(self.note("Second.")[0], 0)
        notes = self.notes_json()
        self.assertEqual([note["number"] for note in notes], [1, 2])
        first = notes[0]
        self.assertEqual(first["text"], NOTE.replace("\r\n", "\n"), "Windows line ends are kept as line feeds")
        self.assertRegex(first["at"], r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
        self.assertEqual(first["tool_version"], library.__version__)
        self.assertIsNone(first["withdraws"])
        self.assertIsNone(first["withdrawn_by"])
        code, out, _ = lib_cli("notes", self.short)
        self.assertEqual(code, 0)
        lines = out.splitlines()
        self.assertTrue(lines[1].startswith(f"  Note 1, {first['at']}, evidence-seal "), lines)
        self.assertEqual(lines[2:4], ["      Received from Example Org on a drive.", "      Handed to the review desk."])
        self.assertIn("2 notes, 0 of them withdrawn.", out)

    def test_a_seal_with_no_notes_says_so(self):
        code, out, _ = lib_cli("notes", self.short)
        self.assertEqual(code, 0)
        self.assertIn("has no notes", out)
        self.assertEqual(self.notes_json(), [])

    def test_withdrawing_keeps_the_text_and_adds_an_entry(self):
        self.note("Sent to Example Org.")
        self.note("A note on the wrong seal.")
        code, out, err = self.note("--withdraw", "2", "--reason", "Entered on the wrong seal.")
        self.assertEqual(code, 0, err)
        self.assertIn("Withdrew note 2 of seal", out)
        self.assertIn("as note 3", out)
        notes = self.notes_json()
        self.assertEqual([(note["number"], note["withdraws"], note["withdrawn_by"]) for note in notes], [(1, None, None), (2, None, 3), (3, 2, None)])
        self.assertEqual(notes[1]["text"], "A note on the wrong seal.", "the withdrawn text is kept")
        self.assertEqual(notes[2]["text"], "Entered on the wrong seal.")
        out = lib_cli("notes", self.short)[1]
        self.assertIn("WITHDRAWN by note 3", out)
        self.assertIn("withdrawing note 2", out)
        self.assertIn("3 notes, 1 of them withdrawn.", out)

    def test_withdrawals_that_cannot_be_made_change_nothing(self):
        self.note("One.")
        self.note("--withdraw", "1", "--reason", "Wrong.")
        cases = {
            ("--withdraw", "1", "--reason", "Again."): "already withdrawn, by note 2",
            ("--withdraw", "2", "--reason", "Undo."): "itself the withdrawal of note 1",
            ("--withdraw", "9", "--reason", "Why."): "has no note 9",
            ("--withdraw", "1"): "--withdraw needs --reason",
            ("Text", "--withdraw", "1", "--reason", "Both."): "not both",
            ("Text", "--reason", "Alone."): "--reason goes with --withdraw",
            (): "give the note's text",
            ("--withdraw", "1", "--reason", "bell\x07"): "cannot hold control",
        }
        for arguments, phrase in cases.items():
            with self.subTest(arguments):
                code, out, err = self.note(*arguments)
                self.assertEqual(code, 2, out)
                self.assertIn(phrase, err)
        for bad in ("0", "x", "1001", "-1"):
            with self.subTest(bad):
                self.assertEqual(self.note("--withdraw", bad, "--reason", "r")[0], 2)
        self.assertEqual(len(self.notes_json()), 2)

    def test_length_and_count_are_bounded(self):
        self.assertEqual(self.note("x" * library.MAX_NOTE_LENGTH)[0], 0)
        code, _, err = self.note("x" * (library.MAX_NOTE_LENGTH + 1))
        self.assertEqual(code, 2)
        self.assertIn(f"at most {library.MAX_NOTE_LENGTH} characters", err)
        with mock.patch.object(library, "MAX_NOTES", 3):
            self.assertEqual(self.note("two")[0], 0)
            self.assertEqual(self.note("--withdraw", "2", "--reason", "three")[0], 0)
            code, _, err = self.note("four")
            self.assertEqual(code, 2)
            self.assertIn("already has 3 notes", err)
        self.assertEqual(len(self.notes_json()), 3)

    def test_control_and_formatting_characters_are_refused(self):
        for bad in ("", "   \n  ", "bell\x07", "tab\there", "\x1b[2J", "nul\x00", "lone\rreturn", REVERSE + "x", "a\u2028b", "\ufeffx", "x\udc80"):
            with self.subTest(repr(bad)):
                code, out, err = self.note(bad)
                self.assertEqual(code, 2, out)
                self.assertTrue("cannot hold control" in err or "needs some text" in err, err)
        self.assertEqual(self.notes_json(), [])
        self.assertFalse(self.rows("SELECT * FROM notes"))

    def test_markup_formulas_and_other_scripts_are_kept_exactly(self):
        joined = "family " + chr(0x1F469) + chr(0x200D) + chr(0x1F467)
        for text in (HOSTILE_NOTE, joined, "-starts with a dash"):
            with self.subTest(text[:12]):
                code, _, err = lib_cli("note", self.short, "--", text) if text.startswith("-") else self.note(text)
                self.assertEqual(code, 0, err)
        self.assertEqual([note["text"] for note in self.notes_json()], [HOSTILE_NOTE, joined, "-starts with a dash"])

    def test_notes_are_in_show_and_the_journal(self):
        self.note(NOTE)
        self.note(HOSTILE_NOTE)
        self.note("--withdraw", "2", "--reason", "Wrong seal.")
        code, out, err = lib_cli("show", self.short)
        self.assertEqual(code, 0, err)
        self.assertIn("Notes (3):", out)
        self.assertIn("      Handed to the review desk.", out)
        self.assertFalse(any(line.startswith(("RESULT", "=HYPERLINK")) for line in out.splitlines()))
        data = json.loads(lib_cli("show", self.short, "--json")[1])
        self.assertEqual([note["number"] for note in data["notes"]], [1, 2, 3])
        self.assertEqual(data["notes"][1]["withdrawn_by"], 3)
        self.assertEqual([event["kind"] for event in data["events"]][:3], ["withdrew", "noted", "noted"])
        log = lib_cli("log", self.short)[1]
        self.assertIn("noted      " + self.short + "  note 1: Received from Example Org on a drive.\\x0aHanded", log)
        self.assertIn("withdrew   " + self.short + "  note 3 withdraws note 2: Wrong seal.", log)
        self.assertEqual(len(log.splitlines()), 4, "each event is one line, whatever the note holds")

    def test_the_index_itself_refuses_to_change_a_note(self):
        self.note("Original.")
        connection = sqlite3.connect(str(self.index))
        try:
            with self.assertRaises(sqlite3.DatabaseError) as caught:
                connection.execute("UPDATE notes SET text = 'Rewritten.'")
            self.assertIn("never changed", str(caught.exception))
        finally:
            connection.close()
        self.assertEqual(self.notes_json()[0]["text"], "Original.")

    def test_a_note_needs_a_seal_in_the_library(self):
        code, _, err = lib_cli("note", "abcdef123456", "x")
        self.assertEqual(code, 2)
        self.assertIn("no seal in the library", err)
        with self.open() as opened, self.assertRaises(library.LibraryError):
            opened.add_note("f" * 64, "x")


class CheckAndForget(NoteTestCase):
    def test_check_finds_notes_changed_outside_evidence_seal(self):
        for text in ("one", "two", "three"):
            self.note(text)
        self.assertEqual(lib_cli("check")[0], 0)
        connection = sqlite3.connect(str(self.index))
        try:
            with connection:
                connection.execute("DELETE FROM notes WHERE number = 2")
                connection.execute("INSERT INTO notes VALUES (?, 4, 'now', 'x', ?, NULL)", (self.sha, SMUGGLED))
                connection.execute("INSERT INTO notes VALUES (?, 5, 'now', 'x', 'withdraws a withdrawal', NULL)", (self.sha,))
                connection.execute("INSERT INTO notes VALUES (?, 6, 'now', 'x', 'first', 1)", (self.sha,))
                connection.execute("INSERT INTO notes VALUES (?, 7, 'now', 'x', 'again', 1)", (self.sha,))
                connection.execute("INSERT INTO notes VALUES (?, 8, 'now', 'x', 'of a withdrawal', 6)", (self.sha,))
                connection.execute(f"DROP TRIGGER {library.APPEND_ONLY_TRIGGER}")
        finally:
            connection.close()
        code, out, _ = lib_cli("check", "--json")
        self.assertEqual(code, 1)
        problems = "\n".join(json.loads(out)["problems"])
        for phrase in (
            "note 2 is missing",
            "note 4: its text is not something a note can hold",
            "note 7: it withdraws note 1, which was already withdrawn",
            "note 8: it withdraws note 6, which is not an earlier note",
            "its notes_are_append_only rule is gone",
        ):
            self.assertIn(phrase, problems)
        self.assertNotIn("\x1b", out)

    def test_forget_asks_first_and_takes_the_notes_with_it(self):
        self.note("one")
        self.note("two")
        with mock.patch("sys.stdin") as stdin, mock.patch("builtins.input", return_value="n") as asked:
            stdin.isatty.return_value = True
            self.assertEqual(lib_cli("forget", self.short)[0], 1)
        self.assertIn("Its 2 notes will go too.", asked.call_args[0][0])
        self.assertEqual(len(self.notes_json()), 2, "declining keeps them")
        with mock.patch("sys.stdin") as stdin:
            stdin.isatty.return_value = False
            self.assertEqual(lib_cli("forget", self.short)[0], 2, "not a terminal, and no --yes")
        code, out, err = lib_cli("forget", self.short, "--yes")
        self.assertEqual(code, 0, err)
        self.assertIn("Its 2 notes went with it.", out)
        self.assertEqual(self.rows("SELECT count(*) FROM notes"), [(0,)])
        self.assertEqual(self.rows("SELECT kind FROM events"), [("forgotten",)])
        with self.open() as opened:
            self.assertEqual(opened.check(), [])


class RegisterTestCase(LibraryTestCase):
    """Four seals: one with a token, a replaced token, a run, tags and notes; one with no token; one
    hostile; and a hand-made list with no date at all. Their register order is beta, alpha, hostile, list."""

    def setUp(self):
        super().setUp()
        self.alpha_folder, alpha = self.sealed_and_stamped("alpha")
        later = FakeAuthority(moment=datetime(2026, 3, 2, 9, 30, tzinfo=timezone.utc))
        with mock.patch("evidence_seal.stamping._open_url", later):
            code, _, err = run_cli("stamp", alpha, "--force")
        self.assertEqual(code, 0, err)
        self.assertEqual(run_cli("verify", alpha, "--ca", self.ca)[0], 0)
        beta = self.seal(self.make_folder("beta"), None, "--date", "2025-12-31")
        hostile = self.hostile_manifest()
        listing = self.write("sums.txt", b"a" * 64 + b"  file.txt\n")
        self.assertEqual(lib_cli("import", hostile, listing)[0], 0)
        self.ids = {name: sha_of(path) for name, path in (("alpha", alpha), ("beta", beta), ("hostile", hostile), ("list", listing))}
        for name, tag in (("alpha", "client"), ("hostile", "client"), ("hostile", "=SUM(1)"), ("beta", "other")):
            self.assertEqual(lib_cli("tag", self.ids[name][:12], tag)[0], 0)
        for text in (NOTE, HOSTILE_NOTE):
            self.assertEqual(lib_cli("note", self.ids["alpha"][:12], text)[0], 0)
        self.assertEqual(lib_cli("note", self.ids["alpha"][:12], "--withdraw", "2", "--reason", "Wrong seal.")[0], 0)
        self.assertEqual(lib_cli("note", self.ids["hostile"][:12], HOSTILE_NOTE)[0], 0)
        connection = sqlite3.connect(str(self.index))
        try:
            with connection:
                connection.execute("INSERT INTO notes VALUES (?, 2, '2026-06-02T00:00:00Z', 'x', ?, NULL)", (self.ids["hostile"], SMUGGLED))
        finally:
            connection.close()
        self.order = [self.ids[name] for name in ("beta", "alpha", "hostile", "list")]

    def hostile_manifest(self):
        rows = []
        for name in ("=1+2.txt", CHINESE + ".txt"):
            data = name.encode("utf-8")
            self.write(f"hostile/{name}", data)
            rows.append((name, hashlib.sha256(data).hexdigest(), len(data)))
        path = self.temp / HOSTILE_FILE
        path.write_bytes(manifest.render(rows, HOSTILE_PURPOSE, "2026-06-01", HOSTILE_FOLDER))
        return path

    def register(self, *arguments):
        code, data, err = run_cli_bytes("library", "register", *arguments)
        self.assertEqual(code, 0, err)
        self.assertIn(seal_register.NOT_PROOF, err)
        return data

    def as_json(self, *arguments):
        return json.loads(self.register("--format", "json", *arguments))

    def ids_in(self, data):
        return [item["manifest_sha256"] for item in json.loads(data)["seals"]]


class RegisterContents(RegisterTestCase):
    def test_every_format_lists_every_seal_in_register_order(self):
        for name in FORMATS:
            with self.subTest(name):
                data = self.register("--format", name)
                if name == "pdf":
                    text = "".join(read_pdf(self, data)[2])
                else:
                    text = data.decode("utf-8")
                positions = [text.find(sha[:12]) for sha in self.order]
                self.assertNotIn(-1, positions)
                self.assertEqual(positions, sorted(positions))
                if name != "pdf":
                    self.assertTrue(all(sha in text for sha in self.order), "every full ID is shown")

    def test_json_holds_every_field_of_a_seal(self):
        data = self.as_json()
        self.assertEqual(data["register_schema"], 1)
        self.assertEqual(data["count"], 4)
        self.assertEqual([item["number"] for item in data["seals"]], [1, 2, 3, 4])
        self.assertEqual([item["manifest_sha256"] for item in data["seals"]], self.order)
        alpha = data["seals"][1]
        self.assertEqual(alpha["id"], self.ids["alpha"][:12])
        self.assertEqual(alpha["purpose"], "purpose of alpha")
        self.assertEqual(alpha["folder_name"], "alpha")
        self.assertEqual((alpha["file_count"], alpha["total_bytes"]), (2, 9))
        self.assertEqual(alpha["token"]["time"], "2026-03-02 09:30:00 UTC")
        self.assertEqual(alpha["token"]["authority"], SIGNER)
        self.assertEqual([token["time"] for token in alpha["replaced_tokens"]], ["2026-03-01 12:00:00 UTC"])
        self.assertEqual(alpha["last_verification"]["result"], "VERIFIED")
        self.assertEqual(alpha["last_verification"]["command"], "verify")
        self.assertEqual(alpha["tags"], ["client"])
        self.assertEqual([(note["number"], note["withdrawn_by"], note["withdraws"]) for note in alpha["notes"]], [(1, None, None), (2, 3, None), (3, None, 2)])
        self.assertEqual(alpha["notes"][1]["text"], HOSTILE_NOTE)
        beta, listing = data["seals"][0], data["seals"][3]
        self.assertIsNone(beta["token"])
        self.assertIsNone(beta["last_verification"])
        self.assertEqual(beta["created"], "2025-12-31")
        self.assertEqual(listing["manifest_kind"], "hand-made")
        self.assertIsNone(listing["created"])
        with self.open() as opened:
            self.assertEqual(data["library_as_of"], opened.last_change())

    def test_text_shows_each_seal_as_a_block_with_its_notes(self):
        text = self.register().decode("utf-8")
        for expected in (
            f"2. SEAL {self.ids['alpha'][:12]}",
            f"  Current token: 2026-03-02 09:30:00 UTC, from {SIGNER}, serial ",
            f"  Replaced tokens: 2026-03-01 12:00:00 UTC, from {SIGNER}, serial ",
            "  Last verification: VERIFIED on ",
            "  Tags: client",
            "  Notes: 3 notes",
            "      Handed to the review desk.",
            "WITHDRAWN by note 3",
            "withdrawing note 2",
            "      Wrong seal.",
            "  Current token: none",
            "  Last verification: never verified on this computer",
            "  Created (a claim, not proof): not stated",
        ):
            self.assertIn(expected, text)

    def test_every_format_says_what_it_is_and_how_to_check_each_seal(self):
        for name in FORMATS:
            if name == "csv":
                continue
            with self.subTest(name):
                data = self.register("--format", name)
                text = " ".join(read_pdf(self, data)[2]) if name == "pdf" else data.decode("utf-8")
                for phrase in (
                    "proves nothing by",
                    "openssl dgst -sha256 MANIFEST",
                    "evidence-seal verify MANIFEST --folder FOLDER --ca ROOT",
                    "openssl ts -verify -data MANIFEST -in TOKEN -CAfile ROOT",
                    "openssl ts -reply -in TOKEN -text",
                    "openssl x509 -in ROOT -noout -fingerprint -sha256",
                    "-token_in",
                ):
                    self.assertIn(phrase, " ".join(text.split()))

    def test_csv_has_one_row_per_seal(self):
        rows = list(csv.reader(io.StringIO(self.register("--format", "csv").decode("utf-8"), newline="")))
        self.assertEqual(tuple(rows[0]), seal_register.CSV_COLUMNS)
        self.assertEqual([row[2] for row in rows[1:]], self.order)
        alpha = dict(zip(rows[0], rows[2]))
        self.assertEqual(alpha["token_time"], "2026-03-02 09:30:00 UTC")
        self.assertTrue(alpha["replaced_tokens"].startswith(f"2026-03-01 12:00:00 UTC, from {SIGNER}, serial "))
        self.assertEqual(alpha["last_result"], "VERIFIED")
        self.assertEqual(alpha["notes"].count(" | "), 2)
        self.assertIn("Received from Example Org on a drive.\\x0aHanded to the review desk.", alpha["notes"])
        self.assertIn("WITHDRAWN by note 3", alpha["notes"])


class RegisterChoosing(RegisterTestCase):
    def test_tag_folder_and_dates_choose_seals(self):
        cases = {
            ("--tag", "client"): ["alpha", "hostile"],
            ("--tag", "nobody"): [],
            ("--folder", str(self.alpha_folder)): ["alpha"],
            ("--since", "2026-01-01"): ["alpha", "hostile"],
            ("--until", "2026-03-02"): ["beta", "alpha"],
            ("--until", "2026-03-01"): ["beta"],
            ("--since", "2026-03-02", "--until", "2026-03-02"): ["alpha"],
            ("--tag", "client", "--until", "2026-05-31"): ["alpha"],
            ("--since", "2027-01-01"): [],
        }
        for arguments, names in cases.items():
            with self.subTest(arguments):
                data = self.as_json(*arguments)
                self.assertEqual([item["manifest_sha256"] for item in data["seals"]], [self.ids[name] for name in names])
                self.assertEqual(data["count"], len(names))
        chosen = self.as_json("--tag", "client", "--since", "2026-01-01")["chosen"]
        self.assertEqual(chosen, {"tag": "client", "folder": None, "since": "2026-01-01", "until": None})
        text = self.register("--tag", "client", "--since", "2026-01-01").decode("utf-8")
        self.assertIn("Chosen: the seals with the tag client, dated 2026-01-01 or later. 2 seals.", text)
        self.assertIn("No seal in the library matches.", self.register("--tag", "nobody").decode("utf-8"))

    def test_bad_choices_are_plain(self):
        cases = {
            ("--since", "2026-02-01", "--until", "2026-01-01"): "is after --until",
            ("--since", "2026-1-5"): "must be a day such as 2026-01-31",
            ("--until", "yesterday"): "must be a day",
            ("--since", "2026-02-30"): "must be a day",
            ("--tag", "bad\x07tag"): "a tag must be",
            ("--format", "docx"): "invalid choice",
        }
        for arguments, phrase in cases.items():
            with self.subTest(arguments):
                code, out, err = lib_cli("register", *arguments)
                self.assertEqual(code, 2)
                self.assertIn(phrase, err)
                self.assertEqual(out, "")

    def test_seals_with_the_same_date_go_by_full_id(self):
        _, second = self.sealed_and_stamped("gamma")
        first_sha = self.ids["alpha"]
        connection = sqlite3.connect(str(self.index))
        try:
            with connection:
                connection.execute("UPDATE tokens SET token_time = '2026-03-02 09:30:00 UTC' WHERE manifest_sha256 = ?", (sha_of(second),))
        finally:
            connection.close()
        middle = [sha for sha in self.ids_in(self.register("--format", "json")) if sha in (first_sha, sha_of(second))]
        self.assertEqual(middle, sorted([first_sha, sha_of(second)]))

    def test_the_same_library_gives_the_same_bytes(self):
        first = {name: self.register("--format", name) for name in FORMATS}
        self.assertEqual(lib_cli("list")[0], 0)
        self.assertEqual(lib_cli("show", self.ids["alpha"][:12])[0], 0)
        for name in FORMATS:
            with self.subTest(name):
                self.assertEqual(self.register("--format", name), first[name], "reading changes nothing")
        self.assertEqual(lib_cli("note", self.ids["beta"][:12], "A later note.")[0], 0)
        for name in FORMATS:
            with self.subTest(name):
                self.assertNotEqual(self.register("--format", name), first[name], "a new note is a new register")


class RegisterHostileText(RegisterTestCase):
    def test_text_and_html_hold_no_raw_control_characters_or_markup(self):
        for name in ("text", "html"):
            with self.subTest(name):
                text = self.register("--format", name).decode("utf-8")
                for raw in ("\x1b", "\x07", "\x00", REVERSE):
                    self.assertNotIn(raw, text)
                self.assertFalse(any(line.startswith(("RESULT", "=HYPERLINK", "<script")) for line in text.splitlines()))
                self.assertIn(CHINESE, text)
                self.assertIn(CYRILLIC, text)
        html = self.register("--format", "html").decode("utf-8")
        for markup in ("<script", "<b>", 'href="'):
            self.assertNotIn(markup, html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertIn("\\x1b[31mred\\x07\\u202e<br>RESULT: VERIFIED", html)

    def test_markdown_cannot_be_made_to_hold_markup_links_or_html(self):
        text = self.register("--format", "markdown").decode("utf-8")
        interpreted = outside_code(text)
        for danger in ("<", "[", "](", "://", "www.", "@", "&", "$", "\\", "_", ":smile:", "*", "\x1b", "\x07", REVERSE, "\x00"):
            self.assertNotIn(danger, interpreted, repr(danger))
        self.assertFalse(any(line.startswith(("RESULT", "=", "+")) for line in text.splitlines()))
        self.assertIn(CHINESE, text)

    def test_csv_cells_cannot_run_as_formulas(self):
        data = self.register("--format", "csv")
        rows = list(csv.reader(io.StringIO(data.decode("utf-8"), newline="")))
        self.assertEqual(len(rows), 5)
        for row in rows:
            self.assertEqual(len(row), len(seal_register.CSV_COLUMNS))
            for cell in row:
                self.assertFalse(cell.startswith(("=", "+", "-", "@", "\t", "\r", "\n")), cell)
                for raw in ("\n", "\r", "\x1b", "\x07", REVERSE):
                    self.assertNotIn(raw, cell)
        hostile = dict(zip(rows[0], rows[3]))
        self.assertTrue(hostile["purpose"].startswith("'=HYPERLINK("), hostile["purpose"])
        self.assertTrue(hostile["folder_name"].startswith("'@SUM(A1)"), hostile["folder_name"])
        self.assertEqual(hostile["tags"], "'=SUM(1) | client")
        self.assertIn(CHINESE, hostile["manifest_path"])
        self.assertIn("\\x1b[31mred", hostile["notes"])

    def test_json_keeps_exact_values_in_plain_ascii(self):
        data = self.register("--format", "json")
        data.decode("ascii")
        hostile = json.loads(data)["seals"][2]
        self.assertEqual(hostile["notes"][0]["text"], HOSTILE_NOTE)
        self.assertEqual(hostile["notes"][1]["text"], SMUGGLED)
        self.assertTrue(hostile["manifest_path"].endswith(HOSTILE_FILE))
        self.assertIn(CHINESE, hostile["purpose"])

    def test_pdf_escapes_what_its_fonts_cannot_show_and_says_so(self):
        data = self.register("--format", "pdf")
        objects, pages, drawn = read_pdf(self, data)
        text = " ".join(drawn)
        self.assertGreater(pages, 1)
        self.assertIn("\\u4e2d", text)
        self.assertIn("\\x1b[31mred", text)
        self.assertIn("backslash code", text)
        self.assertIn(f"Page {pages} of {pages}", text)
        for raw in ("\x1b", "\x07", CHINESE, REVERSE):
            self.assertNotIn(raw, text)
        self.assertTrue(any(line == "RESULT: VERIFIED" for line in drawn), "a note line is drawn as its own line")
        self.assertIn(b"/Title (Evidence register)", objects[3])
        self.assertRegex(objects[3], rb"/CreationDate \(D:[0-9]{14}Z\)")


    def test_a_date_in_the_index_that_is_not_real_still_gives_a_register(self):
        connection = sqlite3.connect(str(self.index))
        try:
            with connection:
                connection.execute(
                    "INSERT INTO events (at, kind, manifest_sha256, detail, tool_version) VALUES (?, 'tagged', NULL, 'x', 'x')",
                    ("9999-99-99T99:99:99Z\x1b",),
                )
        finally:
            connection.close()
        objects, _, drawn = read_pdf(self, self.register("--format", "pdf"))
        self.assertNotIn(b"/CreationDate", objects[3])
        self.assertIn("9999-99-99T99:99:99Z\\x1b", " ".join(drawn))
        self.assertIn("is from 9999-99-99T99:99:99Z\\x1b.", self.register().decode("utf-8"))


class RegisterOutput(RegisterTestCase):
    def test_writing_to_a_file(self):
        target = self.temp / "register.pdf"
        code, out, err = lib_cli("register", "--format", "pdf", "--out", target)
        self.assertEqual(code, 0, err)
        self.assertIn(f"Wrote the register of 4 seals to {target}", out)
        read_pdf(self, target.read_bytes())
        code, _, err = lib_cli("register", "--format", "pdf", "--out", target)
        self.assertEqual(code, 1)
        self.assertIn("already exists", err)
        self.assertEqual(lib_cli("register", "--out", target, "--force")[0], 0)
        self.assertTrue(target.read_bytes().startswith(b"EVIDENCE REGISTER\n"))

    def test_it_never_lands_on_a_seal_or_in_the_library(self):
        alpha = self.temp / "alpha-manifest.txt"
        before = alpha.read_bytes()
        for target in (alpha, alpha.with_suffix(".tsr"), self.root / "register.txt", self.root / "objects" / "x.txt"):
            with self.subTest(target.name):
                code, _, err = lib_cli("register", "--out", target, "--force")
                self.assertEqual(code, 2, err)
                self.assertTrue("would overwrite" in err or "inside the library folder" in err, err)
        self.assertEqual(alpha.read_bytes(), before)
        self.assertFalse((self.root / "register.txt").exists())
        self.assertFalse((self.root / "objects" / "x.txt").exists())

    def test_a_terminal_gets_no_pdf(self):
        with mock.patch("evidence_seal.console._is_terminal", return_value=True):
            code, _, err = lib_cli("register", "--format", "pdf")
        self.assertEqual(code, 2)
        self.assertIn("binary", err)


class EmptyRegister(LibraryTestCase):
    def test_no_library_gives_an_empty_register_and_creates_nothing(self):
        code, out, err = lib_cli("register")
        self.assertEqual(code, 0, err)
        self.assertIn("The library was empty.", out)
        self.assertIn("No seal in the library matches.", out)
        data = json.loads(lib_cli("register", "--format", "json")[1])
        self.assertEqual((data["count"], data["seals"], data["library_as_of"]), (0, [], None))
        code, data, _ = run_cli_bytes("library", "register", "--format", "pdf")
        self.assertEqual(code, 0)
        read_pdf(self, data)
        self.assertFalse(self.home.exists())
