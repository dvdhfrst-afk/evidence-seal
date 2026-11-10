"""Every report format, for every verdict, with hostile names and purposes, and a PDF read back byte by byte."""

import contextlib
import csv
import hashlib
import io
import json
import re
import shutil
import subprocess
import xml.etree.ElementTree as ElementTree
from datetime import datetime, timezone
from unittest import mock

from evidence_seal import cli, console, manifest, pdf, report_formats, reporting, sealing, verification
from evidence_seal.errors import UsageError
from tests import forge
from tests.support import LOCAL, TempFolderTestCase, run_cli

NOW = datetime(2026, 11, 9, 12, 0, 0, tzinfo=timezone.utc)
CHINESE = chr(0x4E2D) + chr(0x6587)
CYRILLIC = chr(0x0444) + chr(0x0430) + chr(0x0439) + chr(0x043B)
REVERSE = chr(0x202E)
# Hostile on purpose: markup, a link, a formula, control characters, text that reverses, non-Latin text.
HOSTILE = (
    "<script>alert(1)</script> [click](http://example.test) **bold** _x_ `tick` $m$ :smile: @someone #1"
    ' =HYPERLINK("http://example.test") \x1b[2J\x00 line\nRESULT: VERIFIED '
    + REVERSE + "desrever " + CHINESE + " " + CYRILLIC
)
LONG = " long" * 2000
# Names a Windows folder can hold, which still mean something to Markdown, HTML, XML or a spreadsheet.
HOSTILE_NAMES = (
    "=1+2.txt",
    "@SUM(A1).txt",
    "-dash.txt",
    "+plus.txt",
    "[a](b) &amp; `x` $y$ _z_ #1 www.example.test.txt",
    CHINESE + " " + CYRILLIC + ".txt",
    "x" * 150 + ".txt",
)
MISSING_NAME = "<img src=x onerror=y>\n=cmd|' /C calc'!A0\x1b[31m" + REVERSE + ".txt"


def run_cli_bytes(*arguments):
    """Like run_cli, with a standard output that has a byte buffer, as a real pipe does."""
    raw = io.BytesIO()
    out = io.TextIOWrapper(raw, encoding="utf-8", newline="")
    err = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main([str(item) for item in arguments])
        except SystemExit as stop:
            code = stop.code
        out.flush()
    return code, raw.getvalue(), err.getvalue()


def outside_code(markdown_text):
    """What a Markdown reader would interpret: everything except fenced blocks and code spans."""
    kept = []
    fence = None
    for line in markdown_text.splitlines():
        stripped = line.strip()
        if fence is not None:
            if stripped == fence:
                fence = None
            continue
        if stripped.startswith("```"):
            fence = stripped
            continue
        index = 0
        while index < len(line):
            if line[index] != "`":
                kept.append(line[index])
                index += 1
                continue
            end = index
            while end < len(line) and line[end] == "`":
                end += 1
            run = line[index:end]
            found = re.compile(r"(?<!`)" + run + r"(?!`)").search(line, end)
            if found is None:
                kept.append(run)
                index = end
            else:
                index = found.end()
        kept.append("\n")
    return "".join(kept)


def _unescape_literal(data):
    out = bytearray()
    index = 0
    while index < len(data):
        byte = data[index]
        if byte == 0x5C:
            following = data[index + 1 : index + 4]
            if re.match(rb"[0-7]{3}", following):
                out.append(int(following, 8))
                index += 4
                continue
            out.append(data[index + 1])
            index += 2
            continue
        out.append(byte)
        index += 1
    return bytes(out)


def read_pdf(test, data):
    """Checks the file structure and returns (objects by number, page count, the text drawn, in order)."""
    test.assertTrue(data.startswith(b"%PDF-1.4\n"))
    test.assertTrue(data.endswith(b"%%EOF\n"))
    end = re.search(rb"startxref\n([0-9]+)\n%%EOF\n$", data)
    test.assertIsNotNone(end)
    start = int(end.group(1))
    header = re.match(rb"xref\n0 ([0-9]+)\n", data[start:])
    test.assertIsNotNone(header, "startxref must point at the cross-reference table")
    count = int(header.group(1))
    table_start = start + len(header.group(0))
    entries = [data[table_start + 20 * index : table_start + 20 * (index + 1)] for index in range(count)]
    test.assertEqual(entries[0], b"0000000000 65535 f\r\n")
    objects = {}
    for number, entry in enumerate(entries[1:], 1):
        test.assertRegex(entry, rb"^[0-9]{10} 00000 n\r\n$")
        offset = int(entry[:10])
        prefix = f"{number} 0 obj\n".encode("ascii")
        test.assertEqual(data[offset : offset + len(prefix)], prefix, f"object {number} is not at its offset")
        body_end = data.index(b"\nendobj\n", offset)
        objects[number] = data[offset + len(prefix) : body_end]
    trailer = data[table_start + 20 * count :]
    test.assertTrue(trailer.startswith(b"trailer\n<< /Size %d /Root 1 0 R /Info 3 0 R /ID [<" % count))
    test.assertEqual(objects[1], b"<< /Type /Catalog /Pages 2 0 R >>")
    pages = [body for body in objects.values() if body.startswith(b"<< /Type /Page ")]
    declared = re.search(rb"/Count ([0-9]+)", objects[2])
    test.assertEqual(int(declared.group(1)), len(pages))
    kids = re.findall(rb"([0-9]+) 0 R", re.search(rb"/Kids \[([^\]]*)\]", objects[2]).group(1))
    test.assertEqual(len(kids), len(pages))
    drawn = []
    for body in objects.values():
        if b"stream\n" not in body:
            continue
        length = int(re.match(rb"<< /Length ([0-9]+) >>\nstream\n", body).group(1))
        stream = body[body.index(b"stream\n") + 7 :]
        test.assertEqual(len(stream), length + len(b"\nendstream"), "the stream length must be exact")
        for literal in re.findall(rb"\(((?:\\.|[^\\)])*)\) Tj", stream[:length]):
            drawn.append(_unescape_literal(literal).decode("cp1252"))
    return objects, len(pages), drawn


class Seals(TempFolderTestCase):
    """A sealed sample folder with its token, and a hostile seal signed by a test authority."""

    def setUp(self):
        super().setUp()
        self.folder, self.manifest = self.copy_sample()
        self.manifest.with_suffix(".tsr").write_bytes((LOCAL / "token-rsa.tsr").read_bytes())
        self.ca = LOCAL / "root-rsa.crt"

    def outcome(self, ca=True, skip_files=False):
        options = verification.VerifyOptions(
            manifest_path=self.manifest, ca_files=[self.ca] if ca else [], skip_files=skip_files, now=NOW
        )
        return verification.verify(options)

    def context(self):
        return reporting.ReportContext(self.manifest.name, self.manifest.with_suffix(".tsr").name, self.ca.name)

    def render(self, name, outcome=None):
        return report_formats.by_name(name).render(outcome or self.outcome(), self.context())

    def three_outcomes(self):
        """VERIFIED, FAILED and INCOMPLETE, in that order."""
        verified = self.outcome()
        incomplete = self.outcome(ca=False)
        (self.folder / "notes.txt").write_bytes(b"changed")
        failed = self.outcome()
        self.assertEqual([verified.overall, failed.overall, incomplete.overall], ["VERIFIED", "FAILED", "INCOMPLETE"])
        return [("VERIFIED", verified), ("FAILED", failed), ("INCOMPLETE", incomplete)]

    def hostile_seal(self):
        """A seal of hostile names with a hostile purpose, and a token from an authority with a hostile name."""
        folder = self.temp / "hostile"
        rows = []
        for name in HOSTILE_NAMES:
            data = name.encode("utf-8")
            self.write(f"hostile/{name}", data)
            rows.append((name, hashlib.sha256(data).hexdigest(), len(data)))
        rows.append((MISSING_NAME, "0" * 64, 3))
        path = self.temp / "hostile-manifest.txt"
        path.write_bytes(manifest.render(rows, HOSTILE + LONG, "2026-01-01", "hostile"))
        authority = forge.Authority("<b>" + HOSTILE[:60], seed=91)
        path.with_suffix(".tsr").write_bytes(authority.token(path.read_bytes()))
        root = self.temp / "hostile-root.crt"
        root.write_bytes(authority.root)
        return folder, path, root


class Registry(Seals):
    def test_every_format_is_offered_and_has_its_own_suffix(self):
        names = [item.name for item in report_formats.REPORT_FORMATS]
        self.assertEqual(names, ["text", "html", "json", "markdown", "csv", "junit", "pdf"])
        self.assertEqual(len(set(report_formats.REPORT_SUFFIXES)), len(names))
        self.assertEqual(cli.build_parser().parse_args(["report", "m", "--format", "junit"]).format, "junit")
        code, _, err = run_cli("report", self.manifest, "--format", "docx")
        self.assertEqual(code, 2)
        self.assertIn("markdown", err)
        self.assertEqual([item.name for item in report_formats.REPORT_FORMATS if item.binary], ["pdf"])
        with self.assertRaises(ValueError):
            report_formats.by_name("docx")

    def test_default_paths_come_from_the_table(self):
        for item in report_formats.REPORT_FORMATS:
            path = report_formats.default_report_path(self.manifest, item.name)
            self.assertEqual(path, self.manifest.with_suffix(item.suffix))
            self.assertIn(path, sealing.companion_paths(self.manifest))
            self.assertNotIn(path, sealing.companion_paths(self.manifest, reports=False))

    def test_every_format_writes_beside_the_manifest(self):
        for item in report_formats.REPORT_FORMATS:
            with self.subTest(item.name):
                code, out, err = run_cli("report", self.manifest, "--ca", self.ca, "--format", item.name)
                self.assertEqual(code, 0, err)
                target = self.manifest.with_suffix(item.suffix)
                self.assertTrue(target.is_file())
                self.assertIn(f"Report: {target}", out)
                self.assertEqual(run_cli("report", self.manifest, "--ca", self.ca, "--format", item.name)[0], 1)

    def test_reports_inside_a_sealed_folder_are_its_own_files(self):
        inside = self.folder / "EVIDENCE.txt"
        self.assertEqual(run_cli("seal", self.folder, "--purpose", "p", "--out", inside)[0], 0)
        for item in report_formats.REPORT_FORMATS:
            self.assertIn(f"exclude: /EVIDENCE{item.suffix}", inside.read_text(encoding="utf-8"))
            inside.with_suffix(item.suffix).write_bytes(b"a report")
        code, text, _ = run_cli("verify", inside, "--json")
        data = json.loads(text)
        self.assertEqual(data["differences"]["added"], [])
        self.assertEqual(data["files"]["status"], "pass")
        self.assertEqual(code, 3)

    def test_reports_beside_a_hand_made_list_are_not_added_files(self):
        listed = self.folder / "LIST.txt"
        lines = []
        for path in sorted(self.folder.rglob("*")):
            if path.is_file():
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                lines.append(f"{digest}  {path.relative_to(self.folder).as_posix()}\n")
        listed.write_text("".join(lines), encoding="utf-8")
        for item in report_formats.REPORT_FORMATS:
            listed.with_suffix(item.suffix).write_bytes(b"a report")
        code, text, _ = run_cli("verify", listed, "--json")
        data = json.loads(text)
        self.assertEqual(data["differences"]["added"], [])
        self.assertIn("LIST.report.pdf", data["differences"]["own_files_not_compared"])

    def test_reports_never_land_on_the_files_a_check_needs(self):
        query = self.manifest.with_suffix(".tsq")
        query.write_bytes(b"request")
        root_copy = self.manifest.with_suffix(".ca.crt")
        root_copy.write_bytes(b"root")
        for target in (self.manifest, self.manifest.with_suffix(".tsr"), query, root_copy, self.ca):
            with self.subTest(target.name):
                before = target.read_bytes()
                code, _, err = run_cli("report", self.manifest, "--ca", self.ca, "--out", target, "--force")
                self.assertEqual(code, 2)
                self.assertIn("would overwrite", err)
                self.assertEqual(target.read_bytes(), before)

    def test_text_and_html_are_byte_for_byte_what_they_were(self):
        # Hashes of what the version before the table of formats wrote for these same fixed inputs.
        context = reporting.ReportContext("sample-manifest.txt", "sample-manifest.tsr", "root-rsa.crt")
        verified = self.outcome()
        expected = {
            "text": "24a9f5d62f4b73c735abe8b5d2f3aa0951472d10d194def7a67e8c3c349d2505",
            "html": "941e3020154a5c5d465ba9e8ea82078f58257437404cde7f4f20cd894ff7d9fc",
        }
        for name, digest in expected.items():
            self.assertEqual(hashlib.sha256(report_formats.by_name(name).render(verified, context)).hexdigest(), digest)
        (self.folder / "notes.txt").write_bytes(b"changed")
        failed = self.outcome(ca=False)
        # This one names where trusted roots come from, which the authority list changed, so its hash is newer.
        context = reporting.ReportContext("sample-manifest.txt", "sample-manifest.tsr", None)
        self.assertEqual(
            hashlib.sha256(report_formats.by_name("text").render(failed, context)).hexdigest(),
            "a7274b64c3024b2f2c5ef74ed66a652f38df3a9f2673092e2b94a605abffa561",
        )

    def test_the_same_input_gives_the_same_bytes_in_every_format(self):
        first = self.outcome()
        second = self.outcome()
        for item in report_formats.REPORT_FORMATS:
            self.assertEqual(item.render(first, self.context()), item.render(second, self.context()), item.name)


class Outcomes(Seals):
    def test_json_carries_the_verify_json_claims_and_commands(self):
        for overall, outcome in self.three_outcomes():
            with self.subTest(overall):
                data = json.loads(self.render("json", outcome).decode("ascii"))
                self.assertEqual(data["report_schema"], report_formats.REPORT_SCHEMA_VERSION)
                self.assertEqual(data["result"], overall)
                self.assertEqual(data["verification"], json.loads(json.dumps(outcome.to_dict())))
                self.assertIn("Manifest SHA-256", [claim["label"] for claim in data["claims"]])
                self.assertIn("Who wrote the files", " ".join(data["does_not_show"]))
                commands = [step["command"] for step in data["commands"]]
                self.assertTrue(any(command.startswith("openssl ts -verify") for command in commands))

    def test_markdown_says_what_the_text_report_says(self):
        for overall, outcome in self.three_outcomes():
            with self.subTest(overall):
                text = self.render("markdown", outcome).decode("utf-8")
                self.assertIn(f"**Result: {overall}**", text)
                word = "FAIL" if overall == "FAILED" else "PASS"
                self.assertIn(f"| Files match the manifest | {word} |", text)
                for phrase in ("## What this does not show", "Who wrote the files", "not legal advice", "proves nothing by itself"):
                    self.assertIn(phrase, text)
                self.assertEqual("Every check passed" in text, overall == "VERIFIED")
                self.assertIn("```\n   openssl ts -verify -data sample-manifest.txt", text)

    def test_csv_has_one_row_per_file_with_hashes_and_sizes(self):
        (self.folder / "notes.txt").write_bytes(b"changed")
        (self.folder / "data" / "blob.bin").rename(self.folder / "moved-blob.bin")
        (self.folder / "windows-endings.txt").unlink()
        (self.folder / "new.txt").write_bytes(b"new")
        data = self.render("csv")
        rows = list(csv.reader(io.StringIO(data.decode("utf-8"), newline="")))
        self.assertEqual(tuple(rows[0]), report_formats.FILE_COLUMNS)
        found = {row[0]: row for row in rows[1:]}
        self.assertEqual(found["notes.txt"][1:3], ["changed", ""])
        self.assertEqual(found["notes.txt"][6:], ["38", "7"])
        self.assertEqual(found["data/blob.bin"][1:3], ["moved", "moved-blob.bin"])
        self.assertEqual(found["data/blob.bin"][4], found["data/blob.bin"][5])
        self.assertEqual(found["windows-endings.txt"][1], "missing")
        self.assertEqual(found["new.txt"], ["new.txt", "added", "", "", "", "", "", "3"])
        self.assertEqual(found["data/name with spaces.txt"][1], "unchanged")
        self.assertNotIn("moved-blob.bin", found)
        self.assertEqual(len(rows), 6)
        self.assertTrue(data.endswith(b"\r\n"))
        self.assertNotIn(b"\n", data.replace(b"\r\n", b""))

    def test_csv_lists_files_even_when_they_were_not_compared(self):
        rows = list(csv.reader(io.StringIO(self.render("csv", self.outcome(skip_files=True)).decode("utf-8"))))
        self.assertEqual([row[1] for row in rows[1:]], ["not checked"] * 4)
        self.assertEqual(rows[1][3:5], ["SHA-256", "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880"])

    def test_csv_from_the_command_line(self):
        code, out, _ = run_cli("report", self.manifest, "--ca", self.ca, "--format", "csv", "--out", "-")
        self.assertEqual(code, 0)
        self.assertEqual(out.splitlines()[0], ",".join(report_formats.FILE_COLUMNS))

    def test_junit_has_one_test_per_check(self):
        for overall, outcome in self.three_outcomes():
            with self.subTest(overall):
                root = ElementTree.fromstring(self.render("junit", outcome))
                self.assertEqual(len(root.findall("./testsuite/testcase")), len(outcome.checks))
                failures = root.findall("./testsuite/testcase/failure")
                not_passed = [check for check in outcome.checks if check.status.value != "pass"]
                self.assertEqual(len(failures), len(not_passed))
                self.assertEqual(root.get("failures"), str(len(not_passed)))
                result = [item.get("value") for item in root.iter("property") if item.get("name") == "result"]
                self.assertEqual(result, [overall])
                if overall == "INCOMPLETE":
                    self.assertTrue(any(item.get("message").startswith("not checked:") for item in failures))
                    self.assertTrue(any(item.get("type") == "NOT CHECKED" for item in failures))

    def test_pdf_says_what_the_text_report_says(self):
        for overall, outcome in self.three_outcomes():
            with self.subTest(overall):
                objects, pages, drawn = read_pdf(self, self.render("pdf", outcome))
                text = " ".join(drawn)
                self.assertIn(f"RESULT: {overall}", text)
                for phrase in (
                    "What this does not show",
                    "Who wrote the files",
                    "not legal advice",
                    "Certificate revocation",
                    "proves nothing by itself",
                    f"Page 1 of {pages}",
                    "Files match the manifest",
                    "openssl ts -verify -data sample-manifest.txt",
                ):
                    self.assertIn(phrase, text)
                self.assertIn(b"/Title (Evidence seal report)", objects[3])
                self.assertIn(b"/CreationDate (D:20261109120000Z)", objects[3])
                self.assertNotIn("backslash code", text)

    def test_binary_output_to_standard_output(self):
        code, data, err = run_cli_bytes("report", self.manifest, "--ca", self.ca, "--format", "pdf", "--out", "-")
        self.assertEqual(code, 0, err)
        read_pdf(self, data)
        code, _, err = run_cli("report", self.manifest, "--ca", self.ca, "--format", "pdf", "--out", "-")
        self.assertEqual(code, 2)
        self.assertIn("binary", err)

    def test_a_terminal_never_gets_binary_or_raw_control_characters(self):
        class Terminal(io.StringIO):
            def isatty(self):
                return True

        screen = Terminal()
        with mock.patch("sys.stdout", screen):
            with self.assertRaises(UsageError):
                console.write_output(b"%PDF-1.4", binary=True)
            console.write_output("a\x1b[2Jb\r\nnext\n".encode("utf-8"))
        self.assertEqual(screen.getvalue(), "a\\x1b[2Jb\nnext\n")

    def test_text_report_through_a_pipe_is_exact(self):
        code, data, _ = run_cli_bytes("report", self.manifest, "--ca", self.ca, "--out", "-")
        self.assertEqual(code, 0)
        self.assertIn(b"\nRESULT: VERIFIED\n", data)


class HostileText(Seals):
    def setUp(self):
        super().setUp()
        self.hostile_folder, self.hostile, self.root = self.hostile_seal()

    def hostile_outcome(self):
        outcome = verification.verify(
            verification.VerifyOptions(manifest_path=self.hostile, folder=self.hostile_folder, ca_files=[self.root], now=NOW)
        )
        self.assertEqual(outcome.overall, "FAILED")
        self.assertEqual([check.title for check in outcome.token_checks if check.status.value != "pass"], [])
        return outcome, reporting.ReportContext(self.hostile.name, self.hostile.with_suffix(".tsr").name, self.root.name)

    def test_text_and_html_show_no_raw_control_characters(self):
        outcome, context = self.hostile_outcome()
        for name in ("text", "html"):
            data = report_formats.by_name(name).render(outcome, context).decode("utf-8")
            self.assertNotIn("\x1b", data)
            self.assertNotIn(REVERSE, data)
            self.assertFalse(any(line.startswith("RESULT: VERIFIED") for line in data.splitlines()))
        self.assertNotIn("<script>", report_formats.by_name("html").render(outcome, context).decode("utf-8"))

    def test_json_keeps_exact_values_in_plain_ascii(self):
        outcome, context = self.hostile_outcome()
        data = report_formats.by_name("json").render(outcome, context)
        data.decode("ascii")
        parsed = json.loads(data)
        self.assertEqual(parsed["verification"]["manifest"]["purpose"], HOSTILE + LONG)
        self.assertIn(MISSING_NAME, parsed["verification"]["differences"]["missing"])

    def test_markdown_cannot_be_made_to_hold_markup_links_or_html(self):
        outcome, context = self.hostile_outcome()
        text = report_formats.by_name("markdown").render(outcome, context).decode("utf-8")
        interpreted = outside_code(text)
        for danger in ("<", "[", "](", "://", "www.", "@", "&", "$", "\\", "_", ":smile:", "\x1b", REVERSE, "\x00"):
            self.assertNotIn(danger, interpreted, repr(danger))
        self.assertFalse(any(line.startswith("RESULT") for line in text.splitlines()))
        self.assertIn(CHINESE, text)
        self.assertIn("- Purpose stated by the sealer: `` <script>alert(1)</script> [click](http://example.test)", text)

    def test_markdown_tables_keep_their_columns(self):
        outcome, context = self.hostile_outcome()
        text = report_formats.by_name("markdown").render(outcome, context).decode("utf-8")
        for row in [line for line in text.splitlines() if line.startswith("| ")]:
            self.assertEqual(len(re.split(r"(?<!\\)\|", row)), 5, row)

    def test_csv_cells_cannot_run_as_formulas(self):
        outcome, context = self.hostile_outcome()
        data = report_formats.by_name("csv").render(outcome, context)
        rows = list(csv.reader(io.StringIO(data.decode("utf-8"), newline="")))
        for row in rows:
            for cell in row:
                self.assertFalse(cell.startswith(("=", "+", "-", "@", "\t", "\r", "\n")), cell)
                self.assertNotIn("\n", cell)
                self.assertNotIn("\x1b", cell)
        paths = [row[0] for row in rows[1:]]
        for guarded in ("'=1+2.txt", "'@SUM(A1).txt", "'-dash.txt", "'+plus.txt"):
            self.assertIn(guarded, paths)
        escaped = manifest.escape_text(MISSING_NAME)
        self.assertIn(escaped, paths)
        self.assertEqual(manifest.unescape_text(escaped), MISSING_NAME)
        self.assertIn(CHINESE + " " + CYRILLIC + ".txt", paths)
        self.assertIn("x" * 150 + ".txt", paths)

    def test_junit_is_valid_xml_whatever_the_names(self):
        outcome, context = self.hostile_outcome()
        context.manifest_file = MISSING_NAME + chr(0xFFFE) + chr(0xD800) + " & ]]>"
        data = report_formats.by_name("junit").render(outcome, context)
        root = ElementTree.fromstring(data)
        self.assertNotIn("\x1b", ElementTree.tostring(root, encoding="unicode"))
        self.assertIn("Failed: Files match the manifest", root.find("./testsuite/system-out").text)
        result = [item for item in root.iter("property") if item.get("name") == "result"][0]
        self.assertEqual(result.get("value"), "FAILED")
        shown = [item for item in root.iter("property") if item.get("name") == "manifest"][0].get("value")
        self.assertTrue(shown.startswith("<img src=x onerror=y>\\x0a=cmd|"), shown)
        self.assertTrue(shown.endswith("\\ufffe\\ud800 & ]]>"), shown)

    def test_pdf_escapes_what_its_fonts_cannot_show_and_says_so(self):
        outcome, context = self.hostile_outcome()
        data = report_formats.by_name("pdf").render(outcome, context)
        _, pages, drawn = read_pdf(self, data)
        text = " ".join(drawn)
        self.assertGreater(pages, 3)
        self.assertIn("\\u4e2d\\u6587", text)
        self.assertIn("\\x1b", text)
        self.assertIn("backslash code", text)
        self.assertIn(f"Page {pages} of {pages}", text)
        self.assertNotIn("\x1b", text)
        self.assertNotIn(CHINESE, text)
        self.assertEqual(data, report_formats.by_name("pdf").render(outcome, context))

    def test_every_format_from_the_command_line(self):
        for item in report_formats.REPORT_FORMATS:
            with self.subTest(item.name):
                target = self.temp / f"out{item.suffix}"
                code, _, err = run_cli(
                    "report", self.hostile, "--folder", self.hostile_folder, "--ca", self.root,
                    "--format", item.name, "--out", target,
                )
                self.assertEqual(code, 1, err)
                self.assertGreater(target.stat().st_size, 100)


class PdfWriter(TempFolderTestCase):
    def test_long_words_wrap_inside_the_margins(self):
        document = pdf.Document("t")
        width = document.text_width
        others = "".join(chr(code) for code in (0xE9, 0xC6, 0x20AC))
        for text in ("a" * 500, "W" * 300 + " short", CHINESE * 50, "mixed words " * 80, others * 90):
            for font in pdf.FONTS:
                for line in document.wrap(text, font, 9.5, width):
                    self.assertLessEqual(pdf.text_width(line, font, 9.5), width + 0.01)

    def test_winansi_keeps_what_it_can_and_escapes_the_rest(self):
        latin = "caf" + chr(0xE9) + " " + chr(0x20AC) + " 5"
        self.assertEqual(pdf.to_winansi(latin), (latin, False))
        self.assertEqual(pdf.to_winansi("a" + CHINESE[0] + "b"), ("a\\u4e2db", True))
        self.assertEqual(pdf.to_winansi(chr(0x1F600)), ("\\U0001f600", True))
        self.assertEqual(pdf.to_winansi("\x07" + chr(0x9B)), ("\\x07\\x9b", True))

    def test_a_long_table_row_carries_on_over_pages(self):
        document = pdf.Document("t")
        document.table([[("label", pdf.BOLD), ("word " * 4000, pdf.HELVETICA)]], (30, 70))
        _, pages, drawn = read_pdf(self, document.to_bytes())
        self.assertGreater(pages, 2)
        self.assertEqual(" ".join(drawn).count("word"), 4000)

    def test_information_with_other_scripts_is_unicode(self):
        document = pdf.Document("t", subject=CHINESE + " (x)", producer="p")
        objects, _, _ = read_pdf(self, document.to_bytes())
        self.assertIn(b"/Subject <FEFF4E2D65870020002800780029>", objects[3])

    def test_strings_with_parentheses_and_backslashes_stay_whole(self):
        document = pdf.Document("t")
        text = "a (b) c\\d " + chr(0xE9)
        document.paragraph(text)
        _, _, drawn = read_pdf(self, document.to_bytes())
        self.assertIn(text, drawn)

    def test_a_pdf_checker_accepts_it_when_one_is_installed(self):
        checker = shutil.which("qpdf")
        if checker is None:
            self.skipTest("qpdf is not on the path; read_pdf still checks the structure")
        document = pdf.Document("t", subject="s", producer="p", created=NOW)
        document.paragraph((CHINESE + " (x) ") * 400)
        path = self.write("checked.pdf", document.to_bytes())
        done = subprocess.run([checker, "--check", str(path)], capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
