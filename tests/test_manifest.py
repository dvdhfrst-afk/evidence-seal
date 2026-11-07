"""Writing and reading manifests, native and hand-made."""

import unittest

from evidence_seal import hashes, manifest

HASH_A = "a" * 64
HASH_B = "b" * 64


def native(rows, **overrides):
    options = dict(purpose="p", created="2026-01-15", folder_name="f")
    options.update(overrides)
    return manifest.render(rows, **options)


class Render(unittest.TestCase):
    def test_exact_format(self):
        data = native([("z.txt", HASH_A, 3), ("a/b.txt", HASH_B, 10)], excludes=[".git"], links=["l"], special=["s"])
        self.assertEqual(
            data.decode("ascii"),
            "evidence-seal manifest v1\n"
            "purpose: p\n"
            "created: 2026-01-15\n"
            "folder: f\n"
            "algorithm: sha256\n"
            "exclude: .git\n"
            "link: l\n"
            "special: s\n"
            "files: 2\n"
            "total-bytes: 13\n"
            "\n"
            f"{HASH_B}  10  a/b.txt\n"
            f"{HASH_A}  3  z.txt\n",
        )

    def test_order_does_not_depend_on_input_order(self):
        rows = [("b", HASH_A, 1), ("a", HASH_B, 1), ("C", HASH_A, 1), ("\u00e9", HASH_B, 1)]
        self.assertEqual(native(rows), native(list(reversed(rows))))

    def test_uses_only_line_feeds(self):
        self.assertNotIn(b"\r", native([("a", HASH_A, 1)]))

    def test_values_stay_on_one_line(self):
        data = native([("a\nb.txt", HASH_A, 1)], purpose="line one\nline two\rthree")
        parsed = manifest.parse(data)
        self.assertEqual(parsed.problems, [])
        self.assertEqual(parsed.purpose, "line one\nline two\rthree")
        self.assertEqual(parsed.entries[0].path, "a\nb.txt")


class Escaping(unittest.TestCase):
    def test_round_trip(self):
        for text in (
            "plain",
            "back\\slash",
            "new\nline",
            "tab\there",
            "\x01control\x7f",
            "caf\u00e9 \u4e2d\u6587",
            "double  space",
            " leading and trailing ",
            "\\n literal backslash n",
            "bad byte \udc80\udcff",
            "lone \ud800 surrogate",
        ):
            with self.subTest(text=text):
                escaped = manifest.escape_text(text)
                self.assertNotIn("\n", escaped)
                escaped.encode("utf-8")
                self.assertEqual(manifest.unescape_text(escaped), text)

    def test_awkward_paths_round_trip_through_a_manifest(self):
        rows = [(" space", HASH_A, 1), ("a  b", HASH_A, 2), ("x\\y", HASH_A, 3), ("bad\udc80", HASH_B, 4)]
        parsed = manifest.parse(native(rows))
        self.assertEqual(parsed.problems, [])
        self.assertEqual(sorted(entry.path for entry in parsed.entries), sorted(row[0] for row in rows))


class NativeParsing(unittest.TestCase):
    def setUp(self):
        self.data = native([("a.txt", HASH_A, 3), ("b.txt", HASH_B, 4)], excludes=["*.tmp"], links=["ln"])

    def test_good_manifest(self):
        parsed = manifest.parse(self.data)
        self.assertEqual(parsed.kind, manifest.NATIVE)
        self.assertEqual(parsed.problems, [])
        self.assertEqual(parsed.purpose, "p")
        self.assertEqual(parsed.created, "2026-01-15")
        self.assertEqual(parsed.folder_name, "f")
        self.assertEqual(parsed.excludes, ["*.tmp"])
        self.assertEqual(parsed.links, ["ln"])
        self.assertEqual(parsed.total_bytes, 7)
        self.assertEqual(parsed.entries[0].algorithm, hashes.SHA256)

    def assert_problem(self, data, phrase):
        parsed = manifest.parse(data)
        self.assertTrue(any(phrase in problem for problem in parsed.problems), parsed.problems)

    def test_removed_line_is_noticed(self):
        lines = self.data.split(b"\n")
        self.assert_problem(b"\n".join(line for line in lines if not line.endswith(b"b.txt")), "says 2 files")

    def test_truncated_file_is_noticed(self):
        self.assert_problem(self.data[:-20], "does not end with a line feed")

    def test_changed_size_is_noticed(self):
        self.assert_problem(self.data.replace(b"  3  a.txt", b"  9  a.txt"), "total size")

    def test_added_line_is_noticed(self):
        self.assert_problem(self.data + f"{HASH_A}  1  c.txt\n".encode("ascii"), "says 2 files")

    def test_reordered_or_repeated_lines_are_noticed(self):
        head, body = self.data.split(b"\n\n")
        lines = body.split(b"\n")[:2]
        self.assert_problem(head + b"\n\n" + lines[1] + b"\n" + lines[0] + b"\n", "out of order")
        self.assert_problem(head + b"\n\n" + lines[0] + b"\n" + lines[0] + b"\n", "out of order")

    def test_crlf_conversion_is_noticed(self):
        self.assert_problem(self.data.replace(b"\n", b"\r\n"), "line feeds")

    def test_bad_entry_line_is_noticed(self):
        self.assert_problem(self.data.replace(b"  3  a.txt", b" 3 a.txt"), "not a valid entry")

    def test_unknown_header_is_noticed(self):
        self.assert_problem(self.data.replace(b"folder: f", b"folder: f\ncolor: red"), "not understood")

    def test_other_algorithm_is_noticed(self):
        self.assert_problem(self.data.replace(b"algorithm: sha256", b"algorithm: md5"), "unknown algorithm")

    def test_missing_counts_are_noticed(self):
        self.assert_problem(self.data.replace(b"files: 2\n", b""), "file count")

    def test_invalid_utf8_is_noticed(self):
        self.assert_problem(self.data.replace(b"purpose: p", b"purpose: \xff"), "UTF-8")


class HandMadeParsing(unittest.TestCase):
    def test_sha256sum_formats(self):
        data = (
            f"{HASH_A}  plain.txt\n"
            f"{HASH_B} *binary mode.bin\n"
            f"{'C' * 64}  ./dot/slash.txt\n"
            f"{'d' * 64}  back\\slash.txt\n"
        ).encode("ascii")
        parsed = manifest.parse(data)
        self.assertEqual(parsed.kind, manifest.HAND_MADE)
        paths = [entry.path for entry in parsed.entries]
        self.assertEqual(paths, ["plain.txt", "binary mode.bin", "dot/slash.txt", "back/slash.txt"])
        self.assertEqual(parsed.entries[2].hexdigest, "c" * 64)

    def test_gnu_escaped_names(self):
        parsed = manifest.parse(f"\\{HASH_A}  new\\nline.txt\n".encode("ascii"))
        self.assertEqual(parsed.entries[0].path, "new\nline.txt")

    def test_bsd_and_openssl_formats(self):
        data = (
            f"SHA256 (a b.txt) = {HASH_A}\n"
            f"SHA2-256(c.txt)= {HASH_B}\n"
            f"SHA256(d.txt)= {HASH_A}\n"
        ).encode("ascii")
        parsed = manifest.parse(data)
        self.assertEqual([entry.path for entry in parsed.entries], ["a b.txt", "c.txt", "d.txt"])
        self.assertEqual(parsed.note_lines, 0)

    def test_date_and_size_columns(self):
        data = (
            f"{HASH_A}  2026-03-04T17:47:54Z       1234  folder/name with spaces.pdf\r\n"
            f"{HASH_B}  2026-03-04 17:47:54  55  second.txt\r\n"
        ).encode("ascii")
        parsed = manifest.parse(data)
        self.assertEqual(parsed.entries[0].path, "folder/name with spaces.pdf")
        self.assertEqual(parsed.entries[0].size, 1234)
        self.assertEqual(parsed.entries[1].path, "second.txt")
        self.assertEqual(parsed.entries[1].size, 55)

    def test_digits_in_a_name_are_not_a_size(self):
        parsed = manifest.parse(f"{HASH_A}  2026 report.pdf\n".encode("ascii"))
        self.assertEqual(parsed.entries[0].path, "2026 report.pdf")
        self.assertIsNone(parsed.entries[0].size)

    def test_free_text_lines_are_notes(self):
        data = f"My evidence file\n\nMade on a Tuesday\n{HASH_A}  a.txt\n# a comment\n".encode("ascii")
        parsed = manifest.parse(data)
        self.assertEqual(parsed.note_lines, 3)
        self.assertEqual(len(parsed.entries), 1)

    def test_hash_with_no_name_is_unreadable_rather_than_ignored(self):
        parsed = manifest.parse(f"{HASH_A}\n".encode("ascii"))
        self.assertEqual(parsed.unreadable_lines, 1)
        self.assertEqual(parsed.entries, [])

    def test_unknown_hash_length_is_unreadable(self):
        parsed = manifest.parse(f"{'a' * 50}  a.txt\n".encode("ascii"))
        self.assertEqual(parsed.unreadable_lines, 1)

    def test_contradictory_lines_are_a_problem(self):
        parsed = manifest.parse(f"{HASH_A}  a.txt\n{HASH_B}  a.txt\n".encode("ascii"))
        self.assertTrue(parsed.problems)

    def test_repeated_identical_line_is_fine(self):
        parsed = manifest.parse(f"{HASH_A}  a.txt\n{HASH_A}  a.txt\n".encode("ascii"))
        self.assertEqual(parsed.problems, [])
        self.assertEqual(len(parsed.entries), 1)

    def test_weak_hashes_are_counted(self):
        parsed = manifest.parse(f"{'a' * 40}  a.txt\n{'b' * 32}  b.txt\n".encode("ascii"))
        self.assertEqual(parsed.weak_entries, 2)
        self.assertEqual(parsed.entries[0].algorithm.name, "sha1")

    def test_other_strong_hashes(self):
        parsed = manifest.parse(f"{'a' * 128}  a.txt\n{'b' * 96}  b.txt\n".encode("ascii"))
        self.assertEqual([entry.algorithm.name for entry in parsed.entries], ["sha512", "sha384"])

    def test_byte_order_mark_and_latin1(self):
        parsed = manifest.parse(b"\xef\xbb\xbf" + f"{HASH_A}  a.txt\n".encode("ascii"))
        self.assertEqual(parsed.entries[0].path, "a.txt")
        parsed = manifest.parse(f"{HASH_A}  caf".encode("ascii") + b"\xe9.txt\n")
        self.assertEqual(parsed.entries[0].path, "caf\u00e9.txt")

    def test_empty_file_has_no_entries(self):
        self.assertEqual(manifest.parse(b"").entries, [])
        self.assertIsNone(manifest.parse(f"{HASH_A}  a.txt\n".encode("ascii")).total_bytes)


if __name__ == "__main__":
    unittest.main()
