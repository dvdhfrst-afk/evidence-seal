"""The strict multipart reader, against well-formed and hostile bodies."""

import random
import unittest

from evidence_seal.web.multipart import MAX_PARTS, MultipartError, boundary_of, parse
from tests.web_support import BOUNDARY
from tests.web_support import multipart as encode

EXPECTED = {"manifest": 1000, "token": 100, "folder": 50}
D = b"--" + BOUNDARY.encode()


def part(name, data, filename=None, extra=b""):
    disposition = f'Content-Disposition: form-data; name="{name}"'.encode()
    if filename is not None:
        disposition += f'; filename="{filename}"'.encode()
    return D + b"\r\n" + disposition + b"\r\n" + extra + b"\r\n" + data + b"\r\n"


def body(*parts):
    return b"".join(parts) + D + b"--\r\n"


class Accepts(unittest.TestCase):
    def test_fields_and_files(self):
        data, kind = encode([("folder", "C:\\work")], [("manifest", "m.txt", b"a\r\n--b\r\nc"), ("token", "t.tsr", b"\x00\xff")])
        parts = parse(data, boundary_of(kind), EXPECTED)
        self.assertEqual(parts["folder"].data, b"C:\\work")
        self.assertFalse(parts["folder"].is_file)
        self.assertEqual(parts["manifest"].data, b"a\r\n--b\r\nc")
        self.assertEqual(parts["manifest"].filename, "m.txt")
        self.assertEqual(parts["token"].content_type, "application/octet-stream")

    def test_an_empty_file_and_a_closing_boundary_without_a_line_break(self):
        parts = parse(body(part("token", b"", "t.tsr"))[:-2], BOUNDARY, EXPECTED)
        self.assertEqual(parts["token"].data, b"")

    def test_quoted_and_escaped_names(self):
        raw = D + b'\r\nContent-Disposition: form-data; name=token; filename="a\\"b.tsr"\r\n\r\nx\r\n' + D + b"--\r\n"
        self.assertEqual(parse(raw, BOUNDARY, EXPECTED)["token"].filename, 'a"b.tsr')

    def test_boundaries(self):
        self.assertEqual(boundary_of('multipart/form-data; boundary="a b"'), "a b")
        self.assertEqual(boundary_of("Multipart/Form-Data;boundary=xyz"), "xyz")


class Refuses(unittest.TestCase):
    def refused(self, raw, expected=EXPECTED, boundary=BOUNDARY):
        with self.assertRaises(MultipartError):
            parse(raw, boundary, expected)

    def test_bad_content_types(self):
        for value in (None, "", "text/plain", "multipart/mixed; boundary=x", "multipart/form-data", "multipart/form-data; boundary=",
                      "multipart/form-data; boundary=x; boundary=y", "multipart/form-data; boundary=" + "a" * 71,
                      'multipart/form-data; boundary="a "', "multipart/form-data; boundary=a\r\nx", "multipart/form-data; junk"):
            with self.subTest(value):
                with self.assertRaises(MultipartError):
                    boundary_of(value)

    def test_preamble_epilogue_and_missing_ends(self):
        good = body(part("token", b"x"))
        self.refused(b"preamble\r\n" + good)
        self.refused(good + b"epilogue")
        self.refused(good[: -len(b"--\r\n") - len(D)])
        self.refused(b"")
        self.refused(D + b"--\r\n")
        self.refused(part("token", b"x") + D + b"xx")

    def test_line_feeds_alone_are_not_enough(self):
        self.refused(body(part("token", b"x")).replace(b"\r\n", b"\n"))

    def test_headers(self):
        self.refused(body(part("token", b"x", extra=b"X-Other: 1\r\n")))
        self.refused(body(part("token", b"x", extra=b"Content-Type: a\r\nContent-Type: b\r\n")))
        self.refused(body(part("token", b"x", extra=b" folded\r\n")))
        self.refused(body(part("token", b"x", extra=b"Content-Type: \xff\xfe\r\n")))
        self.refused(body(part("token", b"x", extra=b"no colon\r\n")))
        self.refused(body(part("token", b"x", extra=b"Content-Type: " + b"a" * 2000 + b"\r\n")))
        self.refused(body(D + b"\r\nContent-Type: text/plain\r\n\r\nx\r\n"))
        self.refused(body(D + b"\r\nContent-Disposition: attachment; name=token\r\n\r\nx\r\n"))
        self.refused(body(D + b"\r\nContent-Disposition: form-data\r\n\r\nx\r\n"))
        self.refused(body(D + b'\r\nContent-Disposition: form-data; name="token"; name="folder"\r\n\r\nx\r\n'))
        self.refused(body(D + b'\r\nContent-Disposition: form-data; name="token"; filename*=utf-8\'\'x\r\n\r\nx\r\n'))
        self.refused(body(D + b'\r\nContent-Disposition: form-data; name="token" junk\r\n\r\nx\r\n'))
        self.refused(body(D + b"\r\n" + b"Content-Type: a\r\n" * 10 + b'Content-Disposition: form-data; name="token"\r\n\r\nx\r\n'))

    def test_fields(self):
        self.refused(body(part("token", b"x"), part("token", b"y")))
        self.refused(body(part("evil", b"x")))
        self.refused(body(part("token", b"x" * 101)))
        self.refused(body(*[part("token", b"x")] * (MAX_PARTS + 1)), {"token": 10})
        many = {f"f{number}": 10 for number in range(MAX_PARTS + 2)}
        self.refused(body(*[part(f"f{number}", b"x") for number in range(MAX_PARTS + 1)]), many)

    def test_headers_that_never_end(self):
        self.refused(D + b"\r\n" + b"Content-Type: a" + b"b" * 100000)

    def test_random_damage_is_always_a_plain_refusal(self):
        good = body(part("folder", b"C:\\work"), part("manifest", b"line one\r\nline two", "m.txt"), part("token", b"\x30\x03", "t.tsr"))
        chooser = random.Random(1234)
        for _ in range(1500):
            damaged = bytearray(good)
            for _ in range(chooser.randint(1, 4)):
                action = chooser.randrange(3)
                spot = chooser.randrange(len(damaged))
                if action == 0:
                    damaged[spot] = chooser.randrange(256)
                elif action == 1:
                    del damaged[spot : spot + chooser.randint(1, 20)]
                else:
                    damaged[spot:spot] = bytes(chooser.choice((b"\r\n", b"--", D, b'"', b";", b"\x00")))
            try:
                parts = parse(bytes(damaged), BOUNDARY, EXPECTED)
            except MultipartError:
                continue
            for name, found in parts.items():
                self.assertIn(name, EXPECTED)
                self.assertLessEqual(len(found.data), EXPECTED[name])


if __name__ == "__main__":
    unittest.main()
