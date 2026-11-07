"""The DER reader and writer."""

import unittest
from datetime import datetime, timezone

from evidence_seal import der
from evidence_seal.errors import DerError


class Reader(unittest.TestCase):
    def test_short_and_long_lengths(self):
        short = der.encode_octets(b"x" * 10)
        self.assertEqual(der.parse(short).content, b"x" * 10)
        long_form = der.encode_octets(b"x" * 300)
        self.assertEqual(long_form[:4], b"\x04\x82\x01\x2c")
        self.assertEqual(len(der.parse(long_form).content), 300)

    def test_non_minimal_length_is_refused_in_strict_mode(self):
        for data in (b"\x04\x81\x01x", b"\x04\x82\x00\x01x", b"\x04\x82\x00\x80" + b"x" * 128):
            with self.subTest(data=data[:4]):
                with self.assertRaises(DerError):
                    der.parse(data)
                self.assertEqual(der.parse(data, strict=False).tag, der.OCTET_STRING)

    def test_truncation_is_refused(self):
        whole = der.encode_seq(der.encode_int(5), der.encode_octets(b"abcdef"))
        for size in range(len(whole)):
            with self.subTest(size=size):
                with self.assertRaises(DerError):
                    der.parse(whole[:size])

    def test_trailing_bytes_are_refused(self):
        with self.assertRaises(DerError):
            der.parse(der.encode_int(1) + b"\x00")

    def test_child_may_not_run_past_its_parent(self):
        bad = b"\x30\x03\x04\x05abc" + b"de"
        with self.assertRaises(DerError):
            der.parse(bad)

    def test_length_field_lying_about_size(self):
        with self.assertRaises(DerError):
            der.parse(b"\x04\x88\xff\xff\xff\xff\xff\xff\xff\xffabc")
        with self.assertRaises(DerError):
            der.parse(b"\x04\xfe" + b"\x01" * 126)

    def test_deep_nesting_is_refused_without_a_crash(self):
        data = b""
        for _ in range(200):
            data = der.encode_seq(data)
        with self.assertRaises(DerError):
            der.parse(data)

    def test_indefinite_length_only_in_lenient_mode(self):
        data = b"\x30\x80" + der.encode_int(7) + b"\x00\x00"
        with self.assertRaises(DerError):
            der.parse(data)
        node = der.parse(data, strict=False)
        self.assertEqual(der.int_value(node.children[0]), 7)
        self.assertEqual(node.raw, data)

    def test_unterminated_indefinite_length_is_refused(self):
        with self.assertRaises(DerError):
            der.parse(b"\x30\x80" + der.encode_int(7), strict=False)

    def test_indefinite_length_cannot_escape_a_definite_parent(self):
        inner = b"\x30\x80" + der.encode_int(7)
        data = der.encode_tlv(0x30, inner) + b"\x00\x00"
        with self.assertRaises(DerError):
            der.parse(data, strict=False)

    def test_constructed_octet_string_only_in_lenient_mode(self):
        data = b"\x24\x08" + der.encode_octets(b"ab") + der.encode_octets(b"cd")
        with self.assertRaises(DerError):
            der.parse(data)
        self.assertEqual(der.octets(der.parse(data, strict=False)), b"abcd")

    def test_primitive_sequence_is_refused(self):
        with self.assertRaises(DerError):
            der.parse(b"\x10\x00")

    def test_constructed_integer_is_refused(self):
        with self.assertRaises(DerError):
            der.parse(b"\x22\x03\x02\x01\x05", strict=False)

    def test_long_form_tags(self):
        node = der.parse(b"\x9f\x81\x01\x01x")
        self.assertEqual(node.tag, 129)
        with self.assertRaises(DerError):
            der.parse(b"\x9f\x05\x01x")
        with self.assertRaises(DerError):
            der.parse(b"\x9f\x80\x81\x01\x01x")


class Values(unittest.TestCase):
    def test_integers_round_trip(self):
        for value in (0, 1, 127, 128, 255, 256, -1, -128, -129, 2 ** 64, 2 ** 521 - 1, -(2 ** 70)):
            with self.subTest(value=value):
                self.assertEqual(der.int_value(der.parse(der.encode_int(value))), value)

    def test_non_minimal_integers_are_refused(self):
        for data in (b"\x02\x02\x00\x01", b"\x02\x02\xff\x80", b"\x02\x00"):
            with self.assertRaises(DerError):
                der.int_value(der.parse(data))

    def test_oids_round_trip(self):
        for oid in ("1.2.840.113549.1.9.16.1.4", "2.5.29.37", "0.9.2342.19200300.100.1.25", "2.999.3"):
            with self.subTest(oid=oid):
                self.assertEqual(der.oid_value(der.parse(der.encode_oid(oid))), oid)

    def test_bad_oids_are_refused(self):
        for data in (b"\x06\x00", b"\x06\x01\x81", b"\x06\x02\x80\x01"):
            with self.assertRaises(DerError):
                der.oid_value(der.parse(data))

    def test_booleans(self):
        self.assertTrue(der.bool_value(der.parse(b"\x01\x01\xff")))
        self.assertFalse(der.bool_value(der.parse(b"\x01\x01\x00")))
        with self.assertRaises(DerError):
            der.bool_value(der.parse(b"\x01\x01\x01"))

    def test_bit_flags(self):
        self.assertEqual(der.bit_flags(der.parse(b"\x03\x02\x05\xa0")), {0, 2})
        self.assertEqual(der.bit_flags(der.parse(b"\x03\x01\x00")), set())
        with self.assertRaises(DerError):
            der.bit_flags(der.parse(b"\x03\x02\x08\xa0"))

    def test_bit_octets_need_whole_bytes(self):
        self.assertEqual(der.bit_octets(der.parse(der.encode_bits(b"ab"))), b"ab")
        with self.assertRaises(DerError):
            der.bit_octets(der.parse(b"\x03\x02\x01\xa0"))

    def test_times(self):
        utc = der.parse(der.encode_utc_time(datetime(2026, 8, 6, 17, 54, 32, tzinfo=timezone.utc)))
        self.assertEqual(der.time_value(utc), datetime(2026, 8, 6, 17, 54, 32, tzinfo=timezone.utc))
        old = der.parse(der.encode_tlv(der.UTC_TIME, b"500101000000Z"))
        self.assertEqual(der.time_value(old).year, 1950)
        fraction = der.parse(der.encode_tlv(der.GENERALIZED_TIME, b"20260806175432.25Z"))
        self.assertEqual(der.time_value(fraction).microsecond, 250000)

    def test_bad_times_are_refused(self):
        for data in (
            der.encode_tlv(der.GENERALIZED_TIME, b"20261332000000Z"),
            der.encode_tlv(der.GENERALIZED_TIME, b"20260806175432"),
            der.encode_tlv(der.GENERALIZED_TIME, b"20260806175432+0100"),
            der.encode_tlv(der.GENERALIZED_TIME, b"20260806175432.Z"),
            der.encode_tlv(der.UTC_TIME, b"2608061754Z"),
            der.encode_int(1),
        ):
            with self.subTest(data=data):
                with self.assertRaises(DerError):
                    der.time_value(der.parse(data))

    def test_text_types(self):
        self.assertEqual(der.text_value(der.parse(der.encode_utf8("caf\u00e9"))), "caf\u00e9")
        self.assertEqual(der.text_value(der.parse(der.encode_tlv(der.BMP_STRING, "ab".encode("utf-16-be")))), "ab")
        with self.assertRaises(DerError):
            der.text_value(der.parse(der.encode_tlv(der.UTF8_STRING, b"\xff")))
        with self.assertRaises(DerError):
            der.text_value(der.parse(der.encode_int(1)))

    def test_set_of_is_sorted(self):
        encoded = der.encode_set([der.encode_int(5), der.encode_int(1)])
        children = der.parse(encoded).children
        self.assertEqual([der.int_value(child) for child in children], [1, 5])


class CursorBehavior(unittest.TestCase):
    def test_walks_and_finishes(self):
        cursor = der.Cursor(der.parse(der.encode_seq(der.encode_int(1), der.encode_null())), "thing")
        self.assertEqual(der.int_value(cursor.universal(der.INTEGER, "first")), 1)
        self.assertIsNone(cursor.optional_universal(der.INTEGER))
        self.assertIsNotNone(cursor.optional_universal(der.NULL))
        cursor.finish()

    def test_reports_missing_wrong_and_extra_fields(self):
        cursor = der.Cursor(der.parse(der.encode_seq(der.encode_int(1))), "thing")
        with self.assertRaises(DerError):
            cursor.universal(der.OID, "first")
        cursor = der.Cursor(der.parse(der.encode_seq()), "thing")
        with self.assertRaises(DerError):
            cursor.next("first")
        cursor = der.Cursor(der.parse(der.encode_seq(der.encode_int(1))), "thing")
        with self.assertRaises(DerError):
            cursor.finish()
        with self.assertRaises(DerError):
            der.Cursor(der.parse(der.encode_int(1)), "thing")


if __name__ == "__main__":
    unittest.main()
