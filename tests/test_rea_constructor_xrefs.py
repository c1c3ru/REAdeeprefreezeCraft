"""REA-015/L: synthetic tests for bounded direct rel32 xref enumeration."""
import hashlib
import json
import pathlib
import struct
import tempfile
import unittest
import zipfile

from tests.test_rea_structural import fixture_pe
from tools.rea_constructor_xrefs import (
    DIRECT_SITES, TARGETS, TIME_FORMAT, CallerAuditError,
    analyze_archive, analyze_pe, expected_address_sets, scan_relative_calls,
)


class ConstructorXrefTests(unittest.TestCase):
    def test_pinned_constructor_sites_eleven(self):
        self.assertEqual(len(DIRECT_SITES["constructor"]), 11)
        self.assertEqual(len(expected_address_sets()["constructor"]), 11)
        self.assertEqual(len({x[0] for x in DIRECT_SITES["constructor"]}), 11)

    def test_constructor_null_immediate_sources_are_unique(self):
        nulls = [item[1] for item in DIRECT_SITES["constructor"]]
        self.assertEqual(len(nulls), len(set(nulls)))
        self.assertTrue(all(item[2] in ("caller_argument", "converted_pointer")
                            for item in DIRECT_SITES["constructor"]))

    def test_all_targets_have_a_pinned_caller_count(self):
        count = {n: len(expected_address_sets()[n]) for n, va in TARGETS}
        self.assertEqual(count, {
            "constructor": 11, "time_fallback": 7,
            "four_word_hash": 4, "base_initializer": 2,
        })

    def test_synthetic_calls_two_targets_and_negative_offset(self):
        section = bytearray(b"\x90" * 100)
        start = 0x401000
        target_a = 0x401080
        target_b = 0x400ff0
        section[10] = 0xe8
        struct.pack_into("<i", section, 11, target_a - (start+10+5))
        section[50] = 0xe8
        struct.pack_into("<i", section, 51, target_b - (start+50+5))
        out = scan_relative_calls(bytes(section),
                                  {"A": target_a, "B": target_b},
                                  start, 0x400)
        self.assertEqual(out, {"A": [start+10], "B": [start+50]})

    def test_nonmatching_direct_calls_not_reported(self):
        section = b"\xe8\x00\x00\x00\x00\x90\x90"
        out = scan_relative_calls(section, {"different": 0xdeadbeef},
                                  0x401000, 0x400)
        self.assertEqual(out["different"], [])

    def test_false_positive_bytes_are_not_exhaustive_disassembly(self):
        section = b"\x90\x90\xe8\xfb\xff\xff\xff"
        out = scan_relative_calls(section, {"loop": 0x401002},
                                  0x401000, 0x400)
        self.assertEqual(out["loop"], [0x401002])
        # It is only an opcode-pattern match; a real decoder still needed.

    def test_empty_or_duplicate_targets_rejected(self):
        with self.assertRaisesRegex(CallerAuditError, "Missing call targets"):
            scan_relative_calls(b"\xe8\x00\x00\x00\x00", {}, 0, 0)
        with self.assertRaisesRegex(CallerAuditError, "Duplicate target"):
            scan_relative_calls(b"\xe8\x00\x00\x00\x00",
                                {"a": 5, "b": 5}, 0, 0)

    def test_scan_with_truncated_section_has_no_match(self):
        self.assertEqual(scan_relative_calls(b"\xe8\x01\x01",
                          {"one": 0}, 0x401000, 0x400)["one"], [])

    def test_time_format_template_is_known_but_output_unknown(self):
        self.assertEqual(TIME_FORMAT,
                         b"%.3s %.3s%3d %.2d:%.2d:%.2d %d%s")
        self.assertEqual(len(TIME_FORMAT), 32)

    def test_nonnull_hash_sites_are_not_assumed_loader_uses(self):
        sites = DIRECT_SITES["four_word_hash"]
        self.assertEqual(set(sites[:2]), {0x47b77b, 0x47b827})
        self.assertFalse(set(sites[:2]) & expected_address_sets()["constructor"])

    def test_hash_mismatch_fails_prior_to_any_opcodes(self):
        with self.assertRaisesRegex(CallerAuditError, "SHA-256"):
            analyze_pe(fixture_pe())

    def test_archive_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            file = pathlib.Path(directory) / "synthetic.zip"
            with zipfile.ZipFile(file, "w") as z:
                z.writestr("Faronics_DFS/DFStd.exe", fixture_pe())
            with self.assertRaisesRegex(CallerAuditError, "ZIP SHA-256"):
                analyze_archive(file)

    def test_scan_deterministic_and_json_compatible(self):
        data = b"\x90" * 10 + b"\xe8\x00\x00\x00\x00"
        got = scan_relative_calls(data, {"a": 0x40100f}, 0x401000, 0x400)
        self.assertEqual(got, scan_relative_calls(data, {"a": 0x40100f},
                                                  0x401000, 0x400))
        json.dumps(got)


if __name__=="__main__":
    unittest.main()
