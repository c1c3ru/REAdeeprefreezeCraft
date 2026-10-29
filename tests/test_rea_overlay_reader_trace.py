"""Synthetic evidence fixtures for x86 frame-reader correlations (REA-015/H)."""
import hashlib
import json
import pathlib
import struct
import tempfile
import unittest
import zipfile

from tools.rea_overlay_reader_trace import (
    ReaderEvidenceError, inspect_anchors, frame_correlations,
    analyze_archive, ANCHORS, resolve_iat_symbol,
)
from tests.test_rea_structural import fixture_pe


def frame_fixture():
    frame = bytearray(96 + 512 + 8)
    struct.pack_into("<I", frame, 0, 96)
    struct.pack_into("<I", frame, 8, 0x301)
    struct.pack_into("<I", frame, 12, 0x69abcd69)
    struct.pack_into("<I", frame, 0x24, len(frame))
    struct.pack_into("<I", frame, 0x44, 96)
    struct.pack_into("<I", frame, 0x48, 8928)
    struct.pack_into("<I", frame, 0x4c, 8928)
    frame[-8:-4] = b"\x69\xcd\xab\x69"
    return bytes(frame)


def imagebase_fixture():
    raw = bytearray(fixture_pe())
    struct.pack_into("<I", raw, 0x98 + 28, 0x400000)
    return raw


class FrameReaderTraceTests(unittest.TestCase):
    def test_header_and_trailer_correlation(self):
        r = frame_correlations(frame_fixture())
        self.assertEqual(r["header_span_bytes"], 96)
        self.assertEqual(r["trailer_span_bytes"], 8)
        self.assertEqual(r["dword_values"]["0xc"], 0x69abcd69)
        self.assertEqual(r["observed_structure_base"], "[EBX+0x10]")
        self.assertEqual(len(r["observed_header_correlations"]), 5)
        self.assertEqual(r["matched_format_ownership"], "candidate_not_proven")

    def test_bad_magic_fails_closed(self):
        raw = bytearray(frame_fixture())
        raw[12:16] = b"WRNG"
        with self.assertRaisesRegex(ReaderEvidenceError, "changed"):
            frame_correlations(bytes(raw))

    def test_wrong_length_fails_closed(self):
        raw = bytearray(frame_fixture())
        struct.pack_into("<I", raw, 0x24, 1)
        with self.assertRaises(ReaderEvidenceError):
            frame_correlations(bytes(raw))

    def test_wrong_trailer_magic_fails(self):
        raw = bytearray(frame_fixture())
        raw[-8:-4] = b"ABCD"
        with self.assertRaises(ReaderEvidenceError):
            frame_correlations(bytes(raw))

    def test_valid_synthetic_instruction_inside_text(self):
        fixture = imagebase_fixture()
        fixture[0x405:0x408] = bytes.fromhex("8d7b10")
        report = inspect_anchors(bytes(fixture), [
            ("synthetic_lea", 0x401005, "8d7b10", "lea edi,[ebx+0x10]")
        ])
        self.assertEqual(report[0]["va"], "0x00401005")
        self.assertEqual(report[0]["file_offset"], "0x405")

    def test_bad_instruction_bytes_rejected(self):
        fixture = imagebase_fixture()
        fixture[0x405:0x408] = bytes.fromhex("8d7b10")
        with self.assertRaisesRegex(ReaderEvidenceError, "mismatch"):
            inspect_anchors(bytes(fixture), [("synthetic", 0x401005, "909090", "wrong")])

    def test_wrong_address_rejected(self):
        fixture = imagebase_fixture()
        fixture[0x405:0x408] = bytes.fromhex("8d7b10")
        with self.assertRaises(ReaderEvidenceError):
            inspect_anchors(bytes(fixture), [("synthetic", 0x401006, "8d7b10", "bad address")])

    def test_duplicate_instruction_anchor_rejected(self):
        raw = bytes(imagebase_fixture())
        with self.assertRaisesRegex(ReaderEvidenceError, "Duplicate"):
            inspect_anchors(raw, [
                ("same", 0x401005, "0000", "test"),
                ("same", 0x401006, "0000", "test"),
            ])

    def test_source_checksum_mismatch_rejected_first(self):
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "sample.zip"
            with zipfile.ZipFile(str(path), "w") as z:
                z.writestr("test.exe", fixture_pe())
            with self.assertRaisesRegex(ReaderEvidenceError, "SHA-256"):
                analyze_archive(path)

    def test_anchor_evidence_is_readonly_and_deterministic(self):
        fixture = imagebase_fixture()
        fixture[0x408:0x40a] = bytes.fromhex("6a60")
        specs = [("push", 0x401008, "6a60", "push 0x60")]
        a = inspect_anchors(bytes(fixture), specs)
        self.assertEqual(a, inspect_anchors(bytes(fixture), specs))
        self.assertEqual(a[0]["instruction_bytes_sha256"],
                         hashlib.sha256(bytes.fromhex("6a60")).hexdigest())
        json.dumps(a)

    def test_import_resolution_of_synthetic_iat_slot(self):
        data = bytes(imagebase_fixture())
        symbol = resolve_iat_symbol(data, 0x402050)
        self.assertEqual(symbol["dll"], "KERNEL32.DLL")
        self.assertEqual(symbol["symbol"], "DeviceIoControl")
        self.assertEqual(symbol["iat_va"], "0x00402050")

    def test_unknown_iat_slot_fails_closed(self):
        data = bytes(imagebase_fixture())
        with self.assertRaises(ReaderEvidenceError):
            resolve_iat_symbol(data, 0x402044)

    def test_pinned_evidence_contains_both_checks_and_writer(self):
        names = [item[0] for item in ANCHORS]
        self.assertIn("header_magic_compare", names)
        self.assertIn("trailer_magic_compare", names)
        self.assertIn("header_magic_init", names)
        self.assertIn("header_read_call", names)
        self.assertIn("trailer_read_call", names)
        self.assertIn("readfile_import_call", names)
        self.assertIn("readfile_import_jump", names)


if __name__ == "__main__":
    unittest.main()
