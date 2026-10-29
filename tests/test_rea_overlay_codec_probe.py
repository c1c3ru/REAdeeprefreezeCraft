"""REA-015/G — deterministic bounded codec probes with synthetic data."""
import hashlib
import json
import pathlib
import struct
import tempfile
import unittest
import zipfile
import zlib
from unittest import mock

from tools.rea_overlay_codec_probe import (
    CodecProbeError, analyze_archive, bounded_probe, inspect_overlay,
    plausible_zlib_header, scan_body,
)


def frame(body):
    o = bytearray(96 + len(body) + 8)
    struct.pack_into("<I", o, 0, 96)
    struct.pack_into("<I", o, 0x44, 96)
    struct.pack_into("<I", o, 0x48, 8928)
    struct.pack_into("<I", o, 0x4c, 8928)
    struct.pack_into("<I", o, 0x24, len(o))
    o[0xc:0x10] = b"\x69\xcd\xab\x69"
    o[96:-8] = body
    o[-8:-4] = b"\x69\xcd\xab\x69"
    return bytes(o)


class CodecProbeTests(unittest.TestCase):
    def test_zlib_header_checksum(self):
        self.assertTrue(plausible_zlib_header(0x78, 0x9c))
        self.assertTrue(plausible_zlib_header(0x78, 0xda))
        self.assertFalse(plausible_zlib_header(0x78, 0x9d))
        self.assertFalse(plausible_zlib_header(0x4d, 0x5a))

    def test_valid_zlib_stream_is_recognized(self):
        b = b"prefix" + zlib.compress(b"synthetic" * 50)
        r = scan_body(b)
        self.assertGreaterEqual(r["zlib_probe_results"]["complete"], 1)
        self.assertEqual(r["files_recovered"], 0)

    def test_invalid_candidate_does_not_claim_codec(self):
        r = scan_body(b"\x78\x9c" + b"\xff" * 40)
        self.assertEqual(r["zlib_rfc1950_header_candidates"], 1)
        self.assertEqual(r["zlib_probe_results"]["invalid"], 1)

    def test_valid_gzip_stream_is_recognized(self):
        enc = zlib.compressobj(wbits=31)
        payload = enc.compress(b"synthetic gzip") + enc.flush()
        r = scan_body(b"\xaa" * 3 + payload)
        self.assertEqual(r["gzip_header_candidates"], 1)
        self.assertEqual(r["gzip_probe_results"]["complete"], 1)

    def test_gzip_header_only_is_invalid(self):
        r = scan_body(b"\x1f\x8b\x08" + b"\xff" * 50)
        self.assertEqual(r["gzip_header_candidates"], 1)
        self.assertEqual(r["gzip_probe_results"]["invalid"], 1)

    def test_two_byte_zlib_header_is_incomplete(self):
        self.assertEqual(bounded_probe(b"\x78\x9c", 0, 15), "partial")

    def test_header_duplicate_fields_are_evidence(self):
        r = inspect_overlay(frame(b"fixture" * 40))
        self.assertTrue(r["header_length_fields_match"])
        self.assertTrue(r["paired_fields_match"])
        self.assertFalse(r["payload_format_identified"])
        self.assertFalse(r["coverage_complete"])

    def test_mismatched_pair_is_visible_not_silent(self):
        value = bytearray(frame(b"xyz" * 100))
        struct.pack_into("<I", value, 0x4c, 0)
        self.assertFalse(inspect_overlay(bytes(value))["paired_fields_match"])

    def test_invalid_frame_fails_closed(self):
        value = bytearray(frame(b"x" * 200))
        value[-8:-4] = b"NOPE"
        with self.assertRaisesRegex(CodecProbeError, "frame"):
            inspect_overlay(bytes(value))

    def test_length_field_tampering_fails_closed(self):
        value = bytearray(frame(b"x" * 200))
        struct.pack_into("<I", value, 0x24, 9)
        with self.assertRaisesRegex(CodecProbeError, "frame"):
            inspect_overlay(bytes(value))

    def test_empty_or_oversized_body_rejected(self):
        with self.assertRaises(CodecProbeError):
            scan_body(b"")
        with self.assertRaises(CodecProbeError):
            scan_body(b"x" * (16*1024*1024+1))

    def test_candidate_cap(self):
        with mock.patch("tools.rea_overlay_codec_probe.MAX_CANDIDATES", 1):
            with self.assertRaisesRegex(CodecProbeError, "Too many"):
                scan_body(b"\x78\x9c" * 4)

    def test_deterministic_report_hashes(self):
        b = frame(b"ABC" * 123)
        x = inspect_overlay(b)
        self.assertEqual(x, inspect_overlay(b))
        self.assertEqual(x["overlay_sha256"], hashlib.sha256(b).hexdigest())
        json.dumps(x)

    def test_wrong_archive_hash_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "other.zip"
            with zipfile.ZipFile(path, "w") as zf:
                zf.writestr("other.exe", b"MZ" * 200)
            with self.assertRaisesRegex(CodecProbeError, "SHA-256"):
                analyze_archive(path)


if __name__ == "__main__":
    unittest.main()
