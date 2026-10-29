"""Synthetic REA-015 overlay framing tests; no commercial payloads."""
import hashlib
import json
import pathlib
import struct
import tempfile
import unittest
import zipfile

from tools.rea_overlay_inventory import (
    OverlayError, analyze_overlay, analyze_archive, digest, locations,
)


def synthetic_pe():
    data = bytearray(4096)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HH", data, 0x84, 0x14c, 1)
    struct.pack_into("<H", data, 0x94, 224)
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x10b)
    struct.pack_into("<I", data, opt + 60, 0x400)
    sec = opt + 224
    data[sec:sec+5] = b".text"
    struct.pack_into("<IIII", data, sec + 8, 0x400, 0x1000, 0x400, 0x400)
    return bytes(data)


def synthetic_overlay(body=b"A" * 1024):
    data = bytearray(96 + len(body) + 8)
    struct.pack_into("<III", data, 0, 96, 86, 0x301)
    data[12:16] = b"\x69\xcd\xab\x69"
    struct.pack_into("<I", data, 0x24, len(data))
    data[96:-8] = body
    data[-8:-4] = b"\x69\xcd\xab\x69"
    data[-4:] = b"\x77\x6b\x88\xff"
    return bytes(data)


class OverlayTests(unittest.TestCase):
    def test_frame_hypothesis_and_lengths(self):
        blob = synthetic_overlay()
        result = analyze_overlay(blob)
        self.assertTrue(result["frame_hypothesis_consistent"])
        self.assertFalse(result["format_identified"])
        self.assertFalse(result["driver_absence_proven"])
        self.assertFalse(result["code_recovered"])
        self.assertEqual(result["candidate_header_length"], 96)
        self.assertEqual(result["candidate_body_bytes"], 1024)
        self.assertEqual(result["leading_words"]["offset_0x24"], len(blob))
        self.assertEqual(result["magic_69abcd69_offsets"], ["0xc", "0x460"])

    def test_tampered_length_rejected_as_framed_not_as_unknown(self):
        data = bytearray(synthetic_overlay())
        struct.pack_into("<I", data, 0x24, 1)
        result = analyze_overlay(bytes(data))
        self.assertFalse(result["frame_hypothesis_consistent"])
        self.assertFalse(result["format_identified"])

    def test_tampered_magic_fails_frame(self):
        data = bytearray(synthetic_overlay())
        data[-8:-4] = b"NOPE"
        self.assertFalse(analyze_overlay(bytes(data))["frame_hypothesis_consistent"])

    def test_plain_mz_hits_are_not_executables(self):
        result = analyze_overlay(synthetic_overlay(b"MZ" * 60 + b"X" * 256))
        self.assertEqual(result["mz_marker_count"], 60)
        self.assertEqual(result["validated_embedded_pe_at_mz_offsets"], 0)
        self.assertEqual(result["strong_archive_magic_counts"]["zip_local_header"], 0)

    def test_valid_embedded_synthetic_pe_recorded_as_candidate_only(self):
        result = analyze_overlay(synthetic_overlay(b"prefix" + synthetic_pe()))
        self.assertEqual(result["mz_marker_count"], 1)
        self.assertEqual(result["validated_embedded_pe_at_mz_offsets"], 1)
        self.assertEqual(result["validated_embedded_pe_offsets"], ["0x66"])
        self.assertFalse(result["driver_found"])
        self.assertFalse(result["scope_closed"])

    def test_archive_signature_detection_does_not_claim_unpacking(self):
        result = analyze_overlay(synthetic_overlay(b"PK\x03\x04" * 5))
        self.assertEqual(result["strong_archive_magic_counts"]["zip_local_header"], 5)
        self.assertFalse(result["compression_or_encryption_identified"])

    def test_entropy_windows_nonempty(self):
        result = analyze_overlay(synthetic_overlay(b"A" * 2048))
        self.assertEqual([w["region"] for w in result["entropy_windows"]],
                         ["start", "middle", "end"])
        self.assertTrue(all(w["shannon_bits_per_byte"] == 0 for w in result["entropy_windows"]))

    def test_checksum_in_report(self):
        blob = synthetic_overlay()
        result = analyze_overlay(blob)
        self.assertEqual(result["overlay_sha256"], hashlib.sha256(blob).hexdigest())
        self.assertEqual(result["candidate_header_sha256"], digest(blob[:96]))

    def test_limits_fail_closed(self):
        with self.assertRaisesRegex(OverlayError, "bounded"):
            analyze_overlay(b"MZ")
        with self.assertRaisesRegex(OverlayError, "bounded"):
            analyze_overlay(b"x" * (16 * 1024 * 1024 + 1))
        with self.assertRaisesRegex(OverlayError, "Too many"):
            locations(b"MZ" * 20, b"MZ", max_hits=4)

    def test_invalid_original_archive_hash_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "test.zip"
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("Faronics_DFS/DFStd.exe", synthetic_pe())
            with self.assertRaisesRegex(OverlayError, "SHA-256 mismatch"):
                analyze_archive(path)

    def test_json_serializable_and_deterministic(self):
        blob = synthetic_overlay(b"abcdef" * 100)
        self.assertEqual(analyze_overlay(blob), analyze_overlay(blob))
        json.dumps(analyze_overlay(blob))


if __name__ == "__main__":
    unittest.main()
