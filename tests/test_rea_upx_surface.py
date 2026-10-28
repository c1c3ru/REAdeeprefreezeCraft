"""Synthetic UPX surface tests: no packed third-party executable required."""
import copy
import hashlib
import struct
import unittest

from tools.rea_upx_surface import PackedSurfaceError, analyze_pe
from tests.test_rea_structural import fixture_pe


def fixture_packed_pe():
    data = bytearray(fixture_pe())
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    opt = pe + 24
    sections = opt + 224
    upx0 = sections
    upx1 = sections + 40
    data[upx0:upx0 + 8] = b"UPX0\x00\x00\x00\x00"
    data[upx1:upx1 + 8] = b"UPX1\x00\x00\x00\x00"
    struct.pack_into("<I", data, upx0 + 16, 0)  # no physical bytes
    struct.pack_into("<I", data, upx0 + 36, 0xe0000080)
    struct.pack_into("<I", data, upx1 + 36, 0xe0000040)
    struct.pack_into("<I", data, opt + 16, 0x2100)
    data[0x3e0:0x3e4] = b"UPX!"
    return bytes(data)


class UPXSurfaceTests(unittest.TestCase):
    def test_entrypoint_maps_to_upx1_raw_region(self):
        raw = fixture_packed_pe()
        report = analyze_pe(raw)
        self.assertEqual(report["entrypoint_rva"], "0x2100")
        self.assertEqual(report["entrypoint_file_offset"], "0x700")
        self.assertEqual(report["upx0"]["raw_bytes"], 0)
        self.assertEqual(report["upx0"]["virtual_bytes"], 0x400)
        self.assertEqual(report["upx1"]["raw_bytes"], 0x400)
        self.assertEqual(report["upx_header_markers"], ["0x3e0"])
        self.assertEqual(report["packed_executable_on_disk_bytes"], 0x400)
        self.assertFalse(report["unpacked_code_recovered"])
        self.assertIsNone(report["code_coverage_percent"])

    def test_section_hash_is_provenance_not_unpacked_code(self):
        raw = fixture_packed_pe()
        expected = hashlib.sha256(raw[0x600:0xa00]).hexdigest()
        self.assertEqual(analyze_pe(raw)["upx1"]["raw_sha256"], expected)

    def test_reject_entrypoint_in_unbacked_virtual_upx0(self):
        raw = bytearray(fixture_packed_pe())
        struct.pack_into("<I", raw, 0x98 + 16, 0x1000)
        with self.assertRaisesRegex(PackedSurfaceError, "Entry RVA"):
            analyze_pe(bytes(raw))

    def test_reject_missing_packer_header_marker(self):
        raw = bytearray(fixture_packed_pe())
        raw[0x3e0:0x3e4] = b"XXXX"
        with self.assertRaisesRegex(PackedSurfaceError, "UPX!"):
            analyze_pe(bytes(raw))

    def test_reject_missing_zero_raw_upx0(self):
        raw = bytearray(fixture_packed_pe())
        struct.pack_into("<I", raw, 0x98 + 224 + 16, 0x200)
        with self.assertRaisesRegex(PackedSurfaceError, "zero-raw"):
            analyze_pe(bytes(raw))

    def test_reject_upx1_without_executable_flag(self):
        raw = bytearray(fixture_packed_pe())
        struct.pack_into("<I", raw, 0x98 + 224 + 40 + 36, 0x40000040)
        with self.assertRaisesRegex(PackedSurfaceError, "executable"):
            analyze_pe(bytes(raw))

    def test_reject_empty_or_missing_header(self):
        with self.assertRaises(ValueError):
            analyze_pe(b"not a PE")

    def test_deterministic_output(self):
        raw = fixture_packed_pe()
        self.assertEqual(analyze_pe(raw), analyze_pe(raw))


if __name__ == "__main__":
    unittest.main()
