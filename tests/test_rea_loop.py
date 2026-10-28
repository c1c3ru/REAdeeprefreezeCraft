"""Fixtures sinteticas PE; CI nao precisa de executaveis comerciais."""
import os
import struct
import tempfile
import unittest
import zipfile

from tools.rea_loop import (
    analyze_pe, import_slots, find_import_thunks, ioctl_candidate,
    scan_package, markdown,
)
from tools.rea_structural import PEView
from tests.test_rea_structural import fixture_pe


def fixture_with_call():
    data = bytearray(fixture_pe())
    opt = 0x98
    struct.pack_into("<I", data, opt + 224 + 36, 0x60000020)  # .text executable
    struct.pack_into("<I", data, opt + 28, 0x400000)  # image base
    stub = 0x1100
    data[0x500:0x506] = b"\xff\x25" + struct.pack("<I", 0x402050)
    caller = 0x1180
    data[0x57a:0x580] = b"\x68" + struct.pack("<I", 0x002d1400) + b"\x57"
    data[0x580:0x585] = b"\xe8" + struct.pack("<i", stub - caller - 5)
    return bytes(data)


class LoopTests(unittest.TestCase):
    def test_import_slot(self):
        view = PEView(fixture_with_call())
        slots = import_slots(view)
        self.assertEqual(slots[0]["iat_va"], 0x402050)
        thunks, direct = find_import_thunks(view, slots)
        self.assertEqual(len(thunks), 1)
        self.assertEqual(thunks[0]["rva"], 0x1100)
        self.assertEqual(direct, [])

    def test_callsite_and_constant(self):
        result, _ = analyze_pe(fixture_with_call(), "mock.exe")
        self.assertEqual(len(result["call_candidates"]), 1)
        call = result["call_candidates"][0]
        self.assertEqual(call["rva"], 0x1180)
        self.assertEqual(call["ioctl_argument_hypothesis"]["candidate_code"], "0x002d1400")
        self.assertEqual(result["ioctl_literal_hypotheses"], ["0x002d1400"])
        self.assertEqual(result["iterations"][-1]["new_candidates"], 0)

    def test_unresolved_dynamic_argument(self):
        self.assertIsNone(ioctl_candidate(b"\x90" * 20, 14)["candidate_code"])

    def test_non_executable_sections_not_scanned(self):
        data = bytearray(fixture_with_call())
        struct.pack_into("<I", data, 0x98 + 224 + 36, 0)
        result, _ = analyze_pe(bytes(data), "mock.exe")
        self.assertEqual(result["call_candidates"], [])

    def test_zip_traversal_rejected_no_extraction(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "mock.zip")
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("mock.exe", fixture_with_call())
                archive.writestr("../bad.exe", fixture_with_call())
            first = scan_package(zip_path=path)
            self.assertEqual(first, scan_package(zip_path=path))
            self.assertEqual(len(first["items"]), 1)
            self.assertIn("0x1180", markdown(first))
            self.assertFalse(os.path.exists(os.path.join(folder, "mock.exe")))

    def test_only_metadata_exported(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "mock.exe")
            with open(path, "wb") as out:
                out.write(fixture_with_call())
            report = scan_package(pe_path=path)
            self.assertEqual(report["schema"], "rea-loop-v1")
            self.assertNotIn("payload", str(report))
            self.assertNotIn("binary", str(report))


if __name__ == "__main__":
    unittest.main()
