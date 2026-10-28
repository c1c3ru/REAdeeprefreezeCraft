"""REA-015 inventory tests. Synthetic PE/ZIP data, never commercial bytes."""
import hashlib
import io
import json
import pathlib
import struct
import tempfile
import unittest
import zipfile

from tools.rea_recursive_inventory import (
    InventoryError, analyze_archive, classify, safe_path, to_markdown,
)
from tests.test_rea_structural import fixture_pe


def make_zip(path, entries):
    with zipfile.ZipFile(path, "w") as out:
        for name, body in entries:
            out.writestr(name, body)
    return path


def pe_with_embedded_pe():
    child = fixture_pe()
    parent = bytearray(fixture_pe())
    parent.extend(b"\0" * 8192)
    # Expand .rsrc raw mapping to include an entire synthetic PE.
    sec = 0x98 + 224 + 40 * 2
    struct.pack_into("<II", parent, sec + 8, 8192, 0x3000)
    struct.pack_into("<I", parent, sec + 16, 8192)
    struct.pack_into("<I", parent, 0xa20 + 4, len(child))
    parent[0xa80:0xa80 + len(child)] = child
    return bytes(parent)


class RecursiveInventoryTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = pathlib.Path(self.folder.name)
        self.archive = self.root / "sample.zip"

    def test_recursive_embedded_pe_and_resources(self):
        make_zip(self.archive, [("bin/parent.exe", pe_with_embedded_pe()),
                                 ("manual.txt", b"example")])
        result = analyze_archive(self.archive)
        self.assertEqual(result["top_level_archive_files"], 2)
        self.assertEqual(result["pe_count"], 2)
        self.assertEqual(result["class_counts"]["observed_pe"], 2)
        self.assertGreaterEqual(result["artifacts_discovered"], 4)
        self.assertFalse(result["scope_closed"])
        self.assertTrue(any("::10" in x["path"] for x in result["artifacts"]))
        json.dumps(result)

    def test_no_extension_required_to_identify_pe(self):
        make_zip(self.archive, [("no_extension", fixture_pe())])
        result = analyze_archive(self.archive)
        self.assertEqual(result["pe_count"], 1)
        self.assertEqual(result["artifacts"][0]["classification"], "observed_pe")

    def test_packer_markers_are_detected_not_unpacking(self):
        value = bytearray(fixture_pe())
        section = 0x98 + 224
        value[section:section + 8] = b"UPX0\0\0\0\0"
        make_zip(self.archive, [("packed.exe", value)])
        result = analyze_archive(self.archive)
        self.assertEqual(result["artifacts"][0]["packer_markers"], ["UPX0"])
        self.assertTrue(any(i["reason"] == "packed_pe_uncompressed_code_unavailable"
                            for i in result["unresolved"]))

    def test_zip_traversal_is_ignored_and_reported(self):
        make_zip(self.archive, [("../escape.exe", fixture_pe()),
                                 ("safe/file.txt", b"ok")])
        result = analyze_archive(self.archive)
        self.assertEqual(result["top_level_archive_files"], 1)
        self.assertEqual(len(result["warnings"]), 1)
        self.assertEqual(result["pe_count"], 0)

    def test_archive_hash_pin_rejects_wrong_sample(self):
        make_zip(self.archive, [("text.txt", b"abc")])
        with self.assertRaisesRegex(InventoryError, "SHA-256"):
            analyze_archive(self.archive, "a" * 64)

    def test_nested_zip_is_parsed_but_not_executed(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as inner:
            inner.writestr("app.bin", fixture_pe())
        make_zip(self.archive, [("inner.pkg", stream.getvalue())])
        result = analyze_archive(self.archive)
        self.assertEqual(result["pe_count"], 1)
        self.assertEqual(result["top_level_archive_files"], 1)

    def test_zip_bomb_declared_oversize_rejected(self):
        make_zip(self.archive, [("too-large.bin", b"x" * 128)])
        with zipfile.ZipFile(self.archive) as source:
            self.assertEqual(len(source.infolist()), 1)
        # Verify size limiting via patched module limit, not a large fixture.
        from unittest import mock
        with mock.patch("tools.rea_recursive_inventory.MAX_PE", 64):
            with self.assertRaisesRegex(InventoryError, "maximum size"):
                analyze_archive(self.archive)

    def test_malformed_pe_candidate_is_not_confirmed(self):
        make_zip(self.archive, [("bad.exe", b"MZ" + b"\0" * 20)])
        result = analyze_archive(self.archive)
        self.assertEqual(result["pe_count"], 0)
        self.assertEqual(result["artifacts"][0]["classification"], "invalid_pe_candidate")
        self.assertIn("pe_parse_failed", [x["reason"] for x in result["unresolved"]])

    def test_no_driver_confusion_between_strings_and_sys(self):
        raw = fixture_pe() + b"DeepFrz.sys"
        make_zip(self.archive, [("loader.exe", raw)])
        result = analyze_archive(self.archive)
        self.assertEqual(result["confirmed_driver_pe_paths"], [])
        self.assertEqual(result["artifacts"][0]["driver_filename_references"], ["DeepFrz.sys"])

    def test_supported_data_signatures(self):
        self.assertEqual(classify(b"SIB file hello", "item"), "sib_container_unknown")
        self.assertEqual(classify(b"\x89PNG\r\n\x1a\nhi", "pic"), "png_image")
        self.assertEqual(classify(b"TPF0header", "item"), "delphi_form_data")
        self.assertTrue(safe_path("safe/path.exe"))
        self.assertFalse(safe_path("../unsafe.exe"))
        self.assertFalse(safe_path("/absolute.exe"))

    def test_report_is_deterministic(self):
        make_zip(self.archive, [("bin/sample.exe", fixture_pe())])
        a = analyze_archive(self.archive)
        b = analyze_archive(self.archive)
        self.assertEqual(a, b)
        self.assertIn("REA-015", to_markdown(a))

    def test_exact_tsilang_header_is_data_not_unknown_executable(self):
        payload = (b"SIB file: TsiLang binary translation data\x00"
                   b"Form\x00PORTUGUESE\x00JAPANESE\x00")
        make_zip(self.archive, [("locale.dat", payload)])
        report = analyze_archive(self.archive)
        item = report["artifacts"][0]
        self.assertEqual(item["classification"], "tsilang_translation_data")
        self.assertFalse(item["format_evidence"]["records_parsed"])
        self.assertIn("PORTUGUESE", item["format_evidence"]["recognized_language_labels"])
        self.assertEqual(report["pe_count"], 0)
        self.assertEqual(report["unresolved"], [])

    def test_sib_prefix_is_insufficient_for_format_identification(self):
        make_zip(self.archive, [("maybe.sib", b"SIB file: unknown scheme")])
        report = analyze_archive(self.archive)
        self.assertEqual(report["artifacts"][0]["classification"], "sib_container_unknown")
        self.assertEqual(report["unresolved"][0]["reason"], "unknown_container_or_data_format")

    def test_upx_markers_do_not_claim_unpacked_code(self):
        value = bytearray(fixture_pe())
        section = 0x98 + 224
        value[section:section + 8] = b"UPX0\x00\x00\x00\x00"
        make_zip(self.archive, [("packed.exe", bytes(value))])
        report = analyze_archive(self.archive)
        meta = report["artifacts"][0]["packed_layout"]
        self.assertFalse(meta["unpacked_code_recovered"])
        self.assertEqual(meta["upx1_raw_bytes"], 0)

    def test_root_repository_tool_exists(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        self.assertTrue((root / "tools/rea_recursive_inventory.py").is_file())


if __name__ == "__main__":
    unittest.main()
