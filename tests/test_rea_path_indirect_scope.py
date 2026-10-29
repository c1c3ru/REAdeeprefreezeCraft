"""REA-015/M: synthetic guards for caller path provenance and bounded FF scan."""
import pathlib
import tempfile
import unittest
import zipfile

from tests.test_rea_structural import fixture_pe
from tools.rea_path_indirect_scope import (
    ANCHORS, EDGES, IMPORTS, WINDOWS, IndirectScopeError,
    analyze_archive, inspect_pe, raw_ff_patterns, validate_call_targets,
)


class BoundedPathTests(unittest.TestCase):
    def test_indirect_register_call(self):
        self.assertEqual(
            raw_ff_patterns(b"\x90\xff\xd0\x90", 0x401000),
            [{"va": "0x00401001", "kind": "call"}])

    def test_indirect_iat_call(self):
        self.assertEqual(
            raw_ff_patterns(b"\xff\x15\x98\x69\xa1\x00", 0x401000),
            [{"va": "0x00401000", "kind": "call"}])

    def test_indirect_jump(self):
        self.assertEqual(
            raw_ff_patterns(b"\xff\x25\x98\x69\xa1\x00", 0x401000),
            [{"va": "0x00401000", "kind": "jump"}])

    def test_ff_add_or_inc_not_misclassified(self):
        self.assertEqual(raw_ff_patterns(b"\xff\xc0\xff\x00", 0), [])

    def test_ff_without_modrm_not_misclassified(self):
        self.assertEqual(raw_ff_patterns(b"\xff", 0), [])

    def test_candidate_scan_does_not_claim_instruction_boundaries(self):
        payload = b"\xb8\xff\xd0\x00\x00"
        # Pair occurs inside an immediate constant: report only a candidate.
        self.assertEqual(raw_ff_patterns(payload, 0x401000),
                         [{"va": "0x00401001", "kind": "call"}])

    def test_exact_direct_target_edge_count(self):
        self.assertEqual(len(validate_call_targets()), 10)
        self.assertIn(
            {"source_va": "0x00467cc0", "destination_va": "0x00467cf8"},
            validate_call_targets())

    def test_all_anchor_ids_and_addresses_are_unique(self):
        self.assertEqual(len(ANCHORS), 39)
        self.assertEqual(len({row[0] for row in ANCHORS}), len(ANCHORS))
        self.assertEqual(len({row[1] for row in ANCHORS}), len(ANCHORS))

    def test_expected_api_imports_both_file_attribute_apis(self):
        names = [name for name, address in IMPORTS]
        self.assertEqual(names, [
            "GetFileAttributesA", "SetFileAttributesA", "CreateFileA", "ReadFile"])

    def test_disassembly_reviewed_windows_are_nonoverlapping(self):
        self.assertEqual(len(WINDOWS), 8)
        ordered = sorted(WINDOWS, key=lambda r: r[1])
        self.assertTrue(all(a[2] <= b[1] for a, b in zip(ordered, ordered[1:])))

    def test_unpinned_binary_rejected_before_anchors(self):
        with self.assertRaisesRegex(IndirectScopeError, "SHA-256"):
            inspect_pe(fixture_pe())

    def test_unpinned_archive_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "test.zip"
            with zipfile.ZipFile(path, "w") as file:
                file.writestr("Faronics_DFS/DFStd.exe", fixture_pe())
            with self.assertRaisesRegex(IndirectScopeError, "ZIP SHA-256"):
                analyze_archive(path)


if __name__ == "__main__":
    unittest.main()
