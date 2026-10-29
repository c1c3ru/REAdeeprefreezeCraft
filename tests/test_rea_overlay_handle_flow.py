"""REA-015/I: synthetic-only tests for pinned handle/read/XOR call graph."""
import hashlib
import pathlib
import struct
import tempfile
import unittest
import zipfile

from tools.rea_overlay_handle_flow import (
    ANCHORS, FlowError, EXPECTED_IMPORTS, analyze_archive, analyze_pe_bytes,
    static_contract, validate_edges,
)
from tools.rea_overlay_reader_trace import inspect_anchors, ReaderEvidenceError
from tests.test_rea_structural import fixture_pe


class HandleFlowTests(unittest.TestCase):
    def test_recorded_handle_is_read_from_same_context_offset(self):
        c = static_contract()
        actions = [x["action"] for x in c["handle_provenance"]]
        self.assertIn("store returned HANDLE in [context+0x04]", actions)
        self.assertIn("load [context+0x04] as ReadFile hFile", actions)
        self.assertEqual(len(c["api_imports"]), 0)

    def test_filename_provenance_is_not_claimed_as_fixed_cloud_path(self):
        result = static_contract()
        self.assertIn("[owner+0xDC]", result["filename_origin"])
        self.assertIn("not yet confirmed", result["filename_origin"])
        self.assertFalse(result["link_to_embedded_CLOUD_INSTALLER_proven"])

    def test_after_header_is_not_assumed_full_body_coverage(self):
        result = static_contract()
        self.assertTrue(result["proven_xor_operation"])
        self.assertFalse(result["all_body_bytes_transformed_proven"])
        self.assertFalse(result["link_to_embedded_CLOUD_INSTALLER_proven"])
        self.assertFalse(result["semantically_equivalent"])
        self.assertFalse(result["scope_closed"])

    def test_block_buffer_and_flag_are_explicitly_traced(self):
        details = str(static_contract()["after_header"])
        for token in ("[owner+0x58]", "[owner+0x80]",
                      "[owner+0x60]", "0x7500F8"):
            self.assertIn(token, details)

    def test_xor_worker_is_conditionally_reachable_not_universal(self):
        result = static_contract()
        self.assertEqual(len(result["required_runtime_conditions"]), 3)
        self.assertIn("state-dependent", result["required_runtime_conditions"][-1])

    def test_exact_callgraph_rel32_targets(self):
        edges = validate_edges()
        self.assertGreaterEqual(len(edges), 12)
        pairs = {(item["instruction_va"], item["destination_va"])
                 for item in edges}
        self.assertIn(("0x007522cc", "0x00900d44"), pairs)
        self.assertIn(("0x007526ae", "0x009010c2"), pairs)
        self.assertIn(("0x0074fd9b", "0x007500f8"), pairs)
        self.assertIn(("0x0074f78b", "0x0074f87c"), pairs)

    def test_callgraph_rejects_modified_destination(self):
        modified = list(ANCHORS)
        index = next(i for i, t in enumerate(modified) if t[0] == "block_transform_call")
        name, va, code, label = modified[index]
        modified[index] = (name, va, "e859030000", label)
        with self.assertRaisesRegex(FlowError, "destination mismatch"):
            validate_edges(tuple(modified))

    def test_callgraph_rejects_wrong_instruction_type(self):
        modified = [item for item in ANCHORS if item[0] != "xor_worker_call"]
        with self.assertRaisesRegex(FlowError, "Missing call edge"):
            validate_edges(tuple(modified))

    def test_anchor_bytes_mismatch_fails_closed(self):
        fixture = bytearray(fixture_pe())
        # Use fixture's PE32 image base/ .text RVA (0x00401000 => file 0x400).
        struct.pack_into("<I", fixture, 0x98 + 28, 0x400000)
        fixture[0x404:0x406] = b"\x30\x06"
        spec = [("xor", 0x401004, "3006", "xor byte [esi],al")]
        self.assertEqual(len(inspect_anchors(bytes(fixture), spec)), 1)
        fixture[0x404] = 0x90
        with self.assertRaises(ReaderEvidenceError):
            inspect_anchors(bytes(fixture), spec)

    def test_analyze_rejects_foreign_pe_before_claiming_evidence(self):
        with self.assertRaisesRegex(FlowError, "SHA-256"):
            analyze_pe_bytes(fixture_pe())

    def test_analyze_archive_rejects_unpinned_archive(self):
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "synthetic.zip"
            with zipfile.ZipFile(path, "w") as zf:
                zf.writestr("Faronics_DFS/DFStd.exe", fixture_pe())
            with self.assertRaisesRegex(FlowError, "ZIP SHA-256"):
                analyze_archive(path)

    def test_imports_are_expected_exactly_and_both_win32_apis(self):
        pairs = [(x[0], x[1]) for x in EXPECTED_IMPORTS]
        self.assertEqual(pairs, [("KERNEL32.DLL", "CreateFileA"),
                                 ("KERNEL32.DLL", "ReadFile")])
        self.assertNotEqual(EXPECTED_IMPORTS[0][2], EXPECTED_IMPORTS[1][2])

    def test_static_contract_deterministic(self):
        self.assertEqual(static_contract(), static_contract())
        self.assertEqual(validate_edges(), validate_edges())
        self.assertEqual(len(ANCHORS), len(set(x[0] for x in ANCHORS)))
        self.assertEqual(len(ANCHORS), len(set(x[1] for x in ANCHORS)))


if __name__ == "__main__":
    unittest.main()
