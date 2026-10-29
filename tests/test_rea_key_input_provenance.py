"""REA-015/K: fixture-only tests for byte-pinned caller and clock provenance."""
import hashlib
import json
import pathlib
import tempfile
import unittest
import zipfile

from tests.test_rea_structural import fixture_pe
from tools.rea_key_input_provenance import (
    ANCHORS, EDGES, ProvenanceError, analyze_archive, analyze_pe,
    static_conclusions, validate_edges,
)
from tools.rea_transform_state import select_words


class KeyInputProvenanceTests(unittest.TestCase):
    def test_static_callsite_passes_null_key(self):
        data = static_conclusions()
        self.assertEqual(data["source_key_at_this_callsite"], "NULL")
        self.assertIn("four zero DWORDs", data["null_key_effect"])
        self.assertFalse(data["actual_timestamp_and_words_observed"])

    def test_known_caller_path_is_argument_not_literal(self):
        data = static_conclusions()
        self.assertIn("caller_argument", data["source_path"])
        self.assertFalse(data["actual_path_value_observed"])
        self.assertFalse(data["link_to_CLOUD_INSTALLER_overlay_proven"])

    def test_alternate_source_uses_local_clock_but_format_unknown(self):
        data = static_conclusions()
        self.assertTrue(any("GetLocalTime" in x for x in data["fallback_preparation"]))
        self.assertTrue(any("0x0076AEE4" in x for x in data["fallback_preparation"]))
        self.assertFalse(data["format_of_time_derived_string_proven"])

    def test_zero_primary_words_select_fallback_when_available(self):
        fallback = (0x11111111, 0x22222222, 0x33333333, 0x44444444)
        self.assertEqual(select_words(fallback, (0, 0, 0, 0)), fallback)

    def test_nonzero_primary_words_preempt_fallback(self):
        fallback = (10, 11, 12, 13)
        primary = (1, 0, 0, 0)
        self.assertEqual(select_words(fallback, primary), primary)

    def test_rel32_call_edges_are_consistent(self):
        edges = validate_edges()
        self.assertEqual(len(edges), 11)
        self.assertIn({"site_va": "0x0076b6d2", "callee_va": "0x00900ea0"}, edges)
        self.assertIn({"site_va": "0x00467d45", "callee_va": "0x00750f1c"}, edges)
        self.assertEqual(len(ANCHORS), 39)

    def test_tampering_with_target_is_detected(self):
        modified = list(ANCHORS)
        idx = next(i for i, x in enumerate(modified)
                   if x[0] == "time_source_call")
        name, address, opcode, description = modified[idx]
        modified[idx] = name, address, "e8ca570000", description
        with self.assertRaisesRegex(ProvenanceError, "destination drift"):
            validate_edges(tuple(modified))

    def test_missing_direct_call_is_rejected(self):
        trimmed = tuple(a for a in ANCHORS if a[0] != "site_constructor_call")
        with self.assertRaisesRegex(ProvenanceError, "Missing callsite"):
            validate_edges(trimmed)

    def test_unpinned_main_binary_fails_closed(self):
        with self.assertRaisesRegex(ProvenanceError, "PE SHA-256 mismatch"):
            analyze_pe(fixture_pe())

    def test_unpinned_zip_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            file = pathlib.Path(directory) / "fixture.zip"
            with zipfile.ZipFile(str(file), "w") as archive:
                archive.writestr("Faronics_DFS/DFStd.exe", fixture_pe())
            with self.assertRaisesRegex(ProvenanceError, "ZIP SHA-256"):
                analyze_archive(file)

    def test_deterministic_and_json_serializable(self):
        self.assertEqual(static_conclusions(), static_conclusions())
        self.assertEqual(validate_edges(), validate_edges())
        self.assertEqual(len(ANCHORS), len(set(a[0] for a in ANCHORS)))
        self.assertEqual(len(ANCHORS), len(set(a[1] for a in ANCHORS)))
        json.dumps({"provenance": static_conclusions(), "edges": validate_edges()})


if __name__ == "__main__":
    unittest.main()
