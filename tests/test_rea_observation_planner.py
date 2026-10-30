"""REA-015/Q: deterministic synthetic-only observation-target planning."""
import copy
import json
import pathlib
import tempfile
import unittest

from tools.rea_observation_planner import (
    ObservationPlanError, available_segments, choose_windows,
    main, plan, validate_correlation,
)
from tools.rea_overlay_inventory import ZIP_SHA, CHILD_SHA, OVERLAY_SHA


def synthetic_report():
    return {
        "schema": "rea-015-file-io-correlation-v1",
        "status": "LOCAL_HASH_CONSISTENCY_ONLY_NOT_RUNTIME_PROOF",
        "source_zip_sha256": ZIP_SHA,
        "child_resource_sha256": CHILD_SHA,
        "overlay_sha256": OVERLAY_SHA,
        "capture_id": "SYNTHETIC-NOT-VM",
        "overlay_file_offset_in_child_pe": 512,
        "opaque_body_total_bytes": 40,
        "matched_body_unique_bytes": 0,
        "missing_body_unique_bytes": 40,
        "missing_body_ranges_overlay_relative": [[96, 136]],
        "claimed_trace_authentication": "unverified",
        "original_executable_run_verified": False,
        "file_handle_to_cloud_resource_proven": False,
        "transformation_applied_to_body_proven": False,
        "win7_semantic_equivalence_verified": False,
        "certification_receipt_created": False,
    }


class ObservationPlanningTests(unittest.TestCase):
    def test_full_missing_body_targets_are_bounded_and_nonoverlapping(self):
        result = plan(synthetic_report(), max_targets=4, window_bytes=5)
        self.assertEqual(result["status"], "PLANNING_ONLY_NOT_RUNTIME_PROOF")
        self.assertEqual(result["body_bytes_targeted_unique"], 20)
        self.assertEqual(result["missing_bytes_not_targeted"], 20)
        self.assertEqual(result["context_targets"][0]["overlay_range"], [0, 96])
        self.assertEqual(result["context_targets"][1]["overlay_range"], [136, 144])
        spans = [target["overlay_range"] for target in result["body_targets"]]
        self.assertEqual(len(spans), 4)
        for i, (lo, hi) in enumerate(spans):
            self.assertGreaterEqual(lo, 96)
            self.assertLessEqual(hi, 136)
            self.assertLessEqual(hi - lo, 5)
            self.assertEqual(
                result["body_targets"][i]["if_opened_child_pe_file_offsets"],
                [lo + 512, hi + 512])
            for other_lo, other_hi in spans[:i]:
                self.assertTrue(hi <= other_lo or other_hi <= lo)
        self.assertFalse(result["runtime_evidence_verified"])
        self.assertFalse(result["certification_receipt_created"])

    def test_disjoint_gaps_only_and_byte_arithmetic(self):
        report = synthetic_report()
        report["missing_body_ranges_overlay_relative"] = [[96, 102], [120, 136]]
        report["missing_body_unique_bytes"] = 22
        report["matched_body_unique_bytes"] = 18
        out = plan(report, max_targets=8, window_bytes=4)
        self.assertEqual(
            out["body_bytes_targeted_unique"] + out["missing_bytes_not_targeted"],
            22)
        for item in out["body_targets"]:
            lo, hi = item["overlay_range"]
            self.assertTrue(96 <= lo < hi <= 102 or 120 <= lo < hi <= 136)

    def test_complete_hash_consistency_does_not_certify(self):
        report = synthetic_report()
        report["missing_body_ranges_overlay_relative"] = []
        report["missing_body_unique_bytes"] = 0
        report["matched_body_unique_bytes"] = 40
        out = plan(report)
        self.assertEqual(out["body_targets"], [])
        self.assertEqual(out["missing_bytes_not_targeted"], 0)
        self.assertEqual(out["opaque_body_classification"], "unknown")
        self.assertFalse(out["semantic_equivalence_verified"])

    def test_reject_foreign_reference_and_unsupported_claims(self):
        for field, value in [
            ("overlay_sha256", "f" * 64),
            ("status", "CERTIFIED"),
            ("certification_receipt_created", True),
            ("original_executable_run_verified", True),
            ("claimed_trace_authentication", "verified"),
        ]:
            report = synthetic_report()
            report[field] = value
            with self.subTest(field=field), self.assertRaises(ObservationPlanError):
                validate_correlation(report)

    def test_reject_forged_counts_and_malformed_missing_intervals(self):
        variants = [
            ("missing_body_unique_bytes", 39),
            ("matched_body_unique_bytes", True),
            ("missing_body_ranges_overlay_relative", [[95, 136]]),
            ("missing_body_ranges_overlay_relative", [[96, 110], [108, 136]]),
            ("missing_body_ranges_overlay_relative", [[96, 110], [110, 136]]),
            ("missing_body_ranges_overlay_relative", [[136, 96]]),
            ("missing_body_ranges_overlay_relative", [[96, 136, 140]]),
        ]
        for field, value in variants:
            report = synthetic_report()
            report[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(ObservationPlanError):
                    validate_correlation(report)

    def test_target_parameter_bounds(self):
        for limit, window in [(0, 10), (33, 10), (2, 0),
                              (2, 1048577), (True, 10)]:
            with self.assertRaises(ObservationPlanError):
                plan(synthetic_report(), max_targets=limit, window_bytes=window)

    def test_available_segments_subtracts_prior_targets(self):
        self.assertEqual(available_segments(10, 30, [(12, 18), (20, 25)]),
                         [(10, 12), (18, 20), (25, 30)])
        self.assertEqual(available_segments(10, 20, [(0, 30)]), [])

    def test_planner_is_deterministic(self):
        report = synthetic_report()
        first = choose_windows([(96, 136)], 6, 4)
        self.assertEqual(first, choose_windows([(96, 136)], 6, 4))
        self.assertEqual(plan(report), plan(copy.deepcopy(report)))

    def test_cli_writes_only_sanitized_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            source = pathlib.Path(directory) / "correlation.json"
            target = pathlib.Path(directory) / "plan.json"
            source.write_text(json.dumps(synthetic_report()), encoding="utf-8")
            self.assertEqual(main(["--correlation", str(source), "--json", str(target),
                                   "--max-targets", "2", "--window-bytes", "3"]), 0)
            output = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(len(output["body_targets"]), 2)
            self.assertNotIn("bytes_raw", target.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
