"""Deterministic synthetic tests; NOT evidence of actual Win7 execution."""
import unittest

from tools.rea_runtime_probe_plan import build_plan, ProbePlanError


def report(rows=None):
    return {
        "schema": "rea-015-file-io-correlation-v1",
        "capture_id": "SYNTHETIC",
        "opaque_body_total_bytes": 10000,
        "overlay_file_offset_in_child_pe": 1984512,
        "read_event_checks": rows or [],
    }


class ProbePlanTests(unittest.TestCase):
    def test_both_hypotheses_and_offsets(self):
        plan = build_plan(report(), window=512, limit=5)
        child, overlay = plan["candidates_not_asserted_as_observed"]
        self.assertEqual(child["probes"][0]["file_offset"], 1984512)
        self.assertEqual(overlay["probes"][0]["file_offset"], 0)
        self.assertEqual(overlay["probes"][1]["file_offset"], 10096)
        self.assertEqual(plan["purpose"], "PLAN_ONLY_NOT_RUNTIME_PROOF")

    def test_verified_body_read_is_excluded_from_first_probe(self):
        row = {"kind": "overlay", "read_offset": 96, "read_bytes": 512,
               "read_bytes_match_expected_sha256": True}
        overlay = build_plan(report([row]), window=512, limit=5)["candidates_not_asserted_as_observed"][1]
        self.assertEqual(overlay["previously_matched_body_bytes"], 512)
        self.assertNotIn("body_first", [p["reason"] for p in overlay["probes"]])

    def test_overlapping_coverage_is_unique(self):
        rows = [{"kind": "overlay", "read_offset": a, "read_bytes": 200,
                 "read_bytes_match_expected_sha256": True} for a in (96, 196)]
        data = build_plan(report(rows), limit=3)
        self.assertEqual(data["candidates_not_asserted_as_observed"][1]["previously_matched_body_bytes"], 300)

    def test_mismatched_bytes_do_not_count(self):
        rows = [{"kind": "overlay", "read_offset": 96, "read_bytes": 200,
                 "read_bytes_match_expected_sha256": False}]
        self.assertEqual(build_plan(report(rows))["candidates_not_asserted_as_observed"][1]["previously_matched_body_bytes"], 0)

    def test_rejects_bool_as_integer_and_bad_schema(self):
        with self.assertRaises(ProbePlanError):
            build_plan(report(), window=True)
        with self.assertRaises(ProbePlanError):
            build_plan({"schema": "unknown", "read_event_checks": []})


if __name__ == "__main__":
    unittest.main()
