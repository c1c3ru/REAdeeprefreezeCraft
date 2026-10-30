import unittest
from tools.rea_capture_readiness import audit, ReadinessError, SCHEMAS

def reports():
    return {
      "correlation": {"schema": SCHEMAS["correlation"], "capture_id": "synthetic",
        "opened_file_hash_consistent_with_reference": True,
        "reads_matching_expected_bytes": 1},
      "probes": {"schema": SCHEMAS["probes"], "source_capture_id": "synthetic"},
      "differences": {"schema": SCHEMAS["differences"], "pairs_processed": 1},
      "lineage": {"schema": SCHEMAS["lineage"], "direct_matches": 1},
    }

class ReadinessTests(unittest.TestCase):
    def test_complete_reports_not_certified(self):
        result = audit(reports())
        self.assertEqual(result["local_data_readiness"], "CONSISTENT_REPORT_SET_UNAUTHENTICATED")
        self.assertFalse(result["ready_for_certification"])

    def test_missing_reports(self):
        result = audit({"correlation": reports()["correlation"]})
        self.assertIn("missing_report:lineage", result["gaps"])

    def test_mismatched_capture(self):
        data = reports()
        data["probes"]["source_capture_id"] = "other"
        self.assertIn("probe_capture_id_mismatch", audit(data)["gaps"])

    def test_no_matching_read(self):
        data = reports()
        data["correlation"]["reads_matching_expected_bytes"] = 0
        self.assertIn("no_matching_read_buffers", audit(data)["gaps"])

    def test_no_direct_lineage(self):
        data = reports()
        data["lineage"]["direct_matches"] = 0
        self.assertIn("no_direct_lineage_matches", audit(data)["gaps"])

    def test_schema_rejected(self):
        data = reports()
        data["differences"]["schema"] = "invalid"
        self.assertIn("invalid_schema:differences", audit(data)["gaps"])

if __name__ == "__main__":
    unittest.main()
