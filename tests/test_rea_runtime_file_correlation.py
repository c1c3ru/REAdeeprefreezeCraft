"""REA-015/N: synthetic-only tests of file-I/O observation correlation.

Tests intentionally use fake PE/overlay bytes and mock pinned hashes.
No original commercial payload is required or executed by CI.
"""
import copy
import hashlib
import pathlib
import tempfile
import unittest
import zipfile
from unittest import mock

from tests.test_rea_structural import fixture_pe
from tools.rea_runtime_file_correlation import (
    RuntimeTraceError, correlate, digest, extract_reference,
    interval_union_size, region, validate_trace,
)
from tools.rea_overlay_inventory import ROOT_SHA


def fixture():
    overlay = b"H" * 96 + b"ABCDEFGH12345678" + b"T" * 8
    child = b"P" * 128 + overlay
    trace = {
        "schema": "rea-015-file-io-observation-v1",
        "capture": {
            "platform": "windows7-sp1-x86",
            "original_pe_sha256": ROOT_SHA,
            "capture_id": "synthetic-run-1",
            "method": "synthetic unit test (not actual Windows)",
            "observed_at": "2026-10-29T16:00:00Z",
            "independently_signed": False,
        },
        "events": [
            {
                "seq": 1, "kind": "open", "api": "CreateFileA",
                "pid": 123, "handle": "0x30", "result": "success",
                "file_sha256": digest(child), "file_size": len(child),
                "path_redacted": "VM_LOCAL_PATH_1",
            },
            {
                "seq": 2, "kind": "read", "api": "ReadFile",
                "pid": 123, "handle": "0x30", "result": "success",
                "file_offset": 128, "bytes_returned": 96,
                "buffer_sha256": digest(overlay[:96]),
            },
            {
                "seq": 3, "kind": "read", "api": "ReadFile",
                "pid": 123, "handle": "0x30", "result": "success",
                "file_offset": 128+96, "bytes_returned": 8,
                "buffer_sha256": digest(overlay[96:104]),
            },
            {
                "seq": 4, "kind": "read", "api": "ReadFile",
                "pid": 123, "handle": "0x30", "result": "success",
                "file_offset": 128+96+8, "bytes_returned": 8,
                "buffer_sha256": digest(overlay[104:112]),
            },
            {
                "seq": 5, "kind": "close", "api": "CloseHandle",
                "pid": 123, "handle": "0x30",
            },
        ],
    }
    return trace, {"child_pe": child, "overlay": overlay,
                   "overlay_offset_in_pe": 128}


class RuntimeFileCorrelationTests(unittest.TestCase):
    def correlation(self, trace=None, resources=None):
        t, r = fixture()
        if trace is not None:
            t = trace
        if resources is not None:
            r = resources
        with mock.patch("tools.rea_runtime_file_correlation.CHILD_SHA",
                        digest(r["child_pe"])), mock.patch(
                        "tools.rea_runtime_file_correlation.OVERLAY_SHA",
                        digest(r["overlay"])):
            return correlate(t, r)

    def test_synthetic_child_pe_matches_header_body_and_trailer(self):
        r = self.correlation()
        self.assertEqual(r["reads_reported"], 3)
        self.assertEqual(r["reads_matching_expected_bytes"], 3)
        self.assertEqual([x["overlay_region"] for x in r["read_event_checks"]],
                         ["header", "body", "trailer"])
        self.assertEqual(r["matched_body_unique_bytes"], 8)
        self.assertEqual(r["opaque_body_total_bytes"], 16)
        self.assertFalse(r["file_handle_to_cloud_resource_proven"])
        self.assertFalse(r["certification_receipt_created"])
        self.assertFalse(r["original_executable_run_verified"])

    def test_synthetic_standalone_overlay_offset(self):
        t, r = fixture()
        overlay = r["overlay"]
        t["events"][0]["file_sha256"] = digest(overlay)
        t["events"][0]["file_size"] = len(overlay)
        for e in t["events"]:
            if e["kind"] == "read":
                e["file_offset"] -= 128
        out = self.correlation(t, r)
        self.assertTrue(out["opened_file_hash_consistent_with_reference"])
        self.assertEqual([x["kind"] for x in out["read_event_checks"]],
                         ["overlay"] * 3)
        self.assertEqual(out["reads_matching_expected_bytes"], 3)

    def test_wrong_file_sha_has_no_matching_events(self):
        t, r = fixture()
        t["events"][0]["file_sha256"] = "f" * 64
        out = self.correlation(t, r)
        self.assertEqual(out["reads_matching_expected_bytes"], 0)
        self.assertFalse(out["opened_file_hash_consistent_with_reference"])
        self.assertEqual(out["read_event_checks"][0]["kind"], "unidentified_file")

    def test_read_checksum_mismatch_is_reported_not_silently_matched(self):
        t, r = fixture()
        t["events"][2]["buffer_sha256"] = "f" * 64
        out = self.correlation(t, r)
        self.assertEqual(out["reads_matching_expected_bytes"], 2)
        self.assertFalse(out["read_event_checks"][1]["read_bytes_match_expected_sha256"])
        self.assertEqual(out["matched_body_unique_bytes"], 0)

    def test_reused_overlapping_reads_do_not_inflate_unique_body_coverage(self):
        t, r = fixture()
        duplicate = copy.deepcopy(t["events"][2])
        duplicate["seq"] = 4
        t["events"].insert(3, duplicate)
        for event in t["events"][4:]:
            event["seq"] += 1
        out = self.correlation(t, r)
        self.assertEqual(out["reads_matching_expected_bytes"], 4)
        self.assertEqual(out["matched_body_unique_bytes"], 8)

    def test_open_orphan_read_rejected(self):
        t, r = fixture()
        t["events"].pop(0)
        with self.assertRaisesRegex(RuntimeTraceError, "Read without"):
            self.correlation(t, r)

    def test_close_then_read_rejected(self):
        t, r = fixture()
        close = t["events"].pop(-1)
        close["seq"] = 2
        t["events"].insert(1, close)
        for event in t["events"][2:]:
            event["seq"] += 1
        with self.assertRaisesRegex(RuntimeTraceError, "Read without"):
            self.correlation(t, r)

    def test_open_duplicate_handle_rejected(self):
        t, r = fixture()
        new_open = copy.deepcopy(t["events"][0])
        new_open["seq"] = 2
        t["events"].insert(1, new_open)
        for event in t["events"][2:]:
            event["seq"] += 1
        with self.assertRaisesRegex(RuntimeTraceError, "reopened"):
            self.correlation(t, r)

    def test_events_must_be_strictly_monotonic(self):
        t, r = fixture()
        t["events"][1]["seq"] = 1
        with self.assertRaisesRegex(RuntimeTraceError, "increasing sequence"):
            self.correlation(t, r)

    def test_capture_cannot_self_assert_signature(self):
        t, r = fixture()
        t["capture"]["independently_signed"] = True
        with self.assertRaisesRegex(RuntimeTraceError, "cannot be self-asserted"):
            self.correlation(t, r)

    def test_wrong_pe_origin_rejected(self):
        t, r = fixture()
        t["capture"]["original_pe_sha256"] = "f" * 64
        with self.assertRaisesRegex(RuntimeTraceError, "does not pin original PE"):
            self.correlation(t, r)

    def test_out_of_bounds_read_rejected(self):
        t, r = fixture()
        t["events"][1]["file_offset"] = len(r["child_pe"])-40
        with self.assertRaisesRegex(RuntimeTraceError, "past observed file"):
            self.correlation(t, r)

    def test_negative_or_too_large_read_rejected(self):
        t, r = fixture()
        t["events"][1]["bytes_returned"] = -1
        with self.assertRaisesRegex(RuntimeTraceError, "read length"):
            self.correlation(t, r)
        t, r = fixture()
        t["events"][1]["bytes_returned"] = 1024*1024+1
        with self.assertRaisesRegex(RuntimeTraceError, "read length"):
            self.correlation(t, r)

    def test_invalid_handle_and_wrong_api_rejected(self):
        t, r = fixture()
        t["events"][1]["handle"] = "NOT_A_HANDLE"
        with self.assertRaisesRegex(RuntimeTraceError, "process-local handle"):
            self.correlation(t, r)
        t, r = fixture()
        t["events"][0]["api"] = "OpenFile"
        with self.assertRaisesRegex(RuntimeTraceError, "CreateFileA"):
            self.correlation(t, r)

    def test_distinct_pid_cannot_claim_another_process_handle(self):
        t, r = fixture()
        t["events"][1]["pid"] = 999
        with self.assertRaisesRegex(RuntimeTraceError, "Read without"):
            self.correlation(t, r)

    def test_union_handles_overlap_and_adjacency(self):
        self.assertEqual(interval_union_size([(5, 15), (0, 10),
                                              (20, 25), (15, 20)]), 25)
        self.assertEqual(interval_union_size([(1, 8), (2, 4)]), 7)

    def test_region_boundaries_and_crossings(self):
        self.assertEqual(region(0, 96, 120), "header")
        self.assertEqual(region(96, 16, 120), "body")
        self.assertEqual(region(112, 8, 120), "trailer")
        self.assertEqual(region(90, 12, 120), "crosses_regions")
        self.assertEqual(region(-1, 10, 120), "not_overlay")

    def test_reject_foreign_zip_before_resource_extraction(self):
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "fixture.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("Faronics_DFS/DFStd.exe", fixture_pe())
            with self.assertRaisesRegex(RuntimeTraceError, "ZIP SHA-256"):
                extract_reference(path)


if __name__ == "__main__":
    unittest.main()
