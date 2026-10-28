"""Synthetic-only regression tests for offset-based PE candidates (REA-015)."""
import hashlib
import io
import pathlib
import tempfile
import unittest
import zipfile

from tools.rea_embedded_pe_candidates import (
    CandidateError, analyze_archive, scan_nonzero_mz,
)
from tests.test_rea_structural import fixture_pe


class MZCandidateTests(unittest.TestCase):
    def test_literal_mz_is_not_an_executable(self):
        report = scan_nonzero_mz(b"prefix MZ not executable" + b"x" * 300)
        self.assertEqual(report["mz_nonzero_hits"], 1)
        self.assertEqual(report["invalid_mz_hits"], 1)
        self.assertEqual(report["valid_pe_candidates"], [])

    def test_embedded_pe_offset_is_reported_as_candidate(self):
        payload = b"header" + fixture_pe()
        report = scan_nonzero_mz(payload)
        self.assertEqual(report["mz_nonzero_hits"], 1)
        self.assertEqual(report["invalid_mz_hits"], 0)
        self.assertEqual(report["valid_pe_candidates"][0]["offset_in_resource"], 6)

    def test_mz_candidate_limit_fails_closed(self):
        payload = b"head" + b"MZ" * 20 + b"x" * 512
        with self.assertRaisesRegex(CandidateError, "cap"):
            scan_nonzero_mz(payload, max_hits=2)

    def test_empty_bytes_no_false_candidates(self):
        self.assertEqual(scan_nonzero_mz(b""), {
            "mz_nonzero_hits": 0, "valid_pe_candidates": [], "invalid_mz_hits": 0,
        })

    def test_archive_pins_sha_and_finds_resource_graph(self):
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "sample.zip"
            with zipfile.ZipFile(str(path), "w") as z:
                z.writestr("sample.exe", fixture_pe())
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            report = analyze_archive(path, member="sample.exe", expected_sha=digest)
            self.assertEqual(report["pe_modules_with_resource_trees"], 1)
            self.assertEqual(report["resource_leaves_visited"], 1)
            self.assertEqual(report["validated_nonzero_pe_candidates"], 0)
            self.assertFalse(report["scope_closed"])
            with self.assertRaisesRegex(CandidateError, "SHA-256"):
                analyze_archive(path, member="sample.exe", expected_sha="0" * 64)


if __name__ == "__main__":
    unittest.main()
