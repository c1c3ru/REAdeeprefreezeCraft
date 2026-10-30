"""REA-015/S: synthetic-only tests for bounded, non-extracting output triage."""
import hashlib
import json
import pathlib
import tempfile
import unittest
from unittest import mock

from tools.rea_output_structure import (
    MAX_ARTIFACT, OutputTriageError, analyze_artifact, main,
    pe_header_candidate, scan_offsets,
)


def fixture_pe(arch="x86"):
    """Minimal synthetic PE header/section with no executable behavior."""
    size_opt = 0xe0 if arch == "x86" else 0xf0
    magic = 0x10b if arch == "x86" else 0x20b
    machine = 0x14c if arch == "x86" else 0x8664
    raw = bytearray(0x400)
    raw[0:2] = b"MZ"
    raw[0x3c:0x40] = (0x80).to_bytes(4, "little")
    raw[0x80:0x84] = b"PE\x00\x00"
    raw[0x84:0x86] = machine.to_bytes(2, "little")
    raw[0x86:0x88] = (1).to_bytes(2, "little")
    raw[0x94:0x96] = size_opt.to_bytes(2, "little")
    opt = 0x80 + 24
    raw[opt:opt + 2] = magic.to_bytes(2, "little")
    raw[opt + 56:opt + 60] = (0x2000).to_bytes(4, "little")
    raw[opt + 60:opt + 64] = (0x200).to_bytes(4, "little")
    sect = opt + size_opt
    raw[sect:sect + 5] = b".text"
    raw[sect + 16:sect + 20] = (0x200).to_bytes(4, "little")
    raw[sect + 20:sect + 24] = (0x200).to_bytes(4, "little")
    return bytes(raw)


def report(data):
    return analyze_artifact(
        data, hashlib.sha256(data).hexdigest(), "SYNTHETIC-NOT-WIN7")


class OutputStructureTests(unittest.TestCase):
    def test_synthetic_x86_pe_candidate_not_recovery(self):
        data = fixture_pe()
        out = report(data)
        self.assertEqual(out["artifact_prefix_hint"], "bounded_pe_candidate")
        self.assertEqual(out["signature_hit_counts"]["mz"], 1)
        self.assertEqual(len(out["pe_candidates"]), 1)
        candidate = out["pe_candidates"][0]
        self.assertEqual(candidate["architecture_hint"], "x86")
        self.assertEqual(candidate["candidate_span"], [0, len(data)])
        self.assertEqual(candidate["candidate_span_sha256"],
                         hashlib.sha256(data).hexdigest())
        self.assertFalse(candidate["complete_module_confirmed"])
        self.assertFalse(out["output_format_verified"])
        self.assertEqual(out["modules_recovered"], 0)
        self.assertFalse(out["certification_receipt_created"])
        self.assertNotIn("MZ", json.dumps(out))

    def test_synthetic_x64_pe_candidate(self):
        data = fixture_pe("x64")
        out = report(data)
        self.assertEqual(out["pe_candidates"][0]["architecture_hint"], "x64")

    def test_embedded_pe_with_false_magic_is_not_auto_extracted(self):
        data = b"abcMZdef" + fixture_pe() + b"endMZ"
        out = report(data)
        self.assertEqual(out["artifact_prefix_hint"], "unclassified")
        self.assertEqual(out["signature_hit_counts"]["mz"], 3)
        self.assertEqual(out["pe_candidates"][0]["offset"], 8)
        self.assertEqual(len(out["pe_candidates"]), 1)
        self.assertEqual(out["modules_recovered"], 0)

    def test_truncated_or_malformed_pe_is_rejected(self):
        for data in (b"MZ", b"MZ" + b"\x00" * 62, fixture_pe()[:300]):
            with self.subTest(length=len(data)):
                self.assertIsNone(pe_header_candidate(data, 0))
        raw = bytearray(fixture_pe())
        raw[0x3c:0x40] = (0xffff).to_bytes(4, "little")
        self.assertIsNone(pe_header_candidate(bytes(raw), 0))
        raw = bytearray(fixture_pe())
        raw[0x84:0x86] = (0xffff).to_bytes(2, "little")
        self.assertIsNone(pe_header_candidate(bytes(raw), 0))
        raw = bytearray(fixture_pe())
        section = 0x80 + 24 + 0xe0
        raw[section + 20:section + 24] = (0xffffffff).to_bytes(4, "little")
        self.assertIsNone(pe_header_candidate(bytes(raw), 0))

    def test_signature_detection_is_only_candidate(self):
        for magic, label in ((b"PK\x03\x04xxxx", "zip_local_header_prefix_only"),
                             (b"\x1f\x8b\x08xxx", "gzip_header_prefix_only"),
                             (b"7z\xbc\xaf\x27\x1cxxx", "7z_header_prefix_only"),
                             (b"MZxx", "mz_prefix_only")):
            with self.subTest(label=label):
                out = report(magic)
                self.assertEqual(out["artifact_prefix_hint"], label)
                self.assertFalse(out["output_format_verified"])

    def test_marker_count_uses_bounded_positions(self):
        count, positions = scan_offsets(b"MZ" * 100, b"MZ", 3)
        self.assertEqual(count, 100)
        self.assertEqual(positions, [0, 2, 4])
        out = report(b"MZ" * 100)
        self.assertTrue(out["pe_candidate_scan_capped"])
        self.assertEqual(out["pe_candidates"], [])

    def test_wrong_hash_and_capture_label_rejected(self):
        raw = fixture_pe()
        with self.assertRaisesRegex(OutputTriageError, "does not match"):
            analyze_artifact(raw, "0" * 64, "SYNTHETIC-NOT-WIN7")
        with self.assertRaisesRegex(OutputTriageError, "capture"):
            analyze_artifact(raw, hashlib.sha256(raw).hexdigest(), "../escape")
        with self.assertRaisesRegex(OutputTriageError, "Expected SHA"):
            analyze_artifact(raw, "not-a-sha", "SYNTHETIC-NOT-WIN7")

    def test_artifact_size_and_type_limits(self):
        with self.assertRaisesRegex(OutputTriageError, "size"):
            report(b"")
        with mock.patch("tools.rea_output_structure.MAX_ARTIFACT", 8):
            with self.assertRaisesRegex(OutputTriageError, "size"):
                report(b"012345678")

    def test_cli_writes_only_digests_and_metadata(self):
        raw = fixture_pe()
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            source = directory / "private-output.bin"
            reportfile = directory / "result.json"
            source.write_bytes(raw)
            self.assertEqual(main([
                "--artifact", str(source),
                "--expected-sha256", hashlib.sha256(raw).hexdigest(),
                "--capture-id", "SYNTHETIC-NOT-WIN7",
                "--json", str(reportfile)]), 0)
            result = json.loads(reportfile.read_text(encoding="utf-8"))
            self.assertEqual(result["artifact_size_bytes"], len(raw))
            self.assertNotIn(str(source), reportfile.read_text(encoding="utf-8"))
            self.assertNotIn("private-output.bin", reportfile.read_text(encoding="utf-8"))

    def test_cli_rejects_incorrect_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            input_path = pathlib.Path(directory) / "a.bin"
            input_path.write_bytes(fixture_pe())
            self.assertEqual(main(["--artifact", str(input_path),
                                   "--expected-sha256", "f" * 64,
                                   "--capture-id", "test"]), 1)


if __name__ == "__main__":
    unittest.main()
