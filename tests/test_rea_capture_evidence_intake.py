"""REA-015/S synthetic-only intake tests; no real VM or proprietary data."""
import copy
import hashlib
import json
import pathlib
import tempfile
import unittest

from tools.rea_capture_evidence_intake import (
    EvidenceIntakeError, main, verify_bundle,
)
from tools.rea_overlay_inventory import ROOT_SHA

CAPTURE = "SYNTHETIC-NOT-VM"
PLATFORM = "windows7-sp1-x86"


def create_fixture(root):
    data = {
        "file_io_trace": json.dumps({
            "schema": "rea-015-file-io-observation-v1",
            "capture": {"capture_id": CAPTURE, "platform": PLATFORM,
                        "original_pe_sha256": ROOT_SHA},
        }).encode("utf-8"),
        "xor_pairs": json.dumps({
            "schema": "rea-015-xor-paired-observation-v1",
            "capture_id": CAPTURE, "samples": [],
        }).encode("utf-8"),
        "observer_log": b"synthetic instrument event, not original execution",
        "vm_environment": b"synthetic VM configuration metadata",
    }
    artifacts = []
    for role, payload in data.items():
        name = role + ".dat"
        (root / name).write_bytes(payload)
        artifacts.append({
            "role": role, "relative_path": name,
            "size_bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        })
    return {
        "schema": "rea-015-win7-evidence-bundle-v1",
        "capture_id": CAPTURE,
        "platform": PLATFORM,
        "snapshot_id": "snapshot-synthetic",
        "instrumentation_method": "fixture",
        "original_pe_sha256": ROOT_SHA,
        "independently_reviewed": False,
        "network_isolated": True,
        "artifacts": artifacts,
    }


class CaptureEvidenceIntakeTests(unittest.TestCase):
    def test_synthetic_bundle_digests_match_but_are_not_authenticated(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_fixture(pathlib.Path(directory))
            report = verify_bundle(manifest, directory)
            self.assertEqual(report["artifact_count"], 4)
            self.assertTrue(report["local_manifest_digest_consistency"])
            self.assertFalse(report["original_executable_run_authenticated"])
            self.assertFalse(report["instrumentation_trusted"])
            self.assertFalse(report["independent_reviewer_signature_verified"])
            self.assertFalse(report["certification_receipt_created"])
            self.assertEqual(report["status"],
                             "LOCAL_DIGEST_INTEGRITY_ONLY_REVIEW_REQUIRED")
            self.assertNotIn(str(directory), json.dumps(report))
            self.assertNotIn("relative_path", json.dumps(report))

    def test_modified_private_file_fails_digest_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            manifest = create_fixture(root)
            (root / "observer_log.dat").write_bytes(b"different content")
            with self.assertRaises(EvidenceIntakeError):
                verify_bundle(manifest, root)

    def test_missing_and_duplicated_roles_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            original = create_fixture(root)
            modified = copy.deepcopy(original)
            modified["artifacts"].pop()
            with self.assertRaisesRegex(EvidenceIntakeError, "Missing|Mandatory"):
                verify_bundle(modified, root)
            modified = copy.deepcopy(original)
            modified["artifacts"][1]["role"] = modified["artifacts"][0]["role"]
            with self.assertRaisesRegex(EvidenceIntakeError, "repeated"):
                verify_bundle(modified, root)
            modified = copy.deepcopy(original)
            modified["artifacts"][1]["relative_path"] = modified["artifacts"][0]["relative_path"]
            with self.assertRaisesRegex(EvidenceIntakeError, "reused"):
                verify_bundle(modified, root)

    def test_reject_forged_provenance_claims(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            original = create_fixture(root)
            variants = (
                ("original_pe_sha256", "f" * 64),
                ("independently_reviewed", True),
                ("network_isolated", False),
                ("platform", "windows10"),
                ("capture_id", "../not-allowed"),
            )
            for field, value in variants:
                modified = copy.deepcopy(original)
                modified[field] = value
                with self.subTest(field=field), self.assertRaises(EvidenceIntakeError):
                    verify_bundle(modified, root)

    def test_reject_path_traversal_and_symlink_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "files"
            root.mkdir()
            manifest = create_fixture(root)
            modified = copy.deepcopy(manifest)
            modified["artifacts"][0]["relative_path"] = "../outside"
            with self.assertRaises(EvidenceIntakeError):
                verify_bundle(modified, root)
            outside = pathlib.Path(directory) / "secret.txt"
            outside.write_text("not in evidence root", encoding="utf-8")
            (root / "escape").symlink_to(outside)
            modified["artifacts"][0]["relative_path"] = "escape"
            with self.assertRaises(EvidenceIntakeError):
                verify_bundle(modified, root)

    def test_trace_and_pairs_must_match_capture_label(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            original = create_fixture(root)
            wrong = copy.deepcopy(original)
            wrong["capture_id"] = "ANOTHER-CAPTURE"
            with self.assertRaisesRegex(EvidenceIntakeError, "identity mismatch"):
                verify_bundle(wrong, root)
            trace = json.loads((root / "file_io_trace.dat").read_text())
            trace["capture"]["platform"] = "windows7-sp1-x64"
            payload = json.dumps(trace).encode()
            (root / "file_io_trace.dat").write_bytes(payload)
            original["artifacts"][0]["size_bytes"] = len(payload)
            original["artifacts"][0]["sha256"] = hashlib.sha256(payload).hexdigest()
            with self.assertRaisesRegex(EvidenceIntakeError, "identity mismatch"):
                verify_bundle(original, root)

    def test_malformed_pair_file_rejected_even_with_matching_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            manifest = create_fixture(root)
            payload = b"{bad json"
            (root / "xor_pairs.dat").write_bytes(payload)
            manifest["artifacts"][1]["size_bytes"] = len(payload)
            manifest["artifacts"][1]["sha256"] = hashlib.sha256(payload).hexdigest()
            with self.assertRaisesRegex(EvidenceIntakeError, "Invalid capture JSON"):
                verify_bundle(manifest, root)

    def test_wrong_size_and_boolean_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            manifest = create_fixture(root)
            modified = copy.deepcopy(manifest)
            modified["artifacts"][0]["size_bytes"] = True
            with self.assertRaises(EvidenceIntakeError):
                verify_bundle(modified, root)
            modified = copy.deepcopy(manifest)
            modified["artifacts"][0]["size_bytes"] += 1
            with self.assertRaises(EvidenceIntakeError):
                verify_bundle(modified, root)

    def test_cli_writes_metadata_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            manifest = create_fixture(root)
            source = root / "manifest.json"
            target = root / "report.json"
            source.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertEqual(main(["--manifest", str(source),
                                   "--evidence-dir", str(root),
                                   "--json", str(target)]), 0)
            report = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(report["artifact_count"], 4)
            self.assertNotIn(str(root), target.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
