"""Synthetic certification gate tests; no commercial executables or keys in Git."""
import hashlib
import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from tools.rea_certification import (
    CLAIMS, CertificateError, assess, check_receipt, render, safe_path,
    sha_file, verify_claim_policy,
)


def policy_pending():
    return {"schema": "rea-certification-v1", "as_of": "2026-10-29",
            "claims": [{"id": k, "status": "pending", "receipt": None,
                        "receipt_sha256": None, "signature": None,
                        "signer": None} for k in CLAIMS]}


class CertificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = pathlib.Path(self.temp.name)
        self.root = self.base / "repo"
        (self.root / "docs/coverage").mkdir(parents=True)
        (self.root / "docs/progress").mkdir(parents=True)
        self.scope = {"as_of": "2026-10-29", "source_archive": {
            "sha256": "a" * 64}}
        (self.root / "docs/coverage/scope.json").write_text(
            json.dumps(self.scope), encoding="utf-8")
        (self.root / "docs/progress/tasks.json").write_text(json.dumps({
            "as_of": "2026-10-29", "tasks": []}), encoding="utf-8")

    def fake_assess(self, policy, complete=False, trust=None):
        return self._mocked_assess(policy, complete, trust)

    def _mocked_assess(self, policy, complete, trust):
        fake_tasks = {"REA-001": {"status": "done" if complete else "todo"}}
        with mock.patch("tools.rea_certification.measure", return_value={
                "full_coverage_certified": bool(complete)}), mock.patch(
                    "tools.rea_certification.validate_tasks",
                    return_value=fake_tasks):
            return assess(self.root, policy, trust)

    def test_pending_claims_have_full_gate_coverage(self):
        self.assertEqual([x["id"] for x in verify_claim_policy(policy_pending())],
                         list(CLAIMS))

    def test_missing_required_gate_fails(self):
        p = policy_pending()
        p["claims"].pop(4)
        with self.assertRaisesRegex(CertificateError, "Missing"):
            verify_claim_policy(p)

    def test_reordered_required_gate_fails(self):
        p = policy_pending()
        p["claims"].reverse()
        with self.assertRaises(CertificateError):
            verify_claim_policy(p)

    def test_pending_with_positive_receipt_rejected(self):
        p = policy_pending()
        p["claims"][0]["receipt"] = "docs/certification/receipts/forged.json"
        with self.assertRaisesRegex(CertificateError, "Pending"):
            verify_claim_policy(p)

    def test_manual_verified_field_without_signed_receipt_fails(self):
        p = policy_pending()
        p["claims"][0]["status"] = "verified"
        with self.assertRaisesRegex(CertificateError, "signed receipt"):
            verify_claim_policy(p)

    def test_untrusted_paths_and_escape_rejected(self):
        with self.assertRaisesRegex(CertificateError, "Invalid"):
            safe_path(self.root, "docs/../secret.pem")
        with self.assertRaises(CertificateError):
            safe_path(self.root, "/etc/passwd")
        with self.assertRaises(CertificateError):
            safe_path(self.root, "docs/certification/../../secret")

    def test_symlink_outside_repository_rejected(self):
        outside = self.base / "outside"
        outside.write_text("secret")
        link = self.root / "docs/coverage/link.txt"
        link.symlink_to(outside)
        with self.assertRaisesRegex(CertificateError, "escapes"):
            safe_path(self.root, "docs/coverage/link.txt")

    def test_blocked_coverage_cannot_be_certified(self):
        r = self.fake_assess(policy_pending(), complete=False)
        self.assertFalse(r["certified"])
        self.assertIn("Global coverage gate is not certified", r["blockers"])
        self.assertEqual(r["signed_receipts_present"], 0)
        self.assertEqual(r["tasks_done"], 0)
        self.assertEqual(r["signed_receipts_required"], 8)

    def test_even_complete_coverage_with_no_signatures_is_blocked(self):
        r = self.fake_assess(policy_pending(), complete=True)
        self.assertFalse(r["certified"])
        self.assertTrue(r["coverage_passed"])
        self.assertIn("Trusted external review keys not provided", r["blockers"])
        self.assertEqual(len([x for x in r["blockers"] if x.startswith("Unsigned")]), 8)

    def test_status_never_labels_pending_certificate_success(self):
        text = render(policy_pending(), self.fake_assess(policy_pending(), True))
        self.assertIn("NAO CERTIFICADO", text)
        self.assertIn("windows7_x64 | pending", text)

    def test_digest_rejects_size_expansion(self):
        test = self.root / "docs/coverage/digest.txt"
        test.write_bytes(b"abc")
        self.assertEqual(sha_file(test), hashlib.sha256(b"abc").hexdigest())
        with self.assertRaisesRegex(CertificateError, "too large"):
            sha_file(test, limit=2)

    def make_signed_proof(self, claim_id, signer, private_key, trusted):
        receipt_dir = self.root / "docs/certification/receipts"
        proof_dir = self.root / "docs/certification/proofs"
        receipt_dir.mkdir(parents=True, exist_ok=True)
        proof_dir.mkdir(parents=True, exist_ok=True)
        artifact_rel = "docs/certification/proofs/" + claim_id + ".txt"
        artifact = self.root / artifact_rel
        artifact.write_text("Synthetic proof for "+claim_id, encoding="utf-8")
        payload = {
            "schema": "rea-signed-receipt-v1", "claim_id": claim_id,
            "scope_sha256": sha_file(self.root / "docs/coverage/scope.json"),
            "source_archive_sha256": self.scope["source_archive"]["sha256"],
            "result": "pass", "run_id": "synthetic-"+claim_id,
            "method": "synthetic test, not commercial software",
            "reviewed_at": "2026-10-29T12:00:00Z",
            "test_cases": ["fixture-"+claim_id],
            "artifacts": [{"path": artifact_rel, "sha256": sha_file(artifact)}],
        }
        if claim_id in ("windows7_x86", "windows7_x64"):
            payload["platform"] = "windows7-sp1-" + claim_id.split("_")[-1]
        receipt_rel = "docs/certification/receipts/"+claim_id+".json"
        signature_rel = "docs/certification/receipts/"+claim_id+".sig"
        file = self.root / receipt_rel
        signature = self.root / signature_rel
        file.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(private_key),
                        "-out", str(signature), str(file)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True)
        return {
            "id": claim_id, "status": "verified", "receipt": receipt_rel,
            "receipt_sha256": sha_file(file), "signature": signature_rel,
            "signer": signer,
        }

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL unavailable")
    def test_external_signatures_and_independent_review_are_real(self):
        trust = self.base / "trusted_keys"
        trust.mkdir()
        keys = {}
        for ident in ("ExecutorA", "AuditorB"):
            private = self.base / (ident + ".key")
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "RSA",
                 "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            with (trust / (ident + ".pem")).open("wb") as dest:
                subprocess.run(
                    ["openssl", "pkey", "-in", str(private), "-pubout"],
                    stdout=dest, stderr=subprocess.PIPE, check=True)
            keys[ident] = private
        policy = policy_pending()
        for i, ident in enumerate(CLAIMS):
            signer = "AuditorB" if ident == "independent_review" else "ExecutorA"
            policy["claims"][i] = self.make_signed_proof(
                ident, signer, keys[signer], trust)
        r = self.fake_assess(policy, complete=True, trust=trust)
        self.assertTrue(r["certified"])
        self.assertTrue(r["signatures_verified_externally"])
        self.assertEqual(r["signed_receipts_present"], 8)
        # Tampering cannot pass after a verified signature.
        receipt = self.root / policy["claims"][0]["receipt"]
        receipt.write_text(receipt.read_text() + " ", encoding="utf-8")
        with self.assertRaisesRegex(CertificateError, "digest mismatch"):
            self.fake_assess(policy, complete=True, trust=trust)
        # Self-declared success without trusted public keys is insufficient.
        receipt.write_text(receipt.read_text()[:-1], encoding="utf-8")
        self.assertFalse(self.fake_assess(policy, complete=True)["certified"])
        # Repo-provided public keys cannot become their own trust anchors.
        with self.assertRaisesRegex(CertificateError, "outside repository"):
            self.fake_assess(policy, complete=True, trust=self.root)


if __name__ == "__main__":
    unittest.main()
