"""Coverage ledger tests; synthetic fixtures only."""
import copy
import hashlib
import io
import json
import pathlib
import tempfile
import unittest
import zipfile

from tools.rea_coverage import (
    CoverageError, measure, render, union_size, validate, verify_archive,
)


def fixture(root):
    evidence = root / "docs/coverage/proof.md"
    evidence.parent.mkdir(parents=True)
    evidence.write_text("Synthetic test evidence", encoding="utf-8")
    return {
        "schema": "rea-full-scope-v1",
        "product": "Synthetic product",
        "as_of": "2026-10-28",
        "objective": "All auditable components",
        "discovery_closed": False, "reconstruction_complete": False,
        "semantic_equivalence_verified": False, "windows7_sp1_x86_verified": False,
        "windows7_sp1_x64_verified": False,
        "source_archive": {"name": "fixture.zip", "sha256": hashlib.sha256(b"").hexdigest()},
        "components": [
            {"id": "MAIN", "kind": "observed_pe", "origin": "archive_member",
             "path": "bin/app.exe", "size_bytes": 200,
             "sha256": hashlib.sha256(b"fixture").hexdigest(),
             "architecture": "x86", "semantics_status": "partial",
             "behavior_verified": False,
             "executable_sections": [{"name": ".text", "start_rva": "0x1000", "raw_size": 100}],
             "decoded_intervals": [
                 {"start_rva": "0x1000", "end_rva_exclusive": "0x1010",
                  "evidence": "docs/coverage/proof.md"}]},
            {"id": "DRIVER", "kind": "filename_reference", "origin": "string_only",
             "path": "unknown.sys", "size_bytes": None, "sha256": None,
             "semantics_status": "unmeasured", "behavior_verified": False,
             "executable_sections": [], "decoded_intervals": []},
        ],
        "unknowns": ["Driver not found"], "work_queue": [],
    }


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.data = fixture(self.root)

    def test_partial_coverage_is_not_global(self):
        out = measure(self.data, self.root)
        self.assertEqual(out["known_pes"], 1)
        self.assertEqual(out["measured_executable_bytes"], 100)
        self.assertEqual(out["locally_decoded_bytes"], 16)
        self.assertEqual(out["measured_modules_local_percent"], 16.0)
        self.assertIsNone(out["global_reverse_engineering_percent"])
        self.assertFalse(out["full_coverage_certified"])

    def test_unknown_denominator_stays_null(self):
        comp = copy.deepcopy(self.data["components"][0])
        comp["id"] = "NESTED"
        comp["executable_sections"] = []
        comp["decoded_intervals"] = []
        comp["semantics_status"] = "unmeasured"
        self.data["components"].append(comp)
        out = measure(self.data, self.root)
        self.assertEqual(out["unknown_executable_denominators"], 1)
        self.assertIsNone(out["modules"][1]["decoded_percent"])

    def test_reject_overlap(self):
        self.data["components"][0]["decoded_intervals"].append({
            "start_rva": "0x1008", "end_rva_exclusive": "0x1020",
            "evidence": "docs/coverage/proof.md"})
        with self.assertRaisesRegex(CoverageError, "Overlapping"):
            measure(self.data, self.root)

    def test_reject_outside_section(self):
        self.data["components"][0]["decoded_intervals"][0]["end_rva_exclusive"] = "0x2000"
        with self.assertRaisesRegex(CoverageError, "outside"):
            measure(self.data, self.root)

    def test_reject_missing_evidence(self):
        self.data["components"][0]["decoded_intervals"][0]["evidence"] = "docs/missing.md"
        with self.assertRaisesRegex(CoverageError, "Missing"):
            measure(self.data, self.root)

    def test_reject_duplicate_component(self):
        self.data["components"].append(copy.deepcopy(self.data["components"][0]))
        with self.assertRaisesRegex(CoverageError, "duplicate"):
            measure(self.data, self.root)

    def test_filename_reference_cannot_claim_hash(self):
        self.data["components"][1]["sha256"] = "a" * 64
        with self.assertRaisesRegex(CoverageError, "not a recovered"):
            validate(self.data, self.root)

    def test_no_false_certificate_even_if_bytes_complete(self):
        item = self.data["components"][0]
        item["decoded_intervals"][0]["end_rva_exclusive"] = "0x1064"
        item["semantics_status"] = "verified"
        item["behavior_verified"] = True
        for flag in ("discovery_closed", "reconstruction_complete",
                     "semantic_equivalence_verified", "windows7_sp1_x86_verified",
                     "windows7_sp1_x64_verified"):
            self.data[flag] = True
        self.assertFalse(measure(self.data, self.root)["full_coverage_certified"])

    def test_union_and_invalid_rva(self):
        self.assertEqual(union_size([(10, 20), (21, 30)]), 19)
        with self.assertRaises(CoverageError):
            union_size([(10, 20), (15, 22)])

    def test_archive_hash_guard(self):
        path = self.root / "fixture.zip"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("bin/app.exe", b"x" * 200)
        self.data["source_archive"]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(CoverageError, "PE hash mismatch"):
            verify_archive(path, self.data)

    def test_document_deterministic(self):
        r = measure(self.data, self.root)
        self.assertEqual(render(self.data, r), render(self.data, r))
        self.assertIn("indeterminado", render(self.data, r))

    def test_repository_scope_is_consistent(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        manifest = json.loads((root / "docs/coverage/scope.json").read_text(encoding="utf-8"))
        generated = render(manifest, measure(manifest, root))
        self.assertEqual(generated,
                         (root / "docs/coverage/STATUS.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
