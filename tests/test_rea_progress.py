"""Progress planner tests: all fixtures synthetic, no third-party data."""
import contextlib
import io
import json
import pathlib
import tempfile
import unittest

from tools.rea_progress import (
    ProgressError, groups, main, render, validate,
)


def base_task(identifier, status="todo", depends_on=None, evidence=None, blocker=None):
    item = {
        "id": identifier, "phase": "test", "title": "Fixture " + identifier,
        "status": status, "priority": "P0", "depends_on": depends_on or [],
        "evidence": evidence or [], "acceptance": ["Criterion one"],
        "next_action": "Run synthetic check",
    }
    if blocker is not None:
        item["blocker"] = blocker
    return item


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = pathlib.Path(self.folder.name)
        (self.root / "fixture.txt").write_text("test", encoding="utf-8")
        self.manifest = {
            "schema": "rea-progress-v1",
            "as_of": "2026-10-28",
            "project": "test/repo",
            "objective": "Build traceable results",
            "scope_note": "Task completion is not behavioral equivalence.",
            "tasks": [
                base_task("REA-001", "done", evidence=["fixture.txt"]),
                base_task("REA-002", "todo", depends_on=["REA-001"]),
                base_task("REA-003", "todo", depends_on=["REA-002"]),
                base_task("REA-004", "blocked", depends_on=["REA-002"],
                          blocker="VM not provided"),
            ],
        }

    def test_valid_groups_and_next_actions(self):
        idx = validate(self.manifest, self.root)
        status = groups(idx)
        self.assertEqual([t["id"] for t in status["done"]], ["REA-001"])
        self.assertEqual([t["id"] for t in status["ready"]], ["REA-002"])
        self.assertEqual([t["id"] for t in status["waiting"]], ["REA-003"])
        self.assertEqual([t["id"] for t in status["blocked"]], ["REA-004"])

    def test_document_deterministic(self):
        first = render(self.manifest, self.root)
        self.assertEqual(first, render(self.manifest, self.root))
        self.assertIn("REA-002 (P0)", first)
        self.assertIn("Concluídas: **1/4**", first)
        self.assertIn("fixture.txt", first)
        self.assertIn("VM not provided", first)

    def test_reject_done_without_evidence(self):
        self.manifest["tasks"][0]["evidence"] = []
        with self.assertRaisesRegex(ProgressError, "Done without evidence"):
            validate(self.manifest, self.root)

    def test_reject_missing_evidence(self):
        self.manifest["tasks"][0]["evidence"] = ["not-here"]
        with self.assertRaisesRegex(ProgressError, "Missing evidence"):
            validate(self.manifest, self.root)

    def test_reject_path_traversal(self):
        self.manifest["tasks"][0]["evidence"] = ["../escape.txt"]
        with self.assertRaisesRegex(ProgressError, "Unsafe"):
            validate(self.manifest, self.root)

    def test_reject_cyclic_dependencies(self):
        self.manifest["tasks"][0]["depends_on"] = ["REA-003"]
        with self.assertRaisesRegex(ProgressError, "Cyclic dependency"):
            validate(self.manifest, self.root)

    def test_reject_done_before_dependency(self):
        self.manifest["tasks"][2]["status"] = "done"
        self.manifest["tasks"][2]["evidence"] = ["fixture.txt"]
        with self.assertRaisesRegex(ProgressError, "Done despite unfinished"):
            validate(self.manifest, self.root)

    def test_reject_undocumented_blocker(self):
        del self.manifest["tasks"][3]["blocker"]
        with self.assertRaisesRegex(ProgressError, "Blocked without reason"):
            validate(self.manifest, self.root)

    def test_check_detects_stale_document(self):
        docs = self.root / "docs"
        (docs / "progress").mkdir(parents=True)
        with (docs / "progress/tasks.json").open("w", encoding="utf-8") as stream:
            json.dump(self.manifest, stream)
        captured_stdout, captured_stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(captured_stdout):
            self.assertEqual(main(["--root", str(self.root), "--write"]), 0)
            self.assertEqual(main(["--root", str(self.root), "--check"]), 0)
        self.assertIn("status e evidencias validos", captured_stdout.getvalue())
        (docs / "STATUS_ATUAL.md").write_text("bad", encoding="utf-8")
        with contextlib.redirect_stderr(captured_stderr):
            self.assertEqual(main(["--root", str(self.root), "--check"]), 1)
        # O erro é esperado pelo teste; não deve poluir os logs de CI aprovado.
        self.assertIn("Status desatualizado", captured_stderr.getvalue())

    def test_complete_status_requires_real_files(self):
        for item in self.manifest["tasks"]:
            item["status"] = "done"
            item["evidence"] = ["fixture.txt"]
        validate(self.manifest, self.root)

    def test_real_repository_manifest_is_consistent(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        with (root / "docs/progress/tasks.json").open("r", encoding="utf-8") as stream:
            data = json.load(stream)
        self.assertEqual(data["schema"], "rea-progress-v1")
        self.assertEqual(render(data, root),
                         (root / "docs/STATUS_ATUAL.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
