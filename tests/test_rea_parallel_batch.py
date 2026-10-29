"""REA parallel batch: synthetic fixtures, concurrency, cache, fail-closed proof."""
import hashlib
import json
import pathlib
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from tools import rea_parallel_batch as batch


class ParallelBatchTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = pathlib.Path(tmp.name)
        self.root = self.base / "repo"
        (self.root / "tools").mkdir(parents=True)
        (self.root / "tools" / "rea_parallel_batch.py").write_text("# synthetic")
        (self.root / "tools" / "rea_overlay_inventory.py").write_text("# synthetic")
        self.archive = self.base / "fake_source.zip"
        self.archive.write_bytes(b"FAKE ZIP ONLY; not a real installer")
        self.out = self.base / "private_results"
        self.digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.patch_zip = mock.patch.object(batch, "ZIP_SHA", self.digest)
        self.patch_zip.start()
        self.addCleanup(self.patch_zip.stop)

    def fake_runner(self, call, **kwargs):
        result_file = pathlib.Path(call[call.index("--json")+1])
        result_file.write_text(json.dumps(
            {"schema": "test-synthetic-report-v1", "task": call[2]}))
        return subprocess.CompletedProcess(call, 0, "", "")

    def run_batch(self, tasks=None, runner=None, workers=2, source_sha="a"*64,
                  resume=True, root=None, output=None):
        return batch.run_batch(
            self.archive, output or self.out,
            tasks or ("rea_overlay_inventory", "rea_upx_surface"),
            workers=workers, timeout=10, resume=resume,
            repo_root=root or self.root,
            runner=runner or self.fake_runner, source_sha=source_sha)

    def test_allowlist_blocks_shell_and_unknown_modules(self):
        for names in (
            ("../malware",), ("os.system",),
            ("rea_overlay_inventory", "rea_overlay_inventory"),
        ):
            with self.assertRaisesRegex(batch.ParallelBatchError,
                                         "Unapproved|Duplicate"):
                batch.validate_tasks(names)

    def test_empty_work_not_allowed(self):
        with self.assertRaisesRegex(batch.ParallelBatchError, "at least one"):
            batch.validate_tasks(())

    def test_bad_source_zip_blocked_before_running_commands(self):
        with mock.patch.object(batch, "ZIP_SHA", "0"*64):
            with self.assertRaisesRegex(batch.ParallelBatchError, "SHA-256"):
                self.run_batch()

    def test_cannot_write_under_repo_even_if_user_supplies_path(self):
        with self.assertRaisesRegex(batch.ParallelBatchError, "outside"):
            self.run_batch(output=self.root / "private_output")
        self.assertFalse((self.root / "private_output").exists())

    def test_parallel_execution_is_real_and_checkpoints_persist(self):
        barrier = threading.Barrier(2)
        calls = []
        lock = threading.Lock()

        def worker(call, **kwargs):
            with lock:
                calls.append(call[2])
            barrier.wait(timeout=4)
            return self.fake_runner(call, **kwargs)

        result = self.run_batch(runner=worker, workers=2)
        self.assertEqual(result["completed"], 2)
        self.assertEqual(result["failed"], 0)
        self.assertEqual(set(calls),
                         {"tools.rea_overlay_inventory", "tools.rea_upx_surface"})
        self.assertTrue(result["source_run_is_static_only"])
        self.assertFalse(result["product_equivalence_certified"])
        self.assertEqual(result["windows7_runtime_observations"], 0)
        state = json.loads((self.out / "STATUS_BATCH.json").read_text())
        self.assertEqual(state["completed"], 2)
        for name in ("rea_overlay_inventory", "rea_upx_surface"):
            self.assertEqual(result["results"][name]["status"], "passed")

    def test_verified_cache_skips_jobs_without_new_execution(self):
        seen = []
        def worker(call, **kwargs):
            seen.append(call[2])
            return self.fake_runner(call, **kwargs)
        first = self.run_batch(runner=worker)
        self.assertEqual(len(seen), 2)
        second = self.run_batch(runner=worker)
        self.assertEqual(len(seen), 2)
        self.assertEqual(second["completed"], 2)
        self.assertEqual({x["status"] for x in second["results"].values()}, {"cached"})
        self.assertEqual(first["archive_sha256"], second["archive_sha256"])

    def test_cache_can_be_reused_in_successive_resume_cycles(self):
        seen = []
        def worker(call, **kwargs):
            seen.append(call[2])
            return self.fake_runner(call, **kwargs)
        self.run_batch(runner=worker)
        self.run_batch(runner=worker)
        third = self.run_batch(runner=worker)
        self.assertEqual(len(seen), 2)
        self.assertTrue(all(x["status"] == "cached"
                            for x in third["results"].values()))

    def test_tampered_output_causes_automatic_recomputation(self):
        seen = []
        def worker(call, **kwargs):
            seen.append(call[2])
            return self.fake_runner(call, **kwargs)
        self.run_batch(runner=worker)
        (self.out / "rea_upx_surface.json").write_text(
            '{"schema":"forged","passes":true}')
        next_run = self.run_batch(runner=worker)
        self.assertEqual(len(seen), 3)
        self.assertEqual(next_run["results"]["rea_overlay_inventory"]["status"], "cached")
        self.assertEqual(next_run["results"]["rea_upx_surface"]["status"], "passed")

    def test_python_source_tree_change_invalidates_cache(self):
        seen = []
        def worker(call, **kwargs):
            seen.append(call[2])
            return self.fake_runner(call, **kwargs)
        self.run_batch(runner=worker, source_sha="a"*64)
        next_run = self.run_batch(runner=worker, source_sha="b"*64)
        self.assertEqual(len(seen), 4)
        self.assertEqual(next_run["sources_sha256"], "b"*64)

    def test_nonzero_exit_is_recorded_not_masked_by_other_successes(self):
        def worker(call, **kwargs):
            if call[2].endswith("rea_upx_surface"):
                return subprocess.CompletedProcess(call, 1, "", "synthetic fail")
            return self.fake_runner(call, **kwargs)
        out = self.run_batch(runner=worker)
        self.assertEqual(out["completed"], 1)
        self.assertEqual(out["failed"], 1)
        self.assertEqual(out["results"]["rea_upx_surface"]["status"], "failed")
        self.assertIn("synthetic fail", out["results"]["rea_upx_surface"]["error"])
        self.assertTrue((self.out / "rea_overlay_inventory.json").exists())

    def test_malformed_json_report_is_failure(self):
        def worker(call, **kwargs):
            pathlib.Path(call[call.index("--json")+1]).write_text("INVALID JSON")
            return subprocess.CompletedProcess(call, 0, "", "")
        out = self.run_batch(
            tasks=("rea_overlay_inventory",), runner=worker)
        self.assertEqual(out["failed"], 1)
        self.assertEqual(out["completed"], 0)
        self.assertFalse((self.out / "rea_overlay_inventory.json").exists())

    def test_timeout_is_reported_and_other_tasks_continue(self):
        def worker(call, **kwargs):
            if call[2].endswith("rea_upx_surface"):
                raise subprocess.TimeoutExpired(call, 1)
            return self.fake_runner(call, **kwargs)
        out = self.run_batch(runner=worker)
        self.assertEqual(out["failed"], 1)
        self.assertEqual(out["completed"], 1)
        self.assertIn("timed out", out["results"]["rea_upx_surface"]["error"])

    def test_invalid_worker_count_and_timeout_blocked(self):
        for count in (0, 5, "3"):
            with self.assertRaisesRegex(batch.ParallelBatchError, "Workers"):
                self.run_batch(workers=count)
        with self.assertRaisesRegex(batch.ParallelBatchError, "Timeout"):
            batch.run_batch(self.archive, self.out, workers=2, timeout=0,
                            repo_root=self.root, source_sha="a"*64)

    def test_fingerprint_covers_every_analyzer_and_helper_source(self):
        initial = batch.tools_fingerprint(self.root)
        (self.root / "tools" / "rea_overlay_inventory.py").write_text(
            "# changed synthetic module")
        self.assertNotEqual(initial, batch.tools_fingerprint(self.root))

    def test_result_manifest_does_not_contain_private_archive_path(self):
        out = self.run_batch()
        content = (self.out / "STATUS_BATCH.json").read_text()
        self.assertNotIn(str(self.archive), content)
        self.assertIn(self.digest, content)
        self.assertEqual(out["signed_certification_receipts_created"], 0)

    def test_no_resume_forces_all_tasks(self):
        seen = []
        def worker(call, **kwargs):
            seen.append(call[2])
            return self.fake_runner(call, **kwargs)
        self.run_batch(runner=worker)
        out = self.run_batch(runner=worker, resume=False)
        self.assertEqual(len(seen), 4)
        self.assertEqual(out["completed"], 2)
        self.assertEqual({x["status"] for x in out["results"].values()}, {"passed"})


if __name__ == "__main__":
    unittest.main()
