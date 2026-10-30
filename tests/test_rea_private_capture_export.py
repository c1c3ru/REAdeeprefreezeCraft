"""REA-015/T synthetic fixtures for private debugger export ingestion."""
import copy
import hashlib
import json
import os
import pathlib
import stat
import tempfile
import unittest

from tools.rea_overlay_inventory import ROOT_SHA
from tools.rea_private_capture_export import (
    PrivateExportError, export, main, relative_private,
)
from tools.rea_runtime_file_correlation import validate_trace


def fixture(root):
    file_bytes = b"01" + b"synthetic-example-payload" + b"99"
    read_bytes = file_bytes[2:10]
    (root / "opened.bin").write_bytes(file_bytes)
    (root / "read.bin").write_bytes(read_bytes)
    (root / "pre.bin").write_bytes(read_bytes[:4])
    (root / "post.bin").write_bytes(read_bytes[:4])
    capture = {
        "schema": "rea-015-t-private-export-v1",
        "capture": {
            "capture_id": "SYNTHETIC-NEVER-VM",
            "platform": "windows7-sp1-x86",
            "original_pe_sha256": ROOT_SHA,
            "method": "synthetic-fixture-not-debugger",
            "observed_at": "2026-10-30T16:00:00Z",
            "independently_signed": False,
        },
        "events": [
            {"seq": 1, "kind": "open", "pid": 123, "handle": "0x30",
             "path_redacted": "synthetic-file",
             "opened_file_snapshot": "opened.bin"},
            {"seq": 2, "kind": "read", "pid": 123, "handle": "0x30",
             "file_offset": 2, "bytes_returned": len(read_bytes),
             "returned_buffer_dump": "read.bin"},
            {"seq": 3, "kind": "close", "pid": 123, "handle": "0x30"},
        ],
        "pairs": [{
            "sample_id": "synthetic-1", "read_seq": 2, "pid": 123,
            "handle": "0x30", "offset_in_read": 0,
            "byte_index_in_transform_block": 0,
            "pre_transform_dump": "pre.bin", "post_transform_dump": "post.bin",
            "owner_flag_0x60": 0, "state_kind": 1, "branch_observed": False,
            "primary_words": [1, 2, 3, 4],
            "secondary_words": [0, 0, 0, 0],
            "active_words": [1, 2, 3, 4],
            "reported_key_source": "unknown",
        }],
    }
    return capture, file_bytes, read_bytes


class PrivateCaptureExportTests(unittest.TestCase):
    def test_derives_hashes_and_existing_validator_accepts(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            raw, file_bytes, read_bytes = fixture(root)
            trace, pairs = export(raw, root)
            validate_trace(trace)
            self.assertEqual(len(trace["events"]), 3)
            self.assertEqual(trace["events"][0]["file_sha256"],
                             hashlib.sha256(file_bytes).hexdigest())
            self.assertEqual(trace["events"][1]["buffer_sha256"],
                             hashlib.sha256(read_bytes).hexdigest())
            self.assertEqual(pairs["samples"][0]["pre_hex"],
                             read_bytes[:4].hex())
            self.assertEqual(pairs["samples"][0]["post_hex"],
                             read_bytes[:4].hex())
            self.assertFalse(trace["capture"]["independently_signed"])
            self.assertNotIn("opened.bin", json.dumps(trace))
            self.assertNotIn("read.bin", json.dumps(trace))
            self.assertNotIn("file_bytes", json.dumps(trace))

    def test_no_pairs_yields_empty_private_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            raw, _, _ = fixture(root)
            raw["pairs"] = []
            trace, pairs = export(raw, root)
            self.assertEqual(pairs["samples"], [])
            validate_trace(trace)

    def test_read_dump_size_is_exact(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            raw, _, _ = fixture(root)
            raw["events"][1]["bytes_returned"] += 1
            with self.assertRaisesRegex(PrivateExportError, "dump length"):
                export(raw, root)

    def test_detects_before_buffer_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            raw, _, _ = fixture(root)
            (root / "pre.bin").write_bytes(b"NOPE")
            with self.assertRaisesRegex(PrivateExportError, "differ"):
                export(raw, root)

    def test_rejects_orphan_handle_and_reused_sequence(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            raw, _, _ = fixture(root)
            raw["events"][1]["pid"] = 55
            with self.assertRaisesRegex(PrivateExportError, "sequence"):
                export(raw, root)
            raw["events"][1]["pid"] = 123
            raw["events"][1]["seq"] = 1
            with self.assertRaisesRegex(PrivateExportError, "sequence"):
                export(raw, root)

    def test_rejects_path_traversal_and_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d) / "private"
            root.mkdir()
            raw, _, _ = fixture(root)
            raw["events"][0]["opened_file_snapshot"] = "../elsewhere"
            with self.assertRaises(PrivateExportError):
                export(raw, root)
            raw["events"][0]["opened_file_snapshot"] = "linked.bin"
            (root / "linked.bin").symlink_to(root / "opened.bin")
            with self.assertRaisesRegex(PrivateExportError, "Symlinks"):
                export(raw, root)

    def test_pair_wrong_handle_key_and_overlaps(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            raw, _, _ = fixture(root)
            raw["pairs"][0]["handle"] = "0x31"
            with self.assertRaisesRegex(PrivateExportError, "PID/handle"):
                export(raw, root)
            raw["pairs"][0]["handle"] = "0x30"
            raw["pairs"][0]["active_words"] = [1, 2, True, 4]
            with self.assertRaisesRegex(PrivateExportError, "DWORD"):
                export(raw, root)
            raw["pairs"][0]["active_words"] = [1, 2, 3, 4]
            repeated = copy.deepcopy(raw["pairs"][0])
            repeated["sample_id"] = "synthetic-2"
            raw["pairs"].append(repeated)
            with self.assertRaisesRegex(PrivateExportError, "Overlapping"):
                export(raw, root)

    def test_cli_private_permissions_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            raw, _, _ = fixture(root)
            source = root / "raw_index.json"
            source.write_text(json.dumps(raw), encoding="utf-8")
            trace_path, pairs_path = root / "trace.json", root / "private_pairs.json"
            args = ["--manifest", str(source), "--private-root", str(root),
                    "--trace-json", str(trace_path), "--pairs-json", str(pairs_path)]
            self.assertEqual(main(args), 0)
            self.assertEqual(main(args), 1)  # never overwrite original evidence
            trace = json.loads(trace_path.read_text(encoding="utf-8"))
            pairs = json.loads(pairs_path.read_text(encoding="utf-8"))
            self.assertEqual(len(pairs["samples"]), 1)
            self.assertEqual(trace["capture"]["capture_id"], raw["capture"]["capture_id"])
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(trace_path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(pairs_path.stat().st_mode), 0o600)

    def test_cli_blocks_pair_export_outside_root(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d) / "private"
            root.mkdir()
            raw, _, _ = fixture(root)
            src = root / "raw_index.json"
            src.write_text(json.dumps(raw), encoding="utf-8")
            outside = pathlib.Path(d) / "pairs.json"
            result = main(["--manifest", str(src), "--private-root", str(root),
                           "--trace-json", str(root / "trace.json"),
                           "--pairs-json", str(outside)])
            self.assertEqual(result, 1)
            self.assertFalse(outside.exists())
            self.assertFalse((root / "trace.json").exists())

    def test_boolean_not_accepted_as_captured_byte_count(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            raw, _, _ = fixture(root)
            raw["events"][1]["bytes_returned"] = True
            with self.assertRaisesRegex(PrivateExportError, "returned length"):
                export(raw, root)


if __name__ == "__main__":
    unittest.main()
