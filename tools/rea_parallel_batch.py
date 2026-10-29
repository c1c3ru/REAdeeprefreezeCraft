#!/usr/bin/env python3
"""REA acceleration: run independent bounded static analyzers in parallel.

Only approved existing analyzers; no downloaded executables, no execution of
the commercial Windows sample, no driver loading, no background scheduling.
Fail-closed on original ZIP hash mismatch. All reports remain in a *local*
directory outside the Git repository. Cache depends on the complete tools/
Python source tree, Python version and original ZIP hash; reused outputs need
valid SHA-256 and JSON. Checkpoint is written after each completed job.

Python 3.8+ stdlib. Parallelism helps only on sufficiently costly independent
analyses. This is NOT evidence of Windows 7 runtime behavior/equivalence.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
import pathlib
import platform
import subprocess
import sys
import tempfile
import time

from .rea_overlay_inventory import ZIP_SHA

SCHEMA = "rea-static-parallel-batch-v1"
# These existing CLI modules accept --archive and --json.
ALLOWED = (
    "rea_recursive_inventory",
    "rea_embedded_pe_candidates",
    "rea_upx_surface",
    "rea_driver_evidence",
    "rea_overlay_inventory",
    "rea_overlay_codec_probe",
    "rea_overlay_reader_trace",
    "rea_overlay_handle_flow",
    "rea_transform_state",
    "rea_key_input_provenance",
    "rea_constructor_xrefs",
    "rea_path_indirect_scope",
)
DEFAULT = (
    "rea_overlay_inventory",
    "rea_overlay_reader_trace",
    "rea_overlay_handle_flow",
    "rea_transform_state",
    "rea_key_input_provenance",
    "rea_constructor_xrefs",
    "rea_path_indirect_scope",
    "rea_upx_surface",
    "rea_driver_evidence",
)
MAX_WORKERS = 4
MAX_OUTPUT = 8 * 1024 * 1024


class ParallelBatchError(ValueError):
    pass


def file_hash(path):
    h = hashlib.sha256()
    with pathlib.Path(path).open("rb") as fd:
        for chunk in iter(lambda: fd.read(1048576), b""):
            h.update(chunk)
    return h.hexdigest()


def tools_fingerprint(repo_root):
    """Bust cache whenever *any* shared analyzer/helper source changes."""
    root = pathlib.Path(repo_root) / "tools"
    paths = sorted(root.glob("*.py"))
    if not paths or not (root / "rea_parallel_batch.py").is_file():
        raise ParallelBatchError("Local source tree missing analyzers")
    h = hashlib.sha256()
    for path in paths:
        h.update(path.name.encode("utf-8"))
        h.update(b"\0")
        h.update(bytes.fromhex(file_hash(path)))
    return h.hexdigest()


def task_signature(zip_sha, tool_sha, task):
    data = {
        "schema": SCHEMA, "archive_sha256": zip_sha,
        "sources_sha256": tool_sha, "task": task,
        "python": "%d.%d" % sys.version_info[:2],
    }
    return hashlib.sha256(json.dumps(
        data, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def validate_tasks(tasks):
    if not isinstance(tasks, (tuple, list)) or not tasks:
        raise ParallelBatchError("Choose at least one approved task")
    if len(tasks) != len(set(tasks)):
        raise ParallelBatchError("Duplicate analyzer name")
    invalid = [name for name in tasks if name not in ALLOWED]
    if invalid:
        raise ParallelBatchError("Unapproved analyzer(s): "+", ".join(map(str, invalid)))
    return tuple(tasks)


def output_path(repo_root, output_dir):
    root = pathlib.Path(repo_root).resolve()
    out = pathlib.Path(output_dir).resolve()
    if out == root or root in out.parents:
        raise ParallelBatchError("Local output directory must be outside the repository")
    out.mkdir(parents=True, exist_ok=True)
    return out


def valid_cached(previous, name, signature, output):
    item = previous.get(name, {})
    if item.get("signature") != signature or item.get("status") not in ("passed", "cached"):
        return False
    if (not output.is_file() or not 1 <= output.stat().st_size <= MAX_OUTPUT or
            file_hash(output) != item.get("output_sha256")):
        return False
    try:
        payload = json.loads(output.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        return False
    return isinstance(payload, dict) and bool(payload.get("schema"))


def run_task(repo_root, archive, output_dir, name, signature, timeout, runner):
    """One isolated subprocess; metadata-only JSON, no shell interpolation."""
    start = time.monotonic()
    temp = tempfile.NamedTemporaryFile(
        prefix="."+name+".", suffix=".json.tmp", dir=str(output_dir),
        delete=False)
    temp_path = pathlib.Path(temp.name)
    temp.close()
    final = output_dir / (name+".json")
    try:
        command = [sys.executable, "-m", "tools."+name, "--archive",
                   str(archive), "--json", str(temp_path)]
        completed = runner(
            command, cwd=str(repo_root), capture_output=True,
            text=True, timeout=timeout, check=False)
        if completed.returncode:
            raise ParallelBatchError(
                "Analyzer returned %d: %s" % (
                    completed.returncode,
                    (completed.stderr or "")[:260].replace(str(archive), "[ARCHIVE]")))
        if (not temp_path.is_file() or not
                1 <= temp_path.stat().st_size <= MAX_OUTPUT):
            raise ParallelBatchError("Missing or oversized analyzer report")
        obj = json.loads(temp_path.read_text(encoding="utf-8"))
        if not isinstance(obj, dict) or not obj.get("schema"):
            raise ParallelBatchError("Analyzer emitted invalid schema")
        digest = file_hash(temp_path)
        os.replace(str(temp_path), str(final))
        return name, {
            "status": "passed", "signature": signature,
            "output_file": name+".json", "output_sha256": digest,
            "duration_seconds": round(time.monotonic()-start, 3),
        }
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        return name, {
            "status": "failed", "signature": signature,
            "error": str(exc)[:300].replace(str(archive), "[ARCHIVE]"),
            "duration_seconds": round(time.monotonic()-start, 3),
        }
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def checkpoint_path(out):
    return out / "STATUS_BATCH.json"


def write_checkpoint(path, result):
    temp = tempfile.NamedTemporaryFile(prefix=".STATUS_BATCH.",
                                       suffix=".tmp", dir=str(path.parent),
                                       mode="w", encoding="utf-8", delete=False)
    try:
        json.dump(result, temp, sort_keys=True, indent=2)
        temp.write("\n")
        temp.close()
        os.replace(temp.name, str(path))
    finally:
        if not temp.closed:
            temp.close()
        try:
            pathlib.Path(temp.name).unlink()
        except FileNotFoundError:
            pass


def run_batch(archive, output_dir, tasks=DEFAULT, workers=3, timeout=120,
              resume=True, repo_root=None, runner=None, source_sha=None):
    tasks = validate_tasks(tasks)
    if type(workers) is not int or not 1 <= workers <= MAX_WORKERS:
        raise ParallelBatchError("Workers must be 1..%d" % MAX_WORKERS)
    if type(timeout) is not int or not 1 <= timeout <= 600:
        raise ParallelBatchError("Timeout must be 1..600 seconds")
    root = pathlib.Path(repo_root or pathlib.Path(__file__).resolve().parents[1]).resolve()
    archive = pathlib.Path(archive).resolve()
    if not archive.is_file() or file_hash(archive) != ZIP_SHA:
        raise ParallelBatchError("Original source ZIP SHA-256 mismatch")
    out = output_path(root, output_dir)
    fingerprint = source_sha or tools_fingerprint(root)
    previous = {}
    path = checkpoint_path(out)
    if resume and path.is_file():
        try:
            old = json.loads(path.read_text(encoding="utf-8"))
            if (old.get("schema") == SCHEMA and
                    old.get("archive_sha256") == ZIP_SHA and
                    old.get("sources_sha256") == fingerprint and
                    isinstance(old.get("results"), dict)):
                previous = old["results"]
        except (ValueError, UnicodeError):
            pass
    report = {
        "schema": SCHEMA,
        "archive_sha256": ZIP_SHA,
        "sources_sha256": fingerprint,
        "python": "%d.%d" % sys.version_info[:2],
        "requested_tasks": list(tasks),
        "workers": workers,
        "results": {},
        "source_run_is_static_only": True,
        "windows7_runtime_observations": 0,
        "signed_certification_receipts_created": 0,
        "product_equivalence_certified": False,
    }
    # Results are considered individually, not through a truthy "CI passed" flag.
    pending = []
    for name in tasks:
        signature = task_signature(ZIP_SHA, fingerprint, name)
        if resume and valid_cached(previous, name, signature, out/(name+".json")):
            cached = dict(previous[name])
            cached["status"] = "cached"
            report["results"][name] = cached
        else:
            pending.append((name, signature))
    write_checkpoint(path, report)
    runner = runner or subprocess.run
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(run_task, root, archive, out, name, signature,
                        timeout, runner): name
            for name, signature in pending}
        for future in concurrent.futures.as_completed(futures):
            name, result = future.result()
            report["results"][name] = result
            write_checkpoint(path, report)  # recoverable checkpoint per job
    # Stable ordering makes the batch status straightforward to diff.
    report["results"] = {name: report["results"][name] for name in tasks}
    report["completed"] = sum(v["status"] in ("passed", "cached")
                              for v in report["results"].values())
    report["failed"] = sum(v["status"] == "failed"
                          for v in report["results"].values())
    report["ready_for_runtime_certification"] = False
    write_checkpoint(path, report)
    return report


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive", required=True, help="Local original ZIP; never committed")
    p.add_argument("--output-dir", required=True, help="Local, outside the Git repository")
    p.add_argument("--tasks", nargs="+", choices=ALLOWED, default=DEFAULT)
    p.add_argument("--jobs", type=int, default=3)
    p.add_argument("--timeout", type=int, default=120)
    p.add_argument("--no-resume", action="store_true")
    args = p.parse_args(argv)
    try:
        result = run_batch(args.archive, args.output_dir, args.tasks,
                           args.jobs, args.timeout, not args.no_resume)
        print(json.dumps({
            "batch": str(checkpoint_path(pathlib.Path(args.output_dir))),
            "completed": result["completed"], "failed": result["failed"],
            "total": len(result["requested_tasks"]),
            "runtime_certified": False,
        }, sort_keys=True))
        return 1 if result["failed"] else 0
    except (OSError, ParallelBatchError) as exc:
        print("REA parallel batch ERROR: "+str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
