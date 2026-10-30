#!/usr/bin/env python3
"""REA-015/T — assemble sanitized IO and PRIVATE paired-buffer manifests from dumps.

This is an OFFLINE importer. It cannot capture a running process and does not
authenticate debugger output or certify the proprietary executable. Hex pairs
in the private output are sensitive and MUST NOT be committed. Python 3.8+.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import stat
import sys

from .rea_overlay_inventory import ROOT_SHA
from .rea_runtime_file_correlation import MAX_EVENTS, MAX_READ, RuntimeTraceError, validate_trace
from .rea_xor_differential import MAX_SAMPLE_BYTES, MAX_SAMPLES, parse_hex

SCHEMA = "rea-015-t-private-export-v1"
CAPTURE_SCHEMA = "rea-015-file-io-observation-v1"
PAIR_SCHEMA = "rea-015-xor-paired-observation-v1"
MAX_MANIFEST = 2 * 1024 * 1024
MAX_OPEN_SNAPSHOT = 128 * 1024 * 1024
PATH_LABEL = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
HANDLE = re.compile(r"^0x[0-9a-fA-F]{1,16}$")
KEY_SOURCES = ("caller_string", "localtime_fallback", "unknown")


class PrivateExportError(ValueError):
    pass


def integer(value, low, high, label):
    if type(value) is not int or not low <= value <= high:
        raise PrivateExportError("Invalid " + label)
    return value


def relative_private(root, name):
    """Require a local file inside an independently maintained PRIVATE root."""
    if not isinstance(name, str) or not name or "\x00" in name:
        raise PrivateExportError("Invalid private source reference")
    local = pathlib.Path(name)
    if local.is_absolute() or any(s in (".", "..") for s in local.parts):
        raise PrivateExportError("Private source must be a relative file")
    candidate = root / local
    # Reject symlinked components, including directories, to reduce surprises.
    cursor = root
    for component in local.parts:
        cursor = cursor / component
        if cursor.is_symlink():
            raise PrivateExportError("Symlinks are not accepted for captured bytes")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        raise PrivateExportError("Missing captured byte file")
    if root not in resolved.parents or not resolved.is_file():
        raise PrivateExportError("Captured bytes escaped private root")
    if not stat.S_ISREG(resolved.stat().st_mode):
        raise PrivateExportError("Expected a regular capture file")
    return resolved


def hash_snapshot(path):
    if not 1 <= path.stat().st_size <= MAX_OPEN_SNAPSHOT:
        raise PrivateExportError("Invalid opened-file snapshot size")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            digest.update(chunk)
    return path.stat().st_size, digest.hexdigest()


def dump_bytes(root, rel, max_size):
    path = relative_private(root, rel)
    length = path.stat().st_size
    if not 1 <= length <= max_size:
        raise PrivateExportError("Invalid captured buffer size")
    return path.read_bytes()


def export(manifest, private_root):
    """Check dump sizes/links and generate input for existing N/R validators.

    Files and captured bytes are externally supplied: all positive results
    are LOCAL consistency only, not authenticated runtime evidence.
    """
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
        raise PrivateExportError("Invalid private export schema")
    capture = manifest.get("capture")
    if not isinstance(capture, dict):
        raise PrivateExportError("Missing capture metadata")
    if capture.get("platform") not in ("windows7-sp1-x86", "windows7-sp1-x64"):
        raise PrivateExportError("Invalid Windows 7 architecture label")
    if capture.get("original_pe_sha256") != ROOT_SHA:
        raise PrivateExportError("Original executable must match pinned SHA-256")
    for label in ("capture_id", "method", "observed_at"):
        value = capture.get(label)
        if not isinstance(value, str) or not 1 <= len(value) <= 256:
            raise PrivateExportError("Missing " + label)
    if capture.get("independently_signed") is not False:
        raise PrivateExportError("Cannot self-assert independent signature")
    raw_events = manifest.get("events")
    if not isinstance(raw_events, list) or not 1 <= len(raw_events) <= MAX_EVENTS:
        raise PrivateExportError("Invalid event count")
    root = pathlib.Path(private_root).resolve(strict=True)
    if not root.is_dir():
        raise PrivateExportError("Private capture root is not a directory")
    events, reads = [], {}
    for raw in raw_events:
        if not isinstance(raw, dict):
            raise PrivateExportError("Invalid raw event")
        kind = raw.get("kind")
        seq = integer(raw.get("seq"), 1, 100000000, "event sequence")
        pid = integer(raw.get("pid"), 1, 0xffffffff, "PID")
        handle = raw.get("handle")
        if not isinstance(handle, str) or not HANDLE.fullmatch(handle):
            raise PrivateExportError("Invalid handle label")
        base = {"seq": seq, "kind": kind, "pid": pid, "handle": handle}
        if kind == "open":
            label = raw.get("path_redacted")
            if not isinstance(label, str) or not PATH_LABEL.fullmatch(label):
                raise PrivateExportError("Opened path must have sanitized label")
            size, sha = hash_snapshot(relative_private(root, raw.get("opened_file_snapshot")))
            base.update({"api": "CreateFileA", "result": "success",
                         "path_redacted": label, "file_size": size,
                         "file_sha256": sha})
        elif kind == "read":
            offset = integer(raw.get("file_offset"), 0, MAX_OPEN_SNAPSHOT,
                             "ReadFile absolute offset")
            count = integer(raw.get("bytes_returned"), 1, MAX_READ,
                            "ReadFile returned length")
            payload = dump_bytes(root, raw.get("returned_buffer_dump"), MAX_READ)
            if len(payload) != count:
                raise PrivateExportError("ReadFile dump length does not match returned count")
            base.update({"api": "ReadFile", "result": "success",
                         "file_offset": offset, "bytes_returned": count,
                         "buffer_sha256": hashlib.sha256(payload).hexdigest()})
            reads[seq] = (pid, int(handle, 16), payload)
        elif kind == "close":
            base["api"] = "CloseHandle"
        else:
            raise PrivateExportError("Unexpected event kind")
        events.append(base)
    trace = {
        "schema": CAPTURE_SCHEMA,
        "capture": {key: capture[key] for key in
                    ("capture_id", "platform", "original_pe_sha256",
                     "method", "observed_at", "independently_signed")},
        "events": events,
    }
    try:
        validate_trace(trace)
    except RuntimeTraceError as exc:
        raise PrivateExportError("Inconsistent captured event sequence: " + str(exc))

    supplied_pairs = manifest.get("pairs", [])
    if not isinstance(supplied_pairs, list) or len(supplied_pairs) > MAX_SAMPLES:
        raise PrivateExportError("Invalid paired sample count")
    result_pairs = []
    seen_ids, seen_offsets = set(), set()
    for pair in supplied_pairs:
        if not isinstance(pair, dict):
            raise PrivateExportError("Invalid paired sample")
        label = pair.get("sample_id")
        if not isinstance(label, str) or not PATH_LABEL.fullmatch(label) or label in seen_ids:
            raise PrivateExportError("Invalid or duplicate sample identifier")
        seen_ids.add(label)
        seq = integer(pair.get("read_seq"), 1, 100000000, "sample read sequence")
        if seq not in reads:
            raise PrivateExportError("Sample not linked to ReadFile event")
        pid, handle, read_payload = reads[seq]
        if pair.get("pid") != pid or (not isinstance(pair.get("handle"), str)
                                     or not HANDLE.fullmatch(pair["handle"])
                                     or int(pair["handle"], 16) != handle):
            raise PrivateExportError("Sample PID/handle does not match read")
        at = integer(pair.get("offset_in_read"), 0, len(read_payload),
                     "position within ReadFile")
        block = integer(pair.get("byte_index_in_transform_block"), 0, 0xffffffff,
                        "transform-block byte index")
        before = dump_bytes(root, pair.get("pre_transform_dump"), MAX_SAMPLE_BYTES)
        after = dump_bytes(root, pair.get("post_transform_dump"), MAX_SAMPLE_BYTES)
        if len(before) != len(after) or at + len(before) > len(read_payload):
            raise PrivateExportError("Invalid paired-buffer lengths")
        if read_payload[at:at + len(before)] != before:
            raise PrivateExportError("Pre-XOR bytes differ from corresponding ReadFile dump")
        if block + len(before) > 0xffffffff:
            raise PrivateExportError("Transform index overflow")
        if any((seq, idx) in seen_offsets for idx in range(at, at + len(before))):
            raise PrivateExportError("Overlapping paired-byte sample")
        seen_offsets.update((seq, idx) for idx in range(at, at + len(before)))
        # An observed flag or key must be measured, not synthesized.
        words = {}
        for key in ("primary_words", "secondary_words", "active_words"):
            value = pair.get(key)
            if not isinstance(value, list) or len(value) != 4 or any(
                    type(v) is not int or not 0 <= v <= 0xffffffff for v in value):
                raise PrivateExportError("Invalid observed key DWORDs")
            words[key] = value
        flag = integer(pair.get("owner_flag_0x60"), 0, 0xffffffff, "observed flag")
        state = integer(pair.get("state_kind"), 0, 0xffffffff, "state kind")
        if type(pair.get("branch_observed")) is not bool:
            raise PrivateExportError("Missing observed branch Boolean")
        source = pair.get("reported_key_source")
        if source not in KEY_SOURCES:
            raise PrivateExportError("Invalid key-source label")
        result_pairs.append({
            "sample_id": label, "read_seq": seq, "pid": pid,
            "handle": pair["handle"], "offset_in_read": at,
            "byte_index_in_transform_block": block,
            "pre_hex": before.hex(), "post_hex": after.hex(),
            "owner_flag_0x60": flag, "state_kind": state,
            "branch_observed": pair["branch_observed"],
            "reported_key_source": source, **words,
        })
    pairs_doc = {"schema": PAIR_SCHEMA, "capture_id": capture["capture_id"],
                 "samples": result_pairs}
    return trace, pairs_doc


def exclusive_private_json(path, document, root):
    target = pathlib.Path(path)
    if root not in target.resolve().parents:
        raise PrivateExportError("Output must reside beneath private root")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    handle = os.open(str(target), flags, 0o600)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(document, stream, sort_keys=True, indent=2)
            stream.write("\n")
    except Exception:
        try:
            target.unlink()
        except OSError:
            pass
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, help="Private raw dump index")
    parser.add_argument("--private-root", required=True, help="Protected local directory")
    parser.add_argument("--trace-json", required=True, help="New private trace JSON")
    parser.add_argument("--pairs-json", help="New private pairs JSON (contains RAW HEX)")
    args = parser.parse_args(argv)
    try:
        root = pathlib.Path(args.private_root).resolve(strict=True)
        index = relative_private(root, str(pathlib.Path(args.manifest).resolve().relative_to(root)))
        if index.stat().st_size > MAX_MANIFEST:
            raise PrivateExportError("Raw dump manifest too large")
        raw = json.loads(index.read_text(encoding="utf-8"))
        trace, pairs = export(raw, root)
        if pairs["samples"] and not args.pairs_json:
            raise PrivateExportError("--pairs-json required when paired bytes exist")
        if args.pairs_json and pathlib.Path(args.pairs_json).resolve() == \
                pathlib.Path(args.trace_json).resolve():
            raise PrivateExportError("Trace and pair output paths must differ")
        exclusive_private_json(args.trace_json, trace, root)
        if args.pairs_json:
            try:
                exclusive_private_json(args.pairs_json, pairs, root)
            except Exception:
                pathlib.Path(args.trace_json).unlink()
                raise
        print("REA-015/T: local files assembled; open=%d read=%d close=%d pairs=%d; AUTHENTICATION=UNVERIFIED" %
              (sum(x["kind"] == "open" for x in trace["events"]),
               sum(x["kind"] == "read" for x in trace["events"]),
               sum(x["kind"] == "close" for x in trace["events"]), len(pairs["samples"])))
        return 0
    except (OSError, ValueError, UnicodeError) as exc:
        print("REA-015/T export ERROR: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
