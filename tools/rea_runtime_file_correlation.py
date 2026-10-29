#!/usr/bin/env python3
"""REA-015/N — offline correlation of Win7 file I/O evidence with pinned resources.

The input is a LOCAL, manually captured trace. It NEVER instruments or runs
Deep Freeze; it never exports source PE bytes, file paths, or payload slices.
It compares observed file-level SHA256 and individual ReadFile-return buffer
SHA256 to independently extracted original resource bytes.

A trace is self-reported and is NOT an authenticated runtime observation.
Matching bytes cannot establish whether an original installer actually ran.
Certification requires independently reviewed and signed VM evidence.
Python 3.8+, stdlib.
"""
import argparse
import hashlib
import json
import pathlib
import re
import sys
import zipfile

from .rea_structural import PEView, PEError, MAX_PE
from .rea_overlay_inventory import (
    ZIP_SHA, ROOT_SHA, ROOT_MEMBER, CHILD_RESOURCE, CHILD_SHA, OVERLAY_SHA,
)

SHA = re.compile(r"^[0-9a-f]{64}$")
HANDLE = re.compile(r"^0x[0-9a-fA-F]{1,16}$")
MAX_EVENTS = 512
MAX_READ = 1024 * 1024
MAX_TRACE = 2 * 1024 * 1024


class RuntimeTraceError(ValueError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def extract_reference(archive_path):
    """Extract only in memory, with original checksums and bounded members."""
    archive_path = pathlib.Path(archive_path)
    hash_state = hashlib.sha256()
    with archive_path.open("rb") as handle:
        for part in iter(lambda: handle.read(1048576), b""):
            hash_state.update(part)
    if hash_state.hexdigest() != ZIP_SHA:
        raise RuntimeTraceError("Pinned source ZIP SHA-256 mismatch")
    with zipfile.ZipFile(archive_path) as z:
        matches = [x for x in z.infolist() if x.filename == ROOT_MEMBER]
        if len(matches) != 1 or matches[0].flag_bits & 1 or matches[0].file_size > MAX_PE:
            raise RuntimeTraceError("Expected unique, bounded original PE")
        with z.open(matches[0]) as handle:
            main = handle.read(MAX_PE + 1)
        if len(main) != matches[0].file_size or digest(main) != ROOT_SHA:
            raise RuntimeTraceError("Root executable SHA-256 mismatch")
    found = [r for r in PEView(main).resources(depth=1)
             if "/".join(r["path"]) == CHILD_RESOURCE]
    if len(found) != 1:
        raise RuntimeTraceError("Missing unique CLOUD_INSTALLER resource")
    resource = found[0]
    pos, size = resource["file_offset"], resource["size"]
    if pos < 0 or size > MAX_PE or pos+size > len(main):
        raise RuntimeTraceError("Resource bounds invalid")
    child = main[pos:pos+size]
    if resource["sha256"] != CHILD_SHA or digest(child) != CHILD_SHA:
        raise RuntimeTraceError("CLOUD_INSTALLER resource checksum changed")
    view = PEView(child)
    sections = [s for s in view.sections if s["raw_size"]]
    if not sections:
        raise RuntimeTraceError("Embedded PE has no physical sections")
    end = max(s["offset"]+s["raw_size"] for s in sections)
    cert_off, cert_len = view.directory(4)
    if cert_off or cert_len:
        if not cert_off or not cert_len or cert_off+cert_len > len(child):
            raise RuntimeTraceError("Invalid certificate directory")
        end = max(end, cert_off+cert_len)
    overlay = child[end:]
    if digest(overlay) != OVERLAY_SHA or len(overlay) < 104:
        raise RuntimeTraceError("CLOUD_INSTALLER overlay checksum changed")
    return {"child_pe": child, "overlay": overlay, "overlay_offset_in_pe": end}


def integer(value, minimum, maximum, label):
    if type(value) is not int or not minimum <= value <= maximum:
        raise RuntimeTraceError("Invalid "+label)
    return value


def validate_trace(trace):
    if not isinstance(trace, dict) or trace.get("schema") != "rea-015-file-io-observation-v1":
        raise RuntimeTraceError("Unrecognized local observation schema")
    capture = trace.get("capture")
    if not isinstance(capture, dict):
        raise RuntimeTraceError("Missing VM capture metadata")
    if capture.get("platform") not in ("windows7-sp1-x86", "windows7-sp1-x64"):
        raise RuntimeTraceError("Expected isolated Win7 SP1 architecture")
    if capture.get("original_pe_sha256") != ROOT_SHA:
        raise RuntimeTraceError("Capture does not pin original PE")
    for field in ("capture_id", "method", "observed_at"):
        if (not isinstance(capture.get(field), str) or
                not 1 <= len(capture[field]) <= 256):
            raise RuntimeTraceError("Missing capture provenance: "+field)
    if capture.get("independently_signed") is not False:
        raise RuntimeTraceError("Signature status cannot be self-asserted")
    events = trace.get("events")
    if not isinstance(events, list) or not 1 <= len(events) <= MAX_EVENTS:
        raise RuntimeTraceError("Invalid event count")
    seen_seq = 0
    live = {}
    events_out = []
    for e in events:
        if not isinstance(e, dict):
            raise RuntimeTraceError("Malformed trace event")
        seq = integer(e.get("seq"), 1, 100000000, "sequence")
        if seq <= seen_seq:
            raise RuntimeTraceError("Events must have strictly increasing sequence")
        seen_seq = seq
        kind, handle = e.get("kind"), e.get("handle")
        pid = integer(e.get("pid"), 1, 0xffffffff, "pid")
        if not isinstance(handle, str) or not HANDLE.fullmatch(handle):
            raise RuntimeTraceError("Invalid process-local handle")
        key = (pid, int(handle, 16))
        if kind == "open":
            if key in live:
                raise RuntimeTraceError("Handle reopened before close")
            if e.get("api") != "CreateFileA":
                raise RuntimeTraceError("Open must be a CreateFileA observation")
            if e.get("result") != "success":
                raise RuntimeTraceError("Only successful opens establish a handle")
            if not isinstance(e.get("path_redacted"), str) or not e["path_redacted"]:
                raise RuntimeTraceError("Missing redacted path label")
            if not SHA.fullmatch(str(e.get("file_sha256", ""))):
                raise RuntimeTraceError("File needs a full independent SHA-256")
            sz = integer(e.get("file_size"), 1, MAX_PE, "file_size")
            live[key] = {"file_sha256": e["file_sha256"],
                         "file_size": sz, "opening_seq": seq,
                         "path_label": e["path_redacted"]}
        elif kind == "read":
            if key not in live:
                raise RuntimeTraceError("Read without observed open/handle")
            if e.get("api") != "ReadFile" or e.get("result") != "success":
                raise RuntimeTraceError("Read must be a successful ReadFile observation")
            offset = integer(e.get("file_offset"), 0, MAX_PE, "file_offset")
            length = integer(e.get("bytes_returned"), 1, MAX_READ, "read length")
            if offset+length > live[key]["file_size"]:
                raise RuntimeTraceError("Read extends past observed file")
            if not SHA.fullmatch(str(e.get("buffer_sha256", ""))):
                raise RuntimeTraceError("Missing SHA-256 of ReadFile output buffer")
            events_out.append({"event": e, "open": dict(live[key])})
        elif kind == "close":
            if key not in live:
                raise RuntimeTraceError("Close without observed open")
            if e.get("api") != "CloseHandle":
                raise RuntimeTraceError("Close event API mismatch")
            del live[key]
        else:
            raise RuntimeTraceError("Unexpected I/O event kind")
    return events_out


def region(overlay_pos, size, total):
    if overlay_pos < 0 or overlay_pos+size > total:
        return "not_overlay"
    if overlay_pos+size <= 96:
        return "header"
    if overlay_pos >= total-8:
        return "trailer"
    if overlay_pos >= 96 and overlay_pos+size <= total-8:
        return "body"
    return "crosses_regions"


def interval_union_size(intervals):
    end, size = 0, 0
    for lo, hi in sorted(intervals):
        if hi <= end:
            continue
        size += hi-max(lo, end)
        end = hi
    return size


def correlate(trace, resources):
    """Only hash comparisons; does not authenticate user-supplied VM records."""
    reads = validate_trace(trace)
    child, overlay = resources["child_pe"], resources["overlay"]
    start = resources["overlay_offset_in_pe"]
    result = []
    matches = 0
    matched_body_ranges = []
    file_match = False
    for item in reads:
        event, opened = item["event"], item["open"]
        observed_sha = opened["file_sha256"]
        observed_size = opened["file_size"]
        if observed_sha == CHILD_SHA and observed_size == len(child):
            kind, payload, overlay_base = "child_pe", child, start
        elif observed_sha == OVERLAY_SHA and observed_size == len(overlay):
            kind, payload, overlay_base = "overlay", overlay, 0
        else:
            kind, payload, overlay_base = "unidentified_file", None, None
        file_match = file_match or payload is not None
        match = (payload is not None and
                 digest(payload[event["file_offset"]:event["file_offset"]+
                                event["bytes_returned"]]) == event["buffer_sha256"])
        if match:
            matches += 1
        pos = event["file_offset"]-overlay_base if overlay_base is not None else -1
        label = region(pos, event["bytes_returned"], len(overlay))
        if match and label == "body":
            matched_body_ranges.append((pos, pos+event["bytes_returned"]))
        result.append({
            "seq": event["seq"], "pid": event["pid"], "kind": kind,
            "read_offset": event["file_offset"],
            "read_bytes": event["bytes_returned"],
            "overlay_region": label,
            "read_bytes_match_expected_sha256": bool(match),
        })
    covered = interval_union_size(matched_body_ranges)
    return {
        "schema": "rea-015-file-io-correlation-v1",
        "capture_id": trace["capture"]["capture_id"],
        "platform": trace["capture"]["platform"],
        "source_zip_sha256": ZIP_SHA,
        "child_resource_sha256": CHILD_SHA,
        "overlay_sha256": OVERLAY_SHA,
        "overlay_file_offset_in_child_pe": start,
        "reads_reported": len(reads),
        "reads_matching_expected_bytes": matches,
        "read_event_checks": result,
        "matched_body_unique_bytes": covered,
        "opaque_body_total_bytes": len(overlay)-104,
        "opened_file_hash_consistent_with_reference": file_match,
        "claimed_trace_authentication": "unverified",
        "original_executable_run_verified": False,
        "file_handle_to_cloud_resource_proven": False,
        "transformation_applied_to_body_proven": False,
        "win7_semantic_equivalence_verified": False,
        "certification_receipt_created": False,
        "status": "LOCAL_HASH_CONSISTENCY_ONLY_NOT_RUNTIME_PROOF",
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive", required=True)
    p.add_argument("--trace", required=True,
                   help="Local sanitized manual capture JSON (never commit raw traces)")
    p.add_argument("--json", help="Local comparison result JSON")
    args = p.parse_args(argv)
    try:
        trace_file = pathlib.Path(args.trace)
        if trace_file.stat().st_size > MAX_TRACE:
            raise RuntimeTraceError("Local capture manifest too large")
        trace = json.loads(trace_file.read_text(encoding="utf-8"))
        result = correlate(trace, extract_reference(args.archive))
        report = json.dumps(result, sort_keys=True, indent=2)+"\n"
        if args.json:
            pathlib.Path(args.json).write_text(report, encoding="utf-8")
        else:
            print(report, end="")
        return 0
    except (OSError, ValueError, PEError, zipfile.BadZipFile) as exc:
        print("REA Win7 capture correlation ERROR: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
