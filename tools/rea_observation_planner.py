#!/usr/bin/env python3
"""REA-015/Q: suggest bounded observation targets from an untrusted correlation JSON.

No Windows execution, raw sample extraction, automatic reads, or certification.
All offsets are half-open and overlay-relative unless explicitly labelled.
Python 3.8+; standard library only.
"""
import argparse
import json
import pathlib
import sys

from .rea_overlay_inventory import ZIP_SHA, CHILD_SHA, OVERLAY_SHA

SOURCE_SCHEMA = "rea-015-file-io-correlation-v1"
SOURCE_STATUS = "LOCAL_HASH_CONSISTENCY_ONLY_NOT_RUNTIME_PROOF"
MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_BODY_BYTES = 128 * 1024 * 1024
MAX_RANGES = 1025
MAX_TARGETS = 32
MAX_WINDOW_BYTES = 1024 * 1024


class ObservationPlanError(ValueError):
    pass


def count(value, minimum, maximum, field):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ObservationPlanError("Invalid " + field)
    return value


def validate_correlation(report):
    """Validate provenance labels and arithmetic, not actual VM authenticity."""
    if not isinstance(report, dict) or report.get("schema") != SOURCE_SCHEMA:
        raise ObservationPlanError("Unknown correlation schema")
    if report.get("status") != SOURCE_STATUS:
        raise ObservationPlanError("Only unverified offline correlations are accepted")
    for key, expected in (("source_zip_sha256", ZIP_SHA),
                          ("child_resource_sha256", CHILD_SHA),
                          ("overlay_sha256", OVERLAY_SHA)):
        if report.get(key) != expected:
            raise ObservationPlanError("Source identity mismatch: " + key)
    for key in ("original_executable_run_verified",
                "file_handle_to_cloud_resource_proven",
                "transformation_applied_to_body_proven",
                "win7_semantic_equivalence_verified",
                "certification_receipt_created"):
        if report.get(key) is not False:
            raise ObservationPlanError("Unsupported runtime or certification claim: " + key)
    if report.get("claimed_trace_authentication") != "unverified":
        raise ObservationPlanError("Untrusted trace cannot assert authentication")
    body_size = count(report.get("opaque_body_total_bytes"), 1, MAX_BODY_BYTES,
                      "opaque_body_total_bytes")
    child_start = count(report.get("overlay_file_offset_in_child_pe"),
                        0, MAX_BODY_BYTES, "overlay_file_offset_in_child_pe")
    covered = count(report.get("matched_body_unique_bytes"), 0, body_size,
                    "matched_body_unique_bytes")
    missing = count(report.get("missing_body_unique_bytes"), 0, body_size,
                    "missing_body_unique_bytes")
    if covered + missing != body_size:
        raise ObservationPlanError("Body coverage totals disagree")
    raw = report.get("missing_body_ranges_overlay_relative")
    if not isinstance(raw, list) or len(raw) > MAX_RANGES:
        raise ObservationPlanError("Invalid missing range list")
    end = 96 + body_size
    ranges = []
    previous_end = 96
    for item in raw:
        if not isinstance(item, list) or len(item) != 2:
            raise ObservationPlanError("Invalid missing interval")
        lo = count(item[0], 96, end, "interval start")
        hi = count(item[1], 96, end, "interval end")
        if lo < previous_end or hi <= lo:
            raise ObservationPlanError("Missing intervals overlap, are unsorted or empty")
        if ranges and lo == previous_end:
            raise ObservationPlanError("Adjacent missing intervals must be coalesced")
        ranges.append((lo, hi))
        previous_end = hi
    if sum(hi - lo for lo, hi in ranges) != missing:
        raise ObservationPlanError("Missing interval sizes disagree")
    return child_start, body_size, ranges


def available_segments(lo, hi, chosen):
    """Subtract already targeted windows within a missing interval."""
    segments = []
    cursor = lo
    for s, e in sorted(chosen):
        if e <= cursor or s >= hi:
            continue
        if s > cursor:
            segments.append((cursor, min(s, hi)))
        cursor = max(cursor, min(e, hi))
        if cursor >= hi:
            break
    if cursor < hi:
        segments.append((cursor, hi))
    return segments


def choose_windows(ranges, limit, window_bytes):
    """Distribute initial targets across gaps, then target largest uncovered spans."""
    limit = count(limit, 1, MAX_TARGETS, "max_targets")
    window_bytes = count(window_bytes, 1, MAX_WINDOW_BYTES, "window_bytes")
    priority_ranges = sorted(ranges, key=lambda r: (-(r[1] - r[0]), r[0]))
    chosen = []
    reason = []
    for phase in ("start", "middle", "end"):
        for lo, hi in priority_ranges:
            if len(chosen) >= limit:
                break
            segments = available_segments(lo, hi, chosen)
            if not segments:
                continue
            if phase == "start":
                a, b = segments[0]
                start = a
            elif phase == "end":
                a, b = segments[-1]
                start = max(a, b - window_bytes)
            else:
                center = (lo + hi) / 2.0
                a, b = min(segments, key=lambda seg:
                           (abs((seg[0] + seg[1]) / 2.0 - center), seg[0]))
                start = a + max(0, (b - a - window_bytes) // 2)
            stop = min(b, start + window_bytes)
            chosen.append((start, stop))
            reason.append(phase + "_of_unverified_gap")
        if len(chosen) >= limit:
            break
    while len(chosen) < limit:
        remaining = [part for lo, hi in ranges
                     for part in available_segments(lo, hi, chosen)]
        if not remaining:
            break
        a, b = min(remaining, key=lambda r: (-(r[1] - r[0]), r[0]))
        start = a + max(0, (b - a - window_bytes) // 2)
        stop = min(b, start + window_bytes)
        chosen.append((start, stop))
        reason.append("largest_untargeted_gap")
    return [(a, b, why) for (a, b), why in zip(chosen, reason)]


def plan(report, max_targets=12, window_bytes=65536):
    child_start, body_size, gaps = validate_correlation(report)
    windows = choose_windows(gaps, max_targets, window_bytes)
    overlay_size = 96 + body_size + 8

    def target(lo, hi, reason):
        return {"reason": reason, "overlay_range": [lo, hi],
                "if_opened_child_pe_file_offsets": [child_start + lo, child_start + hi],
                "if_opened_standalone_overlay_file_offsets": [lo, hi]}

    body = [target(lo, hi, reason) for lo, hi, reason in windows]
    total = sum(hi - lo for lo, hi, _ in windows)
    return {
        "schema": "rea-015-observation-plan-v1",
        "status": "PLANNING_ONLY_NOT_RUNTIME_PROOF",
        "source_correlation_schema": SOURCE_SCHEMA,
        "capture_id_label": report.get("capture_id") if isinstance(
            report.get("capture_id"), str) else None,
        "source_zip_sha256": ZIP_SHA,
        "opaque_body_classification": "unknown",
        "body_total_bytes": body_size,
        "hash_consistent_body_bytes_reported": report["matched_body_unique_bytes"],
        "missing_body_bytes_reported": report["missing_body_unique_bytes"],
        "observation_targets_are_not_forced_reads": True,
        "context_targets": [
            target(0, 96, "frame_header"),
            target(overlay_size - 8, overlay_size, "frame_trailer")],
        "body_targets": body,
        "body_bytes_targeted_unique": total,
        "missing_bytes_not_targeted": report["missing_body_unique_bytes"] - total,
        "contracts_requiring_original_evidence": [
            {"id": "REA015Q-FILE", "need": "authenticated CreateFileA PID, handle and opened-file identity"},
            {"id": "REA015Q-READ", "need": "ReadFile offsets, bytes returned and pre-transformation buffer digests"},
            {"id": "REA015Q-TRANSFORM", "need": "branch flag, XOR key provenance and paired pre/post buffers"},
            {"id": "REA015Q-FORMAT", "need": "decoded body layout, extracted module hashes and structure checks"},
            {"id": "REA015Q-X86X64", "need": "independent authorized Win7 x86/x64 equivalence evidence"}],
        "runtime_evidence_verified": False,
        "semantic_equivalence_verified": False,
        "certification_receipt_created": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--correlation", required=True, help="Local sanitized correlation JSON")
    parser.add_argument("--json", help="Local output path; stdout if omitted")
    parser.add_argument("--max-targets", type=int, default=12)
    parser.add_argument("--window-bytes", type=int, default=65536)
    args = parser.parse_args(argv)
    try:
        source = pathlib.Path(args.correlation)
        if source.stat().st_size > MAX_INPUT_BYTES:
            raise ObservationPlanError("Correlation JSON exceeds size limit")
        report = json.loads(source.read_text(encoding="utf-8"))
        result = plan(report, args.max_targets, args.window_bytes)
        output = json.dumps(result, sort_keys=True, indent=2) + "\n"
        if args.json:
            pathlib.Path(args.json).write_text(output, encoding="utf-8")
        else:
            print(output, end="")
        return 0
    except (OSError, ValueError, UnicodeError) as exc:
        print("REA-015/Q observation planning ERROR: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
