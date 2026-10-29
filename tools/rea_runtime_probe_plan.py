#!/usr/bin/env python3
"""REA-015/O: deterministic next-probe planner for UNAUTHENTICATED correlation reports.

Never launches the sample, reads proprietary payloads, or certifies execution.
Python 3.8+, standard library only.
"""
import argparse
import json
from pathlib import Path

SCHEMA = "rea-015-file-io-correlation-v1"
BODY_START = 96
TRAILER = 8
MAX_REPORT = 2 * 1024 * 1024
MAX_PROBES = 32


class ProbePlanError(ValueError):
    pass


def _int(value, minimum, maximum, name):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ProbePlanError("Invalid " + name)
    return value


def _intervals(report, kind, overlay_start, total):
    """Only verified body reads may count as coverage; merge overlapping intervals."""
    intervals = []
    for row in report["read_event_checks"]:
        if not isinstance(row, dict):
            raise ProbePlanError("Malformed read row")
        if row.get("kind") != kind or row.get("read_bytes_match_expected_sha256") is not True:
            continue
        offset = _int(row.get("read_offset"), 0, 1 << 31, "read offset") - overlay_start
        length = _int(row.get("read_bytes"), 1, 1 << 20, "read length")
        lo, hi = max(offset, BODY_START), min(offset + length, total - TRAILER)
        if lo < hi:
            intervals.append((lo, hi))
    merged = []
    for lo, hi in sorted(intervals):
        if merged and lo <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(hi, merged[-1][1]))
        else:
            merged.append((lo, hi))
    return merged


def _gaps(lo, hi, intervals):
    cur = lo
    out = []
    for begin, end in intervals:
        if end <= cur:
            continue
        if begin > cur:
            out.append((cur, min(begin, hi)))
        cur = max(cur, end)
        if cur >= hi:
            break
    if cur < hi:
        out.append((cur, hi))
    return [(a, b) for a, b in out if a < b]


def build_plan(report, window=4096, limit=12):
    if not isinstance(report, dict) or report.get("schema") != SCHEMA:
        raise ProbePlanError("Expected a correlation report")
    checks = report.get("read_event_checks")
    if not isinstance(checks, list) or len(checks) > 512:
        raise ProbePlanError("Invalid read checks")
    total_body = _int(report.get("opaque_body_total_bytes"), 1, 1 << 31, "body size")
    overlay_start = _int(report.get("overlay_file_offset_in_child_pe"), 0, 1 << 31, "overlay offset")
    window = _int(window, 1, 1 << 20, "window")
    limit = _int(limit, 1, MAX_PROBES, "limit")
    total = total_body + BODY_START + TRAILER
    candidates = []
    for kind, base in (("child_pe", overlay_start), ("overlay", 0)):
        intervals = _intervals(report, kind, base, total)
        occupied = intervals[:]
        probes = []
        # High-value boundary checks first, then representative body regions.
        anchors = [
            ("header", 0, BODY_START),
            ("trailer", total - TRAILER, total),
            ("body_first", BODY_START, min(total - TRAILER, BODY_START + window)),
            ("body_middle", BODY_START + max(0, (total_body - window) // 2),
             min(total - TRAILER, BODY_START + max(0, (total_body - window) // 2) + window)),
            ("body_last", max(BODY_START, total - TRAILER - window), total - TRAILER),
        ]
        for reason, lo, hi in anchors:
            if reason.startswith("body"):
                missing = _gaps(lo, hi, occupied)
                if not missing:
                    continue
                lo, hi = max(missing, key=lambda x: x[1] - x[0])
                occupied.append((lo, hi))
                occupied.sort()
            probes.append({"reason": reason, "file_offset": base + lo, "bytes_requested": hi - lo})
        # Fill remaining budget using the largest uncovered body gap.
        while len(probes) < limit:
            gaps = _gaps(BODY_START, total - TRAILER, sorted(occupied))
            if not gaps:
                break
            lo, hi = max(gaps, key=lambda x: (x[1] - x[0], -x[0]))
            start = lo + max(0, ((hi - lo) - window) // 2)
            end = min(start + window, hi)
            occupied.append((start, end))
            occupied.sort()
            probes.append({"reason": "body_gap", "file_offset": base + start,
                           "bytes_requested": end - start})
        candidates.append({"file_identity_hypothesis": kind, "probes": probes[:limit],
                           "previously_matched_body_bytes": sum(b-a for a,b in intervals)})
    return {
        "schema": "rea-015-targeted-probe-plan-v1",
        "source_capture_id": report.get("capture_id"),
        "authentication": "UNVERIFIED_SELF_REPORTED_TRACE",
        "purpose": "PLAN_ONLY_NOT_RUNTIME_PROOF",
        "probe_offsets_are_absolute_in_opened_file": True,
        "candidates_not_asserted_as_observed": candidates,
        "notes": [
            "Use only for authorized offline/isolated VM observations.",
            "Do not fabricate PID, handles, offsets, hashes or file-open events.",
            "The probe planner cannot force the original program to read suggested offsets.",
            "The original process may never access some proposed intervals.",
            "ReadFile hashes must come from the original call output, before transformation.",
            "No certification receipt is produced.",
        ],
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--correlation", required=True, help="Local correlator JSON result")
    p.add_argument("--json", help="Output proposal (metadata only)")
    p.add_argument("--window", type=int, default=4096)
    p.add_argument("--limit", type=int, default=12)
    args = p.parse_args(argv)
    try:
        source = Path(args.correlation)
        if source.stat().st_size > MAX_REPORT:
            raise ProbePlanError("Report too large")
        report = json.loads(source.read_text(encoding="utf-8"))
        plan = build_plan(report, args.window, args.limit)
        result = json.dumps(plan, indent=2, sort_keys=True) + "\n"
        if args.json:
            Path(args.json).write_text(result, encoding="utf-8")
        else:
            print(result, end="")
        return 0
    except (ValueError, OSError) as exc:
        p.exit(1, "REA probe planner ERROR: %s\n" % exc)


if __name__ == "__main__":
    main()
