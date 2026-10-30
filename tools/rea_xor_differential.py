#!/usr/bin/env python3
"""REA-015/R: offline consistency checks for bounded pre/post-XOR samples.

All paired bytes must remain in private local input files. This tool neither
executes the original installer nor authenticates user-supplied runtime claims.
Even a fully matching sample is NOT behavioral equivalence or certification.
Python 3.8+, standard library only.
"""
import argparse
import hashlib
import json
import pathlib
import re
import sys

from .rea_runtime_file_correlation import (
    correlate, digest, extract_reference, interval_union_size, validate_trace,
    RuntimeTraceError,
)
from .rea_transform_state import candidate_key_byte, derive_state_word, select_words

SCHEMA = "rea-015-xor-paired-observation-v1"
MAX_SAMPLES = 64
MAX_SAMPLE_BYTES = 4096
MAX_INPUT_BYTES = 2 * 1024 * 1024
UINT32_MAX = 0xffffffff
HEX = re.compile(r"^[0-9a-f]*$")
SAMPLE_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
KEY_SOURCE_KINDS = ("caller_string", "localtime_fallback", "unknown")


class DifferentialEvidenceError(ValueError):
    pass


def integer(value, lower, upper, name):
    if type(value) is not int or not lower <= value <= upper:
        raise DifferentialEvidenceError("Invalid " + name)
    return value


def word_vector(value, name):
    if not isinstance(value, list) or len(value) != 4:
        raise DifferentialEvidenceError("Expected 4 DWORDs for " + name)
    return tuple(integer(v, 0, UINT32_MAX, name) for v in value)


def parse_hex(value, name):
    if not isinstance(value, str) or not value or len(value) > 2 * MAX_SAMPLE_BYTES:
        raise DifferentialEvidenceError("Invalid bounded " + name)
    if len(value) % 2 or not HEX.fullmatch(value):
        raise DifferentialEvidenceError("Invalid hexadecimal " + name)
    return bytes.fromhex(value)


def analyze_pairs(trace, samples, resources):
    """Compare reported pair bytes to pinned source and a synthetic key model.

    Correlation and this function both validate syntax/consistency only.
    Neither can establish that the provided pairs came from actual execution.
    """
    reads = validate_trace(trace)
    correlation = correlate(trace, resources)
    if not isinstance(samples, dict) or samples.get("schema") != SCHEMA:
        raise DifferentialEvidenceError("Unknown paired-observation schema")
    if samples.get("capture_id") != trace["capture"]["capture_id"]:
        raise DifferentialEvidenceError("Capture label does not match trace")
    pairs = samples.get("samples")
    if not isinstance(pairs, list) or not 1 <= len(pairs) <= MAX_SAMPLES:
        raise DifferentialEvidenceError("Invalid pair count")
    checks = {e["seq"]: e for e in correlation["read_event_checks"]}
    records = {e["event"]["seq"]: e["event"] for e in reads}
    seen_ids = set()
    seen_segments = []
    output = []
    accepted_ranges = []
    overlay = resources["overlay"]
    body_end = len(overlay) - 8
    overlay_start_in_pe = resources["overlay_offset_in_pe"]

    for pair in pairs:
        if not isinstance(pair, dict):
            raise DifferentialEvidenceError("Invalid paired observation record")
        sample_id = pair.get("sample_id")
        if not isinstance(sample_id, str) or not SAMPLE_ID.fullmatch(sample_id):
            raise DifferentialEvidenceError("Invalid sample identifier")
        if sample_id in seen_ids:
            raise DifferentialEvidenceError("Duplicate sample identifier")
        seen_ids.add(sample_id)

        seq = integer(pair.get("read_seq"), 1, 100000000, "read sequence")
        if seq not in records:
            raise DifferentialEvidenceError("Paired sample has no original read event")
        read = records[seq]
        if pair.get("pid") != read["pid"] or pair.get("handle") != read["handle"]:
            raise DifferentialEvidenceError("PID/handle does not match original read")
        start_in_read = integer(pair.get("offset_in_read"), 0, UINT32_MAX,
                                "offset within ReadFile output")
        start_in_block = integer(pair.get("byte_index_in_transform_block"),
                                 0, UINT32_MAX, "transform block byte index")
        pre = parse_hex(pair.get("pre_hex"), "pre-transform bytes")
        post = parse_hex(pair.get("post_hex"), "post-transform bytes")
        if len(pre) != len(post):
            raise DifferentialEvidenceError("Unequal pre/post sample sizes")
        if start_in_read + len(pre) > read["bytes_returned"]:
            raise DifferentialEvidenceError("Sample exceeds the corresponding read")
        if start_in_block + len(pre) > UINT32_MAX:
            raise DifferentialEvidenceError("Transform block index overflow")
        for other_seq, a, b in seen_segments:
            if other_seq == seq and start_in_read < b and a < start_in_read + len(pre):
                raise DifferentialEvidenceError("Overlapping samples of one read")
        seen_segments.append((seq, start_in_read, start_in_read + len(pre)))

        checked_read = checks[seq]
        if checked_read["kind"] == "child_pe":
            base = overlay_start_in_pe
            payload = resources["child_pe"]
        elif checked_read["kind"] == "overlay":
            base = 0
            payload = overlay
        else:
            base = None
            payload = None
        file_start = read["file_offset"] + start_in_read
        overlay_pos = file_start - base if base is not None else -1
        if base is not None and not (96 <= overlay_pos and
                                     overlay_pos + len(pre) <= body_end):
            raise DifferentialEvidenceError("Paired sample must be inside opaque body")

        source_matches = (
            payload is not None and
            payload[file_start:file_start + len(pre)] == pre and
            checked_read["read_bytes_match_expected_sha256"]
        )
        owner_flag = integer(pair.get("owner_flag_0x60"), 0, UINT32_MAX,
                             "owner+0x60 flag")
        primary = word_vector(pair.get("primary_words"), "primary key")
        secondary = word_vector(pair.get("secondary_words"), "secondary key")
        active = word_vector(pair.get("active_words"), "active key")
        state_kind = integer(pair.get("state_kind"), 0, UINT32_MAX,
                             "transform state kind")
        if type(pair.get("branch_observed")) is not bool:
            raise DifferentialEvidenceError("Observed branch must be Boolean")
        if pair.get("reported_key_source") not in KEY_SOURCE_KINDS:
            raise DifferentialEvidenceError("Unknown key source label")

        selected = select_words(primary, secondary)
        selected_consistent = active == selected
        should_transform = bool((owner_flag & 1) and any(selected) and
                                state_kind == 1)
        branch_consistent = should_transform == pair["branch_observed"]
        if should_transform:
            seed = derive_state_word(selected)
            candidate = bytes(v ^ candidate_key_byte(seed, start_in_block + idx)
                              for idx, v in enumerate(pre))
        else:
            candidate = pre
        model_matches = candidate == post
        consistent = bool(source_matches and selected_consistent and
                          branch_consistent and model_matches)
        if consistent:
            accepted_ranges.append((overlay_pos, overlay_pos + len(pre)))
        output.append({
            "sample_id": sample_id,
            "read_seq": seq,
            "overlay_body_range": ([overlay_pos, overlay_pos + len(pre)]
                                   if base is not None else None),
            "sample_length": len(pre),
            "read_correlated_to_pinned_source": bool(
                checked_read["read_bytes_match_expected_sha256"]),
            "pre_sample_matches_pinned_source": bool(source_matches),
            "active_key_matches_static_selection_rule": selected_consistent,
            "branch_matches_static_candidate_rule": branch_consistent,
            "candidate_model_matches_reported_post": model_matches,
            "paired_sample_consistent": consistent,
            "pre_sha256": digest(pre),
            "reported_post_sha256": digest(post),
            "candidate_post_sha256": digest(candidate),
            "reported_key_source": pair["reported_key_source"],
            "key_origin_verified": False,
            "actual_branch_execution_authenticated": False,
        })
    return {
        "schema": "rea-015-xor-differential-report-v1",
        "status": "LOCAL_PAIRED_BUFFER_CONSISTENCY_ONLY_NOT_RUNTIME_PROOF",
        "capture_id_label": trace["capture"]["capture_id"],
        "platform_label": trace["capture"]["platform"],
        "samples_reported": len(output),
        "samples_consistent_with_candidate_model": sum(
            int(x["paired_sample_consistent"]) for x in output),
        "candidate_consistent_unique_body_bytes": interval_union_size(accepted_ranges),
        "opaque_body_total_bytes": len(overlay) - 104,
        "pair_checks": output,
        "key_origin_verified": False,
        "original_executable_run_verified": False,
        "cloud_installer_transformation_proven": False,
        "whole_body_decoded": False,
        "output_format_classified": False,
        "win7_x86_x64_equivalence_verified": False,
        "certification_receipt_created": False,
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive", required=True, help="Original locally held ZIP")
    p.add_argument("--trace", required=True, help="Private sanitized ReadFile JSON")
    p.add_argument("--pairs", required=True, help="PRIVATE pre/post byte samples; never commit")
    p.add_argument("--json", help="Only metadata/digests in output; stdout otherwise")
    args = p.parse_args(argv)
    try:
        for filename in (args.trace, args.pairs):
            if pathlib.Path(filename).stat().st_size > MAX_INPUT_BYTES:
                raise DifferentialEvidenceError("Input JSON exceeds allowed size")
        trace = json.loads(pathlib.Path(args.trace).read_text(encoding="utf-8"))
        pairs = json.loads(pathlib.Path(args.pairs).read_text(encoding="utf-8"))
        result = analyze_pairs(trace, pairs, extract_reference(args.archive))
        report = json.dumps(result, sort_keys=True, indent=2) + "\n"
        if args.json:
            pathlib.Path(args.json).write_text(report, encoding="utf-8")
        else:
            print(report, end="")
        return 0
    except (OSError, ValueError, UnicodeError, RuntimeTraceError) as exc:
        print("REA-015/R differential check ERROR: " + str(exc),
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
