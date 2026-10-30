#!/usr/bin/env python3
"""REA-015/S: bounded offline triage of locally recovered output artifacts.

Never executes, unpacks, extracts, or publishes the source bytes. Header
signatures and plausible PE sections are CANDIDATES, not recovered modules.
A matching SHA-256 does not authenticate the provenance of a capture.
Python 3.8+; standard library only.
"""
import argparse
import hashlib
import json
import pathlib
import re
import sys

MAX_ARTIFACT = 32 * 1024 * 1024
MAX_CANDIDATES = 64
SHA256 = re.compile(r"^[0-9a-f]{64}$")
CAPTURE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
MACHINES = {0x014c: "x86", 0x8664: "x64"}
MAGIC = (
    ("mz", b"MZ"),
    ("zip_local_header", b"PK\x03\x04"),
    ("gzip_header", b"\x1f\x8b\x08"),
    ("7z_header", b"7z\xbc\xaf\x27\x1c"),
)


class OutputTriageError(ValueError):
    pass


def u16(data, offset):
    return int.from_bytes(data[offset:offset + 2], "little")


def u32(data, offset):
    return int.from_bytes(data[offset:offset + 4], "little")


def pe_header_candidate(data, offset):
    """Check only local PE header/section bounds; not authenticity or execution."""
    remaining = len(data) - offset
    if remaining < 0x40 or data[offset:offset + 2] != b"MZ":
        return None
    pe_rva = u32(data, offset + 0x3c)
    if not 0x40 <= pe_rva <= 0x2000 or pe_rva + 24 > remaining:
        return None
    pe = offset + pe_rva
    if data[pe:pe + 4] != b"PE\x00\x00":
        return None
    machine = u16(data, pe + 4)
    nsections = u16(data, pe + 6)
    optional_size = u16(data, pe + 20)
    if machine not in MACHINES or not 1 <= nsections <= 96:
        return None
    if not 96 <= optional_size <= 512:
        return None
    optional = pe + 24
    section_table = optional + optional_size
    if section_table + nsections * 40 > len(data):
        return None
    optional_magic = u16(data, optional)
    if (machine == 0x014c and optional_magic != 0x10b or
            machine == 0x8664 and optional_magic != 0x20b):
        return None
    header_size = u32(data, optional + 60)
    image_size = u32(data, optional + 56)
    header_end = section_table + nsections * 40 - offset
    if (header_size < header_end or header_size > remaining or
            image_size < header_size or image_size > 1024 * 1024 * 1024):
        return None

    max_end = header_size
    raw_sections = 0
    for idx in range(nsections):
        base = section_table + idx * 40
        raw_size = u32(data, base + 16)
        raw_offset = u32(data, base + 20)
        if raw_size:
            if raw_offset < header_size or raw_offset > remaining:
                return None
            if raw_size > remaining - raw_offset:
                return None
            max_end = max(max_end, raw_offset + raw_size)
            raw_sections += 1
    if not raw_sections:
        return None
    return {
        "offset": offset,
        "architecture_hint": MACHINES[machine],
        "number_of_sections": nsections,
        "candidate_span": [offset, offset + max_end],
        "candidate_span_sha256": hashlib.sha256(
            data[offset:offset + max_end]).hexdigest(),
        "verification_level": "PE_HEADER_AND_RAW_SECTION_BOUNDS_ONLY",
        "complete_module_confirmed": False,
    }


def scan_offsets(data, needle, cap):
    """Find all hits but retain only a bounded first page of positions."""
    positions = []
    total = 0
    next_at = 0
    while True:
        at = data.find(needle, next_at)
        if at == -1:
            break
        total += 1
        if len(positions) < cap:
            positions.append(at)
        next_at = at + 1
    return total, positions


def analyze_artifact(data, expected_sha256, capture_id):
    """The expected digest must be independently recorded by the observer."""
    if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_ARTIFACT:
        raise OutputTriageError("Artifact exceeds bounded local size")
    if not isinstance(expected_sha256, str) or not SHA256.fullmatch(expected_sha256):
        raise OutputTriageError("Expected SHA-256 must be 64 lowercase hex chars")
    if not isinstance(capture_id, str) or not CAPTURE_ID.fullmatch(capture_id):
        raise OutputTriageError("Invalid sanitized capture identifier")
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_sha256:
        raise OutputTriageError("Artifact does not match independently recorded digest")

    counts = {}
    offsets = {}
    for name, signature in MAGIC:
        counts[name], offsets[name] = scan_offsets(data, signature, MAX_CANDIDATES)
    candidates = []
    for pos in offsets["mz"]:
        candidate = pe_header_candidate(data, pos)
        if candidate is not None:
            candidates.append(candidate)
    prefix = "unclassified"
    if candidates and candidates[0]["offset"] == 0:
        prefix = "bounded_pe_candidate"
    elif data.startswith(b"PK\x03\x04"):
        prefix = "zip_local_header_prefix_only"
    elif data.startswith(b"\x1f\x8b\x08"):
        prefix = "gzip_header_prefix_only"
    elif data.startswith(b"7z\xbc\xaf\x27\x1c"):
        prefix = "7z_header_prefix_only"
    elif data.startswith(b"MZ"):
        prefix = "mz_prefix_only"
    return {
        "schema": "rea-015-output-structure-triage-v1",
        "status": "UNAUTHENTICATED_OFFLINE_STRUCTURE_CANDIDATES_ONLY",
        "capture_id_label": capture_id,
        "artifact_sha256": digest,
        "artifact_size_bytes": len(data),
        "artifact_prefix_hint": prefix,
        "signature_hit_counts": counts,
        "pe_candidates": candidates,
        "pe_candidate_scan_capped": counts["mz"] > MAX_CANDIDATES,
        "signature_offsets_truncated": any(
            count > MAX_CANDIDATES for count in counts.values()),
        "no_decompression_or_extraction_performed": True,
        "original_executable_run_verified": False,
        "transformation_proven": False,
        "output_format_verified": False,
        "modules_recovered": 0,
        "driver_artifacts_recovered": 0,
        "equivalence_verified": False,
        "certification_receipt_created": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", required=True, help="PRIVATE local output bytes")
    parser.add_argument("--expected-sha256", required=True,
                        help="SHA-256 independently recorded before this analysis")
    parser.add_argument("--capture-id", required=True, help="Sanitized capture label")
    parser.add_argument("--json", help="Metadata-only report; stdout if omitted")
    args = parser.parse_args(argv)
    try:
        source = pathlib.Path(args.artifact)
        if source.stat().st_size > MAX_ARTIFACT:
            raise OutputTriageError("Oversized source artifact")
        data = source.read_bytes()
        result = analyze_artifact(data, args.expected_sha256, args.capture_id)
        output = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.json:
            pathlib.Path(args.json).write_text(output, encoding="utf-8")
        else:
            print(output, end="")
        return 0
    except (OSError, ValueError) as exc:
        print("REA-015/S output triage ERROR: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
