#!/usr/bin/env python3
"""REA-015: read-only scan for embedded PE headers at nonzero resource offsets.

A literal 'MZ' is NOT proof of an embedded executable. Each candidate is
validated with the PE parser and recorded as a *candidate*, not a full file or
recovered function. The scan cannot reveal compressed/encrypted payloads.
Python 3.8+, stdlib; never executes or writes proprietary bytes.
"""
import argparse
import hashlib
import json
import pathlib
import sys
import zipfile

try:
    from .rea_structural import PEView, PEError, MAX_PE
except ImportError:
    from rea_structural import PEView, PEError, MAX_PE

MAX_DEPTH = 3
MAX_MZ_HITS_PER_RESOURCE = 1024
MAX_TOTAL_MZ_HITS = 8192
MAX_RESOURCE_VISITS = 4096


class CandidateError(ValueError):
    pass


def scan_nonzero_mz(data, max_hits=MAX_MZ_HITS_PER_RESOURCE):
    """Return candidate offsets, explicitly distinguishing invalid MZ markers."""
    result = {"mz_nonzero_hits": 0, "valid_pe_candidates": [], "invalid_mz_hits": 0}
    start = 1
    while True:
        at = data.find(b"MZ", start)
        if at < 0:
            return result
        result["mz_nonzero_hits"] += 1
        if result["mz_nonzero_hits"] > max_hits:
            raise CandidateError("Per-resource magic-hit cap exceeded")
        start = at + 2
        if len(data) - at < 256:
            result["invalid_mz_hits"] += 1
            continue
        try:
            view = PEView(data[at:])
            if view.machine not in (0x14c, 0x8664):
                raise PEError("Unknown COFF machine type")
            result["valid_pe_candidates"].append({
                "offset_in_resource": at, "machine": "0x%04x" % view.machine,
                "confidence": "PE_header_and_sections_parse_candidate",
            })
        except PEError:
            result["invalid_mz_hits"] += 1


def inspect_resource_graph(pe_bytes, label, aggregate, depth=0):
    if depth > MAX_DEPTH:
        aggregate["unresolved"].append({"path": label, "reason": "depth_limit"})
        return
    try:
        view = PEView(pe_bytes)
        leaves = view.resources(depth=1)
    except PEError as exc:
        aggregate["unresolved"].append({
            "path": label, "reason": "pe_or_resource_parse_failed",
            "detail": str(exc),
        })
        return
    aggregate["pe_resource_modules"] += 1
    summary = {"path": label, "visible_resource_leaves": len(leaves),
               "nonzero_mz_hits": 0, "invalid_nonzero_mz_hits": 0,
               "valid_nonzero_pe_candidates": 0}
    for leaf in leaves:
        aggregate["resource_visits"] += 1
        if aggregate["resource_visits"] > MAX_RESOURCE_VISITS:
            raise CandidateError("Resource visitation cap exceeded")
        pos, size = leaf["file_offset"], leaf["size"]
        if size < 0 or pos < 0 or pos + size > len(pe_bytes):
            raise CandidateError("Resource not within PE")
        payload = pe_bytes[pos:pos + size]
        if hashlib.sha256(payload).hexdigest() != leaf["sha256"]:
            raise CandidateError("Resource changed from parser result")
        found = scan_nonzero_mz(payload)
        aggregate["mz_hits"] += found["mz_nonzero_hits"]
        if aggregate["mz_hits"] > MAX_TOTAL_MZ_HITS:
            raise CandidateError("Global magic-hit cap exceeded")
        summary["nonzero_mz_hits"] += found["mz_nonzero_hits"]
        summary["invalid_nonzero_mz_hits"] += found["invalid_mz_hits"]
        summary["valid_nonzero_pe_candidates"] += len(found["valid_pe_candidates"])
        for item in found["valid_pe_candidates"]:
            aggregate["candidates"].append({
                "resource": label + "::" + "/".join(leaf["path"]),
                **item,
            })
        if payload.startswith(b"MZ"):
            try:
                nested = PEView(payload)
                if nested.machine not in (0x14c, 0x8664):
                    raise PEError("Unknown embedded machine")
            except PEError:
                continue
            inspect_resource_graph(payload, label + "::" + "/".join(leaf["path"]),
                                   aggregate, depth + 1)
    aggregate["modules"].append(summary)


def analyze_archive(path, member="Faronics_DFS/DFStd.exe", expected_sha=None):
    archive_path = pathlib.Path(path)
    digest = hashlib.sha256()
    with archive_path.open("rb") as f:
        for part in iter(lambda: f.read(1048576), b""):
            digest.update(part)
    if expected_sha and digest.hexdigest() != expected_sha:
        raise CandidateError("Archive SHA-256 mismatch")
    with zipfile.ZipFile(path) as archive:
        entries = [i for i in archive.infolist() if i.filename == member]
        if len(entries) != 1 or entries[0].is_dir() or entries[0].flag_bits & 1:
            raise CandidateError("Missing, duplicated, or encrypted PE member")
        if entries[0].file_size > MAX_PE:
            raise CandidateError("PE member exceeds size cap")
        payload = bytearray()
        with archive.open(entries[0]) as stream:
            for chunk in iter(lambda: stream.read(1048576), b""):
                payload.extend(chunk)
                if len(payload) > entries[0].file_size:
                    raise CandidateError("PE member size mismatch")
        if len(payload) != entries[0].file_size:
            raise CandidateError("Truncated PE archive member")
    aggregate = {"modules": [], "candidates": [], "unresolved": [],
                 "resource_visits": 0, "pe_resource_modules": 0, "mz_hits": 0}
    inspect_resource_graph(bytes(payload), member, aggregate)
    return {
        "schema": "rea-015-offset-pe-candidates-v1",
        "source_archive_sha256": digest.hexdigest(),
        "root_member": member,
        "root_member_sha256": hashlib.sha256(payload).hexdigest(),
        "resource_leaves_visited": aggregate["resource_visits"],
        "pe_modules_with_resource_trees": aggregate["pe_resource_modules"],
        "nonzero_mz_marker_hits": aggregate["mz_hits"],
        "validated_nonzero_pe_candidates": len(aggregate["candidates"]),
        "candidates": aggregate["candidates"],
        "modules": sorted(aggregate["modules"], key=lambda s: s["path"]),
        "unresolved": aggregate["unresolved"],
        "scope_closed": False,
        "caveat": "No valid embedded PE at a scanned offset does NOT rule out packed, encrypted or externally installed binaries.",
    }


def main(argv=None):
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--archive", required=True)
    cli.add_argument("--member", default="Faronics_DFS/DFStd.exe")
    cli.add_argument("--expect-sha256")
    cli.add_argument("--json")
    args = cli.parse_args(argv)
    try:
        result = analyze_archive(args.archive, args.member, args.expect_sha256)
        output = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        if args.json:
            pathlib.Path(args.json).write_text(output, encoding="utf-8")
        else:
            sys.stdout.write(output)
        return 0
    except (OSError, ValueError, zipfile.BadZipFile, PEError) as exc:
        print("REA PE candidate scan failed: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
