#!/usr/bin/env python3
"""REA-015/L: complete *direct rel32* xrefs for four pinned static functions.

This enumerates CALL E8-rel32 byte-pattern candidates in the original
executable .text and corroborates each caller with an exact opcode anchor.
It does not prove indirect-call absence, runtime path identity or payload
decoding, and never executes the original Windows installer.
Python 3.8+, stdlib only.
"""
import argparse
import hashlib
import json
import pathlib
import struct
import sys
import zipfile

from .rea_structural import PEError, PEView, MAX_PE
from .rea_overlay_inventory import ZIP_SHA, ROOT_SHA, ROOT_MEMBER
from .rea_overlay_reader_trace import inspect_anchors, ReaderEvidenceError

TARGETS = (
    ("constructor", 0x750f1c),
    ("time_fallback", 0x750c60),
    ("four_word_hash", 0x74f804),
    ("base_initializer", 0x74f914),
)
DIRECT_SITES = {
    "constructor": (
        (0x4170ce, 0x4170c4, "caller_argument"),
        (0x41734f, 0x417345, "caller_argument"),
        (0x437241, 0x43722e, "converted_pointer"),
        (0x465c0a, 0x465c00, "caller_argument"),
        (0x465eab, 0x465ea1, "caller_argument"),
        (0x467d45, 0x467d3e, "caller_argument"),
        (0x467ec1, 0x467eb7, "caller_argument"),
        (0x468029, 0x46801f, "caller_argument"),
        (0x46821b, 0x468211, "caller_argument"),
        (0x4683df, 0x4683d5, "caller_argument"),
        (0x46854f, 0x468545, "caller_argument"),
    ),
    "time_fallback": (
        0x467d83, 0x467dfb, 0x468256, 0x4682d8, 0x46858a,
        0x46860c, 0x46de60,
    ),
    "four_word_hash": (
        0x47b77b, 0x47b827, 0x750b43, 0x750c84,
    ),
    "base_initializer": (0x46dd67, 0x750f41),
}
TIME_FORMAT_VA = 0x9d71b4
TIME_FORMAT = b"%.3s %.3s%3d %.2d:%.2d:%.2d %d%s"
# An x86 .text instruction loads this exact data VA into ESI.
TIME_FORMAT_LOAD = (0x76ae5a, "beb4719d00", "mov esi,0x9d71b4")
TIME_FORMAT_SINK = (0x76ae9d, "e8425fffff", "call 0x760de4")
EXTRA_HASH_ANCHORS = (
    (0x47b773, "8b45d8", "mov eax,[ebp-0x28]"),
    (0x47b776, "50", "push eax"),
    (0x47b777, "8d55c8", "lea edx,[ebp-0x38]"),
    (0x47b77a, "52", "push edx"),
    (0x47b81f, "8b45d8", "mov eax,[ebp-0x28]"),
    (0x47b822, "50", "push eax"),
    (0x47b823, "8d55c8", "lea edx,[ebp-0x38]"),
    (0x47b826, "52", "push edx"),
)


class CallerAuditError(ValueError):
    pass


def expected_address_sets():
    return {
        "constructor": {c[0] for c in DIRECT_SITES["constructor"]},
        "time_fallback": set(DIRECT_SITES["time_fallback"]),
        "four_word_hash": set(DIRECT_SITES["four_word_hash"]),
        "base_initializer": set(DIRECT_SITES["base_initializer"]),
    }


def scan_relative_calls(raw, target_values, start_va, raw_file_offset):
    """Scan E8 byte candidates; not a complete x86 instruction decoder.

    start_va and raw_file_offset define the exact contiguous executable
    section slice. Callers outside the slice, indirect calls and computed
    control flows are not included.
    """
    if not isinstance(raw, bytes) or len(raw) > MAX_PE:
        raise CallerAuditError("Invalid or oversized PE section")
    if not isinstance(target_values, dict) or not target_values:
        raise CallerAuditError("Missing call targets")
    result = {key: [] for key in target_values}
    target_by_va = {val: key for key, val in target_values.items()}
    if len(target_by_va) != len(target_values):
        raise CallerAuditError("Duplicate target VA")
    for i in range(len(raw)-4):
        if raw[i] != 0xe8:
            continue
        displacement = struct.unpack_from("<i", raw, i+1)[0]
        caller = start_va + i
        destination = caller + 5 + displacement
        if destination in target_by_va:
            result[target_by_va[destination]].append(caller)
    return {key: sorted(values) for key, values in result.items()}


def build_anchor_list(raw, image_base):
    """Pin the observed instruction bytes after cross-reference enumeration.

    We construct independent opcodes by reading bytes from the *pinned*
    original file; they remain auditable by VA/offset/section and SHA256
    returned by inspect_anchors. The call targets are checked separately.
    """
    if hashlib.sha256(raw).hexdigest() != ROOT_SHA:
        raise CallerAuditError("Pinned PE SHA-256 mismatch")
    view = PEView(raw)
    specs = []
    for kind, target in TARGETS:
        for va in sorted(expected_address_sets()[kind]):
            rva = va - image_base
            offset = view.rva_offset(rva, 5)
            b = raw[offset:offset+5]
            if b[0] != 0xe8 or va+5+struct.unpack_from("<i",b,1)[0] != target:
                raise CallerAuditError("Pinned direct call changed: 0x%x" % va)
            specs.append((kind+"_%08x" % va, va, b.hex(), "call 0x%x" % target))
    for va, hexbytes, description in (TIME_FORMAT_LOAD, TIME_FORMAT_SINK):
        specs.append(("time_format_%08x" % va, va, hexbytes, description))
    for va, hexbytes, description in EXTRA_HASH_ANCHORS:
        specs.append(("hash_context_%08x" % va, va, hexbytes, description))
    for va, zero, source in DIRECT_SITES["constructor"]:
        specs.append(("null_key_%08x" % va, zero, "6a00", "push NULL key"))
    return specs


def analyze_pe(raw):
    if hashlib.sha256(raw).hexdigest() != ROOT_SHA:
        raise CallerAuditError("Pinned PE SHA-256 mismatch")
    pe = PEView(raw)
    pe_off = pe.u32(0x3c)
    if pe.pe64 or pe.machine != 0x14c:
        raise CallerAuditError("Expected original PE32 x86")
    base = pe.u32(pe_off+24+28)
    secs = [sec for sec in pe.sections if sec["name"]==".text"]
    if len(secs) != 1 or secs[0]["raw_size"] > MAX_PE:
        raise CallerAuditError("Missing unique executable .text")
    sec = secs[0]
    if sec["offset"] < 0 or sec["offset"]+sec["raw_size"] > len(raw):
        raise CallerAuditError("Invalid executable bounds")
    t = {name: va for name, va in TARGETS}
    seen = scan_relative_calls(
        raw[sec["offset"]:sec["offset"]+sec["raw_size"]],
        t, base+sec["rva"], sec["offset"])
    expected = expected_address_sets()
    for name in t:
        if set(seen[name]) != expected[name]:
            raise CallerAuditError(
                "Direct-call candidate inventory drift at "+name+
                " (expected %d, found %d)" % (len(expected[name]), len(seen[name])))
    anchors = inspect_anchors(raw, build_anchor_list(raw, base))
    # Confirm the time-like C format string is located at its data RVA and
    # terminated; this does not demonstrate actual formatted runtime output.
    data_rva = TIME_FORMAT_VA - base
    offset = pe.rva_offset(data_rva, len(TIME_FORMAT)+1)
    if raw[offset:offset+len(TIME_FORMAT)+1] != TIME_FORMAT+b"\x00":
        raise CallerAuditError("Time format literal mismatch")
    return {
        "schema": "rea-015-l-direct-xref-v1",
        "source_pe_sha256": ROOT_SHA,
        "direct_call_candidates_by_target": {
            name: {
                "callee_va": "0x%08x" % target,
                "count": len(seen[name]),
                "sites": ["0x%08x" % va for va in seen[name]],
            } for name, target in TARGETS
        },
        "constructor_sites": [
            {"site_va": "0x%08x" % va, "null_argument_va": "0x%08x" % zero,
             "primary_string_parameter": "null_immediate",
             "path_pointer_provenance": source}
            for va, zero, source in DIRECT_SITES["constructor"]
        ],
        "hash_sites_outside_loader": [
            {"site_va": "0x%08x" % va,
             "source_pointer": "[ebp-0x28]_runtime_value_unknown",
             "destination": "stack_four_dwords_[ebp-0x38]"}
            for va in (0x47b77b, 0x47b827)
        ],
        "clock_format": {
            "data_va": "0x%08x" % TIME_FORMAT_VA,
            "format_sha256": hashlib.sha256(TIME_FORMAT).hexdigest(),
            "format_template": TIME_FORMAT.decode("ascii"),
            "read_from_code_va": "0x0076ae5a",
            "actual_formatted_value_observed": False,
        },
        "checked_instruction_anchor_count": len(anchors),
        "opcode_anchors": anchors,
        "limitations": [
            "E8 rel32 byte-pattern search is not a complete instruction-boundary proof",
            "Computed, indirect, import-thunk and virtual calls are not exhaustively inventoried",
            "A null primary string at 11 *direct* constructor callsites does not prove all runtime calls are null",
            "Two additional 0x74F804 direct sites use stack-derived pointers; no loader ownership established",
            "Runtime pathname, formatted date, key values and CLOUD_INSTALLER overlay identity are not demonstrated",
            "No behavioral equivalence, original payload decoding, recovered driver or Windows 7 VM result",
        ],
        "direct_site_set_complete_within_scanned_text_pattern": True,
        "all_actual_callers_certified": False,
        "global_reverse_engineering_certified": False,
    }


def analyze_archive(path):
    p = pathlib.Path(path)
    digest = hashlib.sha256()
    with p.open("rb") as fd:
        for chunk in iter(lambda: fd.read(1048576),b""):
            digest.update(chunk)
    if digest.hexdigest() != ZIP_SHA:
        raise CallerAuditError("Pinned ZIP SHA-256 mismatch")
    with zipfile.ZipFile(p) as z:
        matches = [m for m in z.infolist() if m.filename == ROOT_MEMBER]
        if len(matches)!=1 or matches[0].flag_bits & 1 or matches[0].file_size>MAX_PE:
            raise CallerAuditError("Missing or invalid PE archive member")
        with z.open(matches[0]) as fd:
            raw=fd.read(MAX_PE+1)
        if len(raw)!=matches[0].file_size:
            raise CallerAuditError("Truncated PE archive member")
    ret=analyze_pe(raw)
    ret["source_zip_sha256"]=digest.hexdigest()
    return ret


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive", required=True)
    p.add_argument("--json")
    args=p.parse_args(argv)
    try:
        r=analyze_archive(args.archive)
        s=json.dumps(r,sort_keys=True,indent=2,ensure_ascii=False)+"\n"
        if args.json:
            pathlib.Path(args.json).write_text(s,encoding="utf-8")
        else:
            print(s,end="")
        return 0
    except (OSError,ValueError,PEError,ReaderEvidenceError,zipfile.BadZipFile) as exc:
        print("REA xref audit ERROR: "+str(exc),file=sys.stderr)
        return 1


if __name__=="__main__":
    sys.exit(main())
