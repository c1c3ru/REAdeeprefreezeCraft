#!/usr/bin/env python3
"""REA-015/K: byte-pinned static provenance of filename and local-time fallback.

This proves a specific *callsite* supplies a NULL primary key argument,
and that another call derives a fallback string via imported GetLocalTime.
It does NOT identify the runtime filename, exact formatted string, or
connect the opened file to the CLOUD_INSTALLER embedded PE/overlay.
Python 3.8+ stdlib, no execution or extraction of proprietary modules.
"""
import argparse
import hashlib
import json
import pathlib
import sys
import zipfile

from .rea_structural import PEError, MAX_PE
from .rea_overlay_inventory import ZIP_SHA, ROOT_SHA, ROOT_MEMBER
from .rea_overlay_reader_trace import inspect_anchors, resolve_iat_symbol, ReaderEvidenceError

# Observations verified against the SHA-256-pinned DFStd.exe x86 .text section.
ANCHORS = (
    ("site_path_from_argument", 0x467d06, "8b7d0c", "mov edi,[ebp+0xc]"),
    ("site_key_null", 0x467d3e, "6a00", "push 0"),
    ("site_path_forward", 0x467d40, "57", "push edi"),
    ("site_object_forward", 0x467d41, "8b55fc", "mov edx,[ebp-4]"),
    ("site_constructor_call", 0x467d45, "e8d2912e00", "call 0x750f1c"),
    ("ctor_null_extra", 0x750f36, "6a00", "push 0"),
    ("ctor_key_arg", 0x750f38, "8b5510", "mov edx,[ebp+0x10]"),
    ("ctor_key_forward", 0x750f3b, "52", "push edx"),
    ("ctor_path_forward", 0x750f3c, "53", "push ebx"),
    ("ctor_init_call", 0x750f41, "e8cee9ffff", "call 0x74f914"),
    ("base_init_forward_key", 0x74fa3a, "8b4d10", "mov ecx,[ebp+0x10]"),
    ("base_init_key_push", 0x74fa3d, "51", "push ecx"),
    ("base_init_inner_call", 0x74fa46, "e89d100000", "call 0x750ae8"),
    ("inner_key_arg", 0x750b38, "8b4d10", "mov ecx,[ebp+0x10]"),
    ("inner_hash_call", 0x750b43, "e8bcecffff", "call 0x74f804"),
    ("hash_zero_words", 0x74f811, "8908", "mov [eax],ecx"),
    ("hash_null_test", 0x74f81c, "837d0c00", "cmp [ebp+0xc],0"),
    ("hash_null_skip", 0x74f820, "7454", "je 0x74f876"),
    ("time_fallback_callsite", 0x467d83, "e8d88e2e00", "call 0x750c60"),
    ("time_fallback_object", 0x750c65, "8b5d08", "mov ebx,[ebp+8]"),
    ("time_output_buffer", 0x750c68, "8d45fc", "lea eax,[ebp-4]"),
    ("time_source_call", 0x750c6c, "e853aa0100", "call 0x76b6c4"),
    ("format_time_call", 0x750c76, "e869a20100", "call 0x76aee4"),
    ("fallback_word_dest", 0x750c7d, "81c3ac000000", "add ebx,0xac"),
    ("fallback_hash_call", 0x750c84, "e87bebffff", "call 0x74f804"),
    ("get_local_time_import_call", 0x76b6d2, "e8c9571900", "call 0x900ea0"),
    ("get_local_time_thunk", 0x900ea0, "ff254468a100", "jmp [0xa16844]"),
    ("hash_formatted_time_entry", 0x76aee4, "55", "push ebp"),
    ("select_secondary_word3", 0x750504, "ffb3c8000000", "push [ebx+0xc8]"),
    ("select_secondary_word0", 0x750516, "ffb3bc000000", "push [ebx+0xbc]"),
    ("secondary_key_zero_test", 0x75051c, "e88bf2ffff", "call 0x74f7ac"),
    ("secondary_zero_jump", 0x750526, "7417", "je 0x75053f"),
    ("fallback_words_source", 0x750529, "8db3ac000000", "lea esi,[ebx+0xac]"),
    ("fallback_words_copy", 0x75053a, "f3a5", "rep movsd"),
    ("secondary_words_source", 0x750540, "8db3bc000000", "lea esi,[ebx+0xbc]"),
    ("secondary_words_copy", 0x750551, "f3a5", "rep movsd"),
    ("site_flag_param_a", 0x467d71, "8a451c", "mov al,[ebp+0x1c]"),
    ("site_flag_param_b", 0x467d75, "8a5518", "mov dl,[ebp+0x18]"),
    ("site_flags_setter", 0x467d7a, "e8a58e2e00", "call 0x750c24"),
)

EDGES = (
    ("site_constructor_call", 0x750f1c),
    ("ctor_init_call", 0x74f914),
    ("base_init_inner_call", 0x750ae8),
    ("inner_hash_call", 0x74f804),
    ("time_fallback_callsite", 0x750c60),
    ("time_source_call", 0x76b6c4),
    ("format_time_call", 0x76aee4),
    ("fallback_hash_call", 0x74f804),
    ("get_local_time_import_call", 0x900ea0),
    ("secondary_key_zero_test", 0x74f7ac),
    ("site_flags_setter", 0x750c24),
)


class ProvenanceError(ValueError):
    pass


def validate_edges(anchors=ANCHORS):
    index = {name: (address, bytes.fromhex(blob)) for name, address, blob, _ in anchors}
    proven = []
    for name, target in EDGES:
        if name not in index:
            raise ProvenanceError("Missing callsite: " + name)
        va, blob = index[name]
        if len(blob) != 5 or blob[0] != 0xe8:
            raise ProvenanceError("Not direct rel32 CALL: " + name)
        relative = int.from_bytes(blob[1:], byteorder="little", signed=True)
        if va + 5 + relative != target:
            raise ProvenanceError("Call destination drift: " + name)
        proven.append({"site_va": "0x%08x" % va, "callee_va": "0x%08x" % target})
    return proven


def static_conclusions():
    return {
        "sample_callsite_va": "0x00467D45",
        "source_path": "caller_argument_[ebp+0x0C]_not_a_literal_path",
        "source_key_at_this_callsite": "NULL",
        "constructor_path_chain": [
            "0x00467D45 -> 0x00750F1C",
            "0x00750F41 -> 0x0074F914",
            "0x0074FA46 -> 0x00750AE8",
            "0x00750B43 -> 0x0074F804",
        ],
        "null_key_effect": "four zero DWORDs, because 0x74F804 zeros output before NULL check",
        "fallback_preparation": [
            "0x00467D83 -> 0x00750C60 (this specific callsite)",
            "0x00750C6C -> 0x0076B6C4",
            "0x0076B6D2 -> imported KERNEL32.DLL!GetLocalTime",
            "0x00750C76 -> 0x0076AEE4 (intermediate conversion/formatting)",
            "0x00750C84 -> 0x0074F804 (four fallback DWORDs)",
        ],
        "word_selection": ("if all secondary DWORDs are zero, copy four fallback "
                           "words [owner+0xAC..0xB8]; otherwise copy primary "
                           "[owner+0xBC..0xC8]"),
        "flags_at_callsite": "two Boolean caller arguments passed to 0x750C24",
        "format_of_time_derived_string_proven": False,
        "actual_timestamp_and_words_observed": False,
        "actual_path_value_observed": False,
        "link_to_CLOUD_INSTALLER_overlay_proven": False,
        "runtime_equivalence_verified": False,
        "scope_closed": False,
    }


def analyze_pe(raw):
    if hashlib.sha256(raw).hexdigest() != ROOT_SHA:
        raise ProvenanceError("Source PE SHA-256 mismatch")
    anchors = inspect_anchors(raw, ANCHORS)
    edges = validate_edges()
    lib = resolve_iat_symbol(raw, 0x00a16844)
    if lib["dll"].upper() != "KERNEL32.DLL" or lib["symbol"] != "GetLocalTime":
        raise ProvenanceError("GetLocalTime import mapping mismatch")
    return {
        "schema": "rea-015-key-input-provenance-v1",
        "source_pe_sha256": ROOT_SHA,
        "opcode_anchors": anchors, "direct_edges": edges,
        "imported_time_api": lib,
        "findings": static_conclusions(),
        "unknowns": [
            "Path argument originates upstream from caller and is not a known literal",
            "Clock formatting/string contents and exact runtime timestamps unobserved",
            "CLOUD_INSTALLER resource linkage to this reader remains unproved",
            "Original-time behavior and decoder equivalence not tested in Windows 7",
        ],
    }


def analyze_archive(path):
    src = pathlib.Path(path)
    h = hashlib.sha256()
    with src.open("rb") as fd:
        for chunk in iter(lambda: fd.read(1048576), b""):
            h.update(chunk)
    if h.hexdigest() != ZIP_SHA:
        raise ProvenanceError("Pinned ZIP SHA-256 mismatch")
    with zipfile.ZipFile(src) as z:
        matches = [m for m in z.infolist() if m.filename == ROOT_MEMBER]
        if len(matches) != 1 or matches[0].flag_bits & 1 or matches[0].file_size > MAX_PE:
            raise ProvenanceError("Invalid pinned PE archive member")
        with z.open(matches[0]) as fd:
            raw = fd.read(MAX_PE + 1)
        if len(raw) != matches[0].file_size:
            raise ProvenanceError("Archive PE length mismatch")
    result = analyze_pe(raw)
    result["source_archive_sha256"] = h.hexdigest()
    return result


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive", required=True)
    p.add_argument("--json")
    args = p.parse_args(argv)
    try:
        data = analyze_archive(args.archive)
        result = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        if args.json:
            pathlib.Path(args.json).write_text(result, encoding="utf-8")
        else:
            print(result, end="")
        return 0
    except (OSError, ValueError, PEError, ReaderEvidenceError,
            zipfile.BadZipFile) as exc:
        print("REA-015 key provenance ERROR: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
