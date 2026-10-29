#!/usr/bin/env python3
"""REA-015/M: bounded static provenance of file pathname and indirect FF sites.

This does not observe a live pathname. FF /2 and FF /4 byte-pattern scans are
not a complete x86 decoder, nor proof that unobserved indirect calls do not
exist. The CLOUD_INSTALLER resource association remains unverified.
Python 3.8+ stdlib, offline; only emits metadata and hashes.
"""
import argparse
import hashlib
import json
import pathlib
import struct
import sys
import zipfile

from .rea_structural import PEView, PEError, MAX_PE
from .rea_overlay_inventory import ZIP_SHA, ROOT_SHA, ROOT_MEMBER
from .rea_overlay_reader_trace import inspect_anchors, resolve_iat_symbol, ReaderEvidenceError

ANCHORS = (
    ("parent_path_load", 0x467cb8, "8b550c", "mov edx,[ebp+0xc]"),
    ("parent_path_push", 0x467cbb, "52", "push edx"),
    ("parent_source_load", 0x467cbc, "8b4d08", "mov ecx,[ebp+8]"),
    ("parent_source_push", 0x467cbf, "51", "push ecx"),
    ("parent_call", 0x467cc0, "e833000000", "call 0x467cf8"),
    ("child_path_load", 0x467d06, "8b7d0c", "mov edi,[ebp+0xc]"),
    ("get_attributes_path", 0x467d0e, "57", "push edi"),
    ("get_attributes_call", 0x467d0f, "e856914900", "call 0x900e6a"),
    ("attributes_save", 0x467d14, "8bf0", "mov esi,eax"),
    ("set_attributes_value", 0x467d1b, "6880000000", "push 0x80"),
    ("set_attributes_path", 0x467d20, "57", "push edi"),
    ("set_attributes_call", 0x467d21, "e8e4934900", "call 0x90110a"),
    ("ctor_null_key", 0x467d3e, "6a00", "push 0"),
    ("ctor_path", 0x467d40, "57", "push edi"),
    ("ctor_call", 0x467d45, "e8d2912e00", "call 0x750f1c"),
    ("converted_source_load", 0x437230, "8b13", "mov edx,[ebx]"),
    ("converted_source_plus_0x2c", 0x437232, "83c22c", "add edx,0x2c"),
    ("converted_source_push", 0x437235, "52", "push edx"),
    ("converted_helper_call", 0x437236, "e8f900fdff", "call 0x407334"),
    ("converted_result_push", 0x43723c, "50", "push eax"),
    ("converted_ctor_call", 0x437241, "e8d69c3100", "call 0x750f1c"),
    ("helper_source_arg", 0x407337, "8b4508", "mov eax,[ebp+8]"),
    ("helper_dereference", 0x40733a, "8b10", "mov edx,[eax]"),
    ("helper_return_empty", 0x407340, "b86ae09000", "mov eax,0x90e06a"),
    ("helper_return_nonempty", 0x407347, "8bc2", "mov eax,edx"),
    ("context_copied_path", 0x750b92, "53", "push ebx"),
    ("context_dest", 0x750b93, "8b96dc000000", "mov edx,[esi+0xdc]"),
    ("context_copy_call", 0x750b9a, "e8ad67cbff", "call 0x40734c"),
    ("copy_dest", 0x407351, "8b4508", "mov eax,[ebp+8]"),
    ("copy_source", 0x407354, "8b550c", "mov edx,[ebp+0xc]"),
    ("copy_length_scan", 0x407360, "f2ae", "repnz scasb"),
    ("context_ptr", 0x750bb4, "8b560c", "mov edx,[esi+0xc]"),
    ("context_open_call", 0x750bb8, "e8af190000", "call 0x75256c"),
    ("open_path_arg", 0x752570, "8b450c", "mov eax,[ebp+0xc]"),
    ("open_path_nonempty_test", 0x75257a, "803800", "cmp byte [eax],0"),
    ("open_helper_call", 0x75258a, "e8a5fcffff", "call 0x752234"),
    ("create_file_path_load", 0x7522c8, "8b4d0c", "mov ecx,[ebp+0xc]"),
    ("create_file_path_push", 0x7522cb, "51", "push ecx"),
    ("create_file_import_call", 0x7522cc, "e873ea1a00", "call 0x900d44"),
)
EDGES = (
    ("parent_call", 0x467cf8),
    ("get_attributes_call", 0x900e6a),
    ("set_attributes_call", 0x90110a),
    ("ctor_call", 0x750f1c),
    ("converted_helper_call", 0x407334),
    ("converted_ctor_call", 0x750f1c),
    ("context_copy_call", 0x40734c),
    ("context_open_call", 0x75256c),
    ("open_helper_call", 0x752234),
    ("create_file_import_call", 0x900d44),
)
IMPORTS = (
    ("GetFileAttributesA", 0xa16820),
    ("SetFileAttributesA", 0xa169c8),
    ("CreateFileA", 0xa1675c),
    ("ReadFile", 0xa16998),
)
# Bounded, disassembly-reviewed function fragments (not the complete program).
# These lie wholly inside the original main executable PE32 .text section.
WINDOWS = (
    ("parent_argument_forward", 0x467cab, 0x467cc8),
    ("attributes_and_constructor", 0x467cf8, 0x467d4a),
    ("structure_string_pointer", 0x407334, 0x40734b),
    ("bounded_string_copy", 0x40734c, 0x40737c),
    ("context_path_open", 0x750b90, 0x750bc0),
    ("open_wrapper", 0x75256c, 0x75259f),
    ("create_file_setup", 0x752234, 0x7522da),
    ("converted_structure_caller", 0x43722e, 0x437246),
)
EMPTY_STRING_VA = 0x90e06a


class IndirectScopeError(ValueError):
    pass


def raw_ff_patterns(payload, base_va):
    """All FF /2 (CALL) and /4 (JMP) byte pairs, *not* decoded instructions."""
    out = []
    for i in range(len(payload)-1):
        if payload[i] != 0xff:
            continue
        extension = (payload[i+1] >> 3) & 7
        if extension in (2, 4):
            out.append({"va": "0x%08x" % (base_va+i),
                        "kind": "call" if extension == 2 else "jump"})
    return out


def validate_call_targets():
    lookup = {name: (va, bytes.fromhex(op)) for name, va, op, _ in ANCHORS}
    result = []
    for label, target in EDGES:
        va, op = lookup[label]
        if len(op) != 5 or op[0] != 0xe8 or va+5+struct.unpack("<i", op[1:])[0] != target:
            raise IndirectScopeError("Direct CALL target mismatch: "+label)
        result.append({"source_va": "0x%08x" % va,
                       "destination_va": "0x%08x" % target})
    return result


def inspect_pe(raw):
    if hashlib.sha256(raw).hexdigest() != ROOT_SHA:
        raise IndirectScopeError("Pinned PE SHA-256 mismatch")
    view = PEView(raw)
    if view.machine != 0x14c or view.pe64:
        raise IndirectScopeError("Expected x86 PE32")
    pe = view.u32(0x3c)
    base = view.u32(pe+24+28)
    checked_anchors = inspect_anchors(raw, ANCHORS)
    checked_edges = validate_call_targets()
    resolved = []
    for name, va in IMPORTS:
        obj = resolve_iat_symbol(raw, va)
        if obj["dll"].upper() != "KERNEL32.DLL" or obj["symbol"] != name:
            raise IndirectScopeError("IAT mapping changed at "+name)
        resolved.append(obj)
    default = view.rva_offset(EMPTY_STRING_VA-base, 1)
    if raw[default] != 0:
        raise IndirectScopeError("Fallback string is not empty")
    sections = [s for s in view.sections if s["name"] == ".text"]
    if len(sections) != 1:
        raise IndirectScopeError("Expected one original .text")
    sec = sections[0]
    windows = []
    for label, lo, hi in WINDOWS:
        if lo >= hi or lo < base + sec["rva"] or hi > base + sec["rva"] + sec["raw_size"]:
            raise IndirectScopeError("Window outside executable .text")
        at = view.rva_offset(lo-base, hi-lo)
        candidates = raw_ff_patterns(raw[at:at+hi-lo], lo)
        windows.append({
            "name": label, "start_va": "0x%08x" % lo,
            "end_va_exclusive": "0x%08x" % hi,
            "bytes_scanned": hi-lo, "ff_indirect_byte_candidates": candidates,
        })
    return {
        "schema": "rea-015-m-path-and-indirect-scope-v1",
        "source_pe_sha256": ROOT_SHA,
        "verified_opcode_anchors": checked_anchors,
        "verified_direct_rel32_edges": checked_edges,
        "verified_win32_imports": resolved,
        "bounded_windows": windows,
        "fallback_empty_c_string_va": "0x%08x" % EMPTY_STRING_VA,
        "relationships": [
            "0x467CC0 forwards a caller-supplied path to 0x467CF8",
            "0x467CF8 reuses the same path pointer for GetFileAttributesA, SetFileAttributesA and the constructor",
            "0x750AE8 optionally copies the provided path into owner+0xDC",
            "0x75256C rejects a null/empty pathname before invoking 0x752234",
            "0x752234 passes its filename pointer to KERNEL32!CreateFileA",
            "0x437241 supplies a separate string from [object+0x2C] via 0x407334",
            "0x407334 may return an empty-string sentinel if the stored pointer is null",
        ],
        "ff_scan_is_opcode_byte_candidates_not_complete_disassembly": True,
        "all_indirect_calls_exhaustively_resolved": False,
        "real_filepath_captured": False,
        "cloud_installer_runtime_identity_proven": False,
        "original_vs_model_equivalence_verified": False,
        "internal_certification_issued": False,
    }


def analyze_archive(path):
    archive = pathlib.Path(path)
    h = hashlib.sha256()
    with archive.open("rb") as fd:
        for block in iter(lambda: fd.read(1048576), b""):
            h.update(block)
    if h.hexdigest() != ZIP_SHA:
        raise IndirectScopeError("Source ZIP SHA-256 mismatch")
    with zipfile.ZipFile(archive) as z:
        matches = [m for m in z.infolist() if m.filename == ROOT_MEMBER]
        if len(matches) != 1 or matches[0].flag_bits & 1 or matches[0].file_size > MAX_PE:
            raise IndirectScopeError("Pinned PE member missing/oversized")
        with z.open(matches[0]) as member:
            raw = member.read(MAX_PE + 1)
        if len(raw) != matches[0].file_size:
            raise IndirectScopeError("Pinned PE member size mismatch")
    report = inspect_pe(raw)
    report["source_zip_sha256"] = h.hexdigest()
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--json")
    args = parser.parse_args(argv)
    try:
        report = analyze_archive(args.archive)
        value = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        if args.json:
            pathlib.Path(args.json).write_text(value, encoding="utf-8")
        else:
            print(value, end="")
        return 0
    except (OSError, ValueError, PEError, ReaderEvidenceError,
            zipfile.BadZipFile) as exc:
        print("REA-015/M path trace ERROR: "+str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
