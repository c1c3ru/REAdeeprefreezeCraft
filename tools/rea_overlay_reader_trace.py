#!/usr/bin/env python3
"""REA-015/H: bounded x86 static anchors for a candidate installer frame reader.

Checks exact opcode bytes at PE virtual addresses, pinned source hashes, and
correlates *observed* structure offsets to the resource overlay. The shared
frame format is strongly suggested; ownership of the CLOUD_INSTALLER payload
and the internal transformation remain unverified. No third-party code runs.
Python >=3.8, stdlib only.
"""
import argparse
import hashlib
import json
import pathlib
import struct
import sys
import zipfile

from .rea_structural import PEView, PEError, MAX_PE
from .rea_overlay_inventory import (
    ZIP_SHA, ROOT_SHA, ROOT_MEMBER, CHILD_RESOURCE, CHILD_SHA,
    OVERLAY_SHA, FRAME_MAGIC,
)

# Exact bytes independently inspected with GNU objdump -b pei-i386 -M intel.
# VA is x86 image VA, not file offset. Use PE section RVA mapping.
ANCHORS = (
    ("header_buffer", 0x74fb45, "8d7b10", "lea edi,[ebx+0x10]"),
    ("header_read_size", 0x74fb49, "6a60", "push 0x60"),
    ("header_read_call", 0x74fb50, "e81b2b0000", "call 0x752670"),
    ("header_validation_call", 0x74fb59, "e82e060000", "call 0x75018c"),
    ("header_magic_compare", 0x75019e, "817b1c69cdab69", "cmp [ebx+0x1c],0x69abcd69"),
    ("header_magic_branch", 0x7501a5, "740e", "je 0x7501b5"),
    ("length_field_write", 0x74fc7f, "894334", "mov [ebx+0x34],eax"),
    ("header_write_buffer", 0x74fc84, "8d7310", "lea esi,[ebx+0x10]"),
    ("header_write_size", 0x74fc8a, "6a60", "push 0x60"),
    ("trailer_seek_size", 0x7502d6, "8b45fc", "mov eax,[ebp-0x4]"),
    ("trailer_seek_call", 0x7502de, "e83d250000", "call 0x752820"),
    ("trailer_buffer", 0x7502fd, "8d4b70", "lea ecx,[ebx+0x70]"),
    ("trailer_read_size", 0x750300, "6a08", "push 0x8"),
    ("trailer_read_call", 0x750307, "e864230000", "call 0x752670"),
    ("trailer_magic_compare", 0x750317, "817b7069cdab69", "cmp [ebx+0x70],0x69abcd69"),
    ("header_size_init", 0x750591, "c7431060000000", "mov [ebx+0x10],0x60"),
    ("header_version_init", 0x7505a5, "c7431801030000", "mov [ebx+0x18],0x301"),
    ("header_magic_init", 0x7505ac, "c7431c69cdab69", "mov [ebx+0x1c],0x69abcd69"),
    ("duplicate_header_size_init", 0x750607, "c7435460000000", "mov [ebx+0x54],0x60"),
    ("paired_field_first_init", 0x750610, "894358", "mov [ebx+0x58],eax"),
    ("paired_field_second_init", 0x750613, "89435c", "mov [ebx+0x5c],eax"),
    ("readfile_buffer_push", 0x7526a9, "57", "push edi"),
    ("readfile_handle_push", 0x7526ad, "51", "push ecx"),
    ("readfile_import_call", 0x7526ae, "e80fea1a00", "call 0x9010c2"),
    ("readfile_import_jump", 0x9010c2, "ff259869a100", "jmp dword [0xa16998]"),
)


class ReaderEvidenceError(ValueError):
    pass


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def inspect_anchors(raw, specs=ANCHORS):
    """Check each pinned x86 instruction occurs at the stated executable VA."""
    view = PEView(raw)
    pe = view.u32(0x3c)
    image_base = view.u32(pe+24+28) if not view.pe64 else None
    if view.machine != 0x14c or image_base is None:
        raise ReaderEvidenceError("Expected PE32 x86 image")
    hits = []
    seen = set()
    for name, va, hexbytes, description in specs:
        if name in seen or va in [item["va_integer"] for item in hits]:
            raise ReaderEvidenceError("Duplicate instruction anchor")
        seen.add(name)
        expected = bytes.fromhex(hexbytes)
        if not expected or va < image_base:
            raise ReaderEvidenceError("Invalid evidence span")
        rva = va - image_base
        offset = view.rva_offset(rva, len(expected))
        if raw[offset:offset+len(expected)] != expected:
            raise ReaderEvidenceError("Pinned instruction mismatch: " + name)
        # Only count code from executable PE section, not bytes in resources.
        matches = [sec for sec in view.sections
                   if sec["rva"] <= rva and rva+len(expected) <=
                   sec["rva"]+sec["raw_size"]]
        if len(matches) != 1 or matches[0]["name"] != ".text":
            raise ReaderEvidenceError("Instruction anchor not in executable .text")
        hits.append({"id": name, "va": "0x%08x" % va, "va_integer": va,
                     "rva": "0x%x" % rva, "file_offset": "0x%x" % offset,
                     "instruction_bytes_sha256": sha(expected),
                     "decoded_offline": description})
    for hit in hits:
        del hit["va_integer"]
    return hits



def resolve_iat_symbol(raw, iat_va):
    """Resolve a DWORD PE32 IAT slot to its DLL/import symbol, without loading it."""
    view = PEView(raw)
    if view.pe64 or view.machine != 0x14c:
        raise ReaderEvidenceError("Expected PE32 x86 imports")
    pe = view.u32(0x3c)
    base = view.u32(pe + 24 + 28)
    target_rva = iat_va - base
    directory, size = view.directory(1)
    if not directory or not size or target_rva < 0:
        raise ReaderEvidenceError("Import directory unavailable")
    for i in range(min(256, size // 20)):
        d = view.rva_offset(directory + i*20, 20)
        oft, stamp, forward, dll_rva, first_thunk = struct.unpack_from("<IIIII", raw, d)
        if not any((oft, stamp, forward, dll_rva, first_thunk)):
            break
        name = view.asciiz(view.rva_offset(dll_rva))
        for index in range(4096):
            thunk = view.u32(view.rva_offset((oft or first_thunk) + index*4))
            if thunk == 0:
                break
            if first_thunk + index*4 == target_rva:
                if thunk & 0x80000000:
                    return {"dll": name, "symbol": "#"+str(thunk&0xffff),
                            "iat_va": "0x%08x" % iat_va}
                symbol = view.asciiz(view.rva_offset(thunk + 2))
                return {"dll": name, "symbol": symbol,
                        "iat_va": "0x%08x" % iat_va}
        else:
            raise ReaderEvidenceError("Too many import thunks")
    raise ReaderEvidenceError("IAT entry not resolved")



def frame_correlations(overlay):
    if len(overlay) < 104:
        raise ReaderEvidenceError("Overlay too short")
    values = {hex(x): struct.unpack_from("<I", overlay, x)[0]
              for x in (0, 8, 12, 0x24, 0x44, 0x48, 0x4c)}
    if (values["0x0"] != 96 or values["0x8"] != 0x301 or
            values["0xc"] != 0x69abcd69 or
            values["0x44"] != 96 or
            values["0x24"] != len(overlay) or
            overlay[-8:-4] != FRAME_MAGIC):
        raise ReaderEvidenceError("Pinned overlay frame/header values changed")
    return {
        "header_span_bytes": 96, "trailer_span_bytes": 8,
        "dword_values": values, "trailer_magic_offset": "0x%x" % (len(overlay)-8),
        "header_magic_relative_offset": "0xc",
        "observed_structure_base": "[EBX+0x10]",
        "observed_header_correlations": [
            {"structure": "[EBX+0x10]", "overlay": "+0x00", "value": 96},
            {"structure": "[EBX+0x18]", "overlay": "+0x08", "value": 769},
            {"structure": "[EBX+0x1C]", "overlay": "+0x0C", "value": 0x69abcd69},
            {"structure": "[EBX+0x54]", "overlay": "+0x44", "value": 96},
            {"structure": "[EBX+0x58] and [EBX+0x5C]",
             "overlay": "+0x48 and +0x4C",
             "observed_equal": values["0x48"] == values["0x4c"]},
        ],
        "matched_format_ownership": "candidate_not_proven",
    }


def analyze_archive(path):
    archive_path = pathlib.Path(path)
    h = hashlib.sha256()
    with archive_path.open("rb") as fp:
        for block in iter(lambda: fp.read(1048576), b""):
            h.update(block)
    if h.hexdigest() != ZIP_SHA:
        raise ReaderEvidenceError("Archive SHA-256 mismatch")
    with zipfile.ZipFile(archive_path) as zf:
        matches = [x for x in zf.infolist() if x.filename == ROOT_MEMBER]
        if len(matches) != 1 or matches[0].flag_bits & 1 or matches[0].file_size > MAX_PE:
            raise ReaderEvidenceError("Missing or invalid archive PE member")
        with zf.open(matches[0]) as member:
            main = member.read(MAX_PE+1)
        if len(main) != matches[0].file_size or sha(main) != ROOT_SHA:
            raise ReaderEvidenceError("Root PE source hash/size mismatch")
    anchors = inspect_anchors(main)
    readfile = resolve_iat_symbol(main, 0x00a16998)
    if readfile["dll"].upper() != "KERNEL32.DLL" or readfile["symbol"] != "ReadFile":
        raise ReaderEvidenceError("Expected pinned ReadFile IAT resolution")
    children = [x for x in PEView(main).resources(depth=1)
                if "/".join(x["path"]) == CHILD_RESOURCE]
    if len(children) != 1:
        raise ReaderEvidenceError("Expected exactly one cloud PE resource")
    item = children[0]
    child = main[item["file_offset"]:item["file_offset"]+item["size"]]
    if sha(child) != CHILD_SHA or item["sha256"] != CHILD_SHA:
        raise ReaderEvidenceError("Cloud PE hash mismatch")
    view = PEView(child)
    physical_end = max(s["offset"]+s["raw_size"] for s in view.sections if s["raw_size"])
    cert_offset, cert_size = view.directory(4)
    if cert_offset or cert_size:
        if not cert_offset or not cert_size or cert_offset + cert_size > len(child):
            raise ReaderEvidenceError("PE security directory invalid")
        physical_end = max(physical_end, cert_offset+cert_size)
    overlay = child[physical_end:]
    if sha(overlay) != OVERLAY_SHA:
        raise ReaderEvidenceError("Overlay SHA-256 mismatch")
    return {
        "schema": "rea-015-static-frame-reader-v1",
        "source_zip_sha256": h.hexdigest(), "source_pe_sha256": sha(main),
        "cloud_pe_sha256": sha(child), "overlay_sha256": sha(overlay),
        "reader_candidate_anchors": anchors,
        "reader_to_win32_readfile": {
            "wrapper_call_va": "0x007526AE", "import_thunk_va": "0x009010C2",
            "iat": readfile, "relation": "static_call_to_imported_ReadFile",
        },
        "candidate_reader_window": "0x0074FB20..0x00750334",
        "candidate_writer_window": "0x00750498..0x00750670",
        "header_and_trailer": frame_correlations(overlay),
        "observed_behavior": "Static read setup (96 bytes), magic checks, write initialization, 8-byte trailer read/check.",
        "unverified": ["No proof these routines consume this exact embedded cloud PE during installation.",
                       "No decoder for the opaque overlay body identified.",
                       "No driver or dynamic Windows 7 validation."],
        "body_transformation_identified": False,
        "whole_product_coverage_certified": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--json")
    args = parser.parse_args(argv)
    try:
        report = analyze_archive(args.archive)
        result = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        if args.json:
            pathlib.Path(args.json).write_text(result, encoding="utf-8")
        else:
            print(result, end="")
        return 0
    except (OSError, ValueError, PEError, zipfile.BadZipFile) as exc:
        print("REA frame reader ERROR: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
