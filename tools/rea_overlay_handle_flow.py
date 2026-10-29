#!/usr/bin/env python3
"""REA-015/I: byte-pinned x86 evidence for file handle and conditional byte XOR.

Static data-flow evidence only. Does not execute CreateFile/ReadFile or drivers;
does not unpack CLOUD_INSTALLER or claim this format's body was decoded.
Python 3.8+ stdlib. No proprietary bytes are written.
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

# (name, virtual_address, exact machine bytes, disassembly finding)
ANCHORS = (
    ("path_arg_forward", 0x750b92, "53", "push ebx"),
    ("path_dest_owner_buffer", 0x750b93, "8b96dc000000", "mov edx,[esi+0xdc]"),
    ("path_buffer_helper", 0x750b9a, "e8ad67cbff", "call 0x40734c"),
    ("path_buffer_load", 0x750bad, "8b86dc000000", "mov eax,[esi+0xdc]"),
    ("context_from_owner", 0x750bb4, "8b560c", "mov edx,[esi+0xc]"),
    ("context_open_wrapper", 0x750bb8, "e8af190000", "call 0x75256c"),
    ("open_wrapper_context", 0x752573, "8b5d08", "mov ebx,[ebp+0x8]"),
    ("open_wrapper_forward", 0x75258a, "e8a5fcffff", "call 0x752234"),
    ("createfile_filename_arg", 0x7522c8, "8b4d0c", "mov ecx,[ebp+0xc]"),
    ("createfile_import_call", 0x7522cc, "e873ea1a00", "call 0x900d44"),
    ("createfile_import_thunk", 0x900d44, "ff255c67a100", "jmp [0xa1675c]"),
    ("createfile_store_handle", 0x7522d1, "894304", "mov [ebx+0x4],eax"),
    ("createfile_invalid_handle_check", 0x7522d4, "837b04ff", "cmp [ebx+0x4],-1"),
    ("header_owner_context", 0x74fb4c, "8b430c", "mov eax,[ebx+0xc]"),
    ("header_read_wrapper", 0x74fb50, "e81b2b0000", "call 0x752670"),
    ("read_wrapper_context_arg", 0x75267c, "8b5d08", "mov ebx,[ebp+0x8]"),
    ("read_handle_from_context", 0x7526aa, "8b4b04", "mov ecx,[ebx+0x4]"),
    ("read_handle_push", 0x7526ad, "51", "push ecx"),
    ("readfile_import_call", 0x7526ae, "e80fea1a00", "call 0x9010c2"),
    ("readfile_import_thunk", 0x9010c2, "ff259869a100", "jmp [0xa16998]"),
    ("header_dispatch", 0x74fe61, "e8bafcffff", "call 0x74fb20"),
    ("block_dispatch", 0x74fe91, "e89efeffff", "call 0x74fd34"),
    ("block_required_length", 0x74fd58, "8b4e58", "mov ecx,[esi+0x58]"),
    ("block_destination_buffer", 0x74fd5c, "8b8680000000", "mov eax,[esi+0x80]"),
    ("block_owner_context", 0x74fd63, "8b560c", "mov edx,[esi+0xc]"),
    ("block_read_wrapper", 0x74fd67, "e804290000", "call 0x752670"),
    ("block_transform_flag", 0x74fd71, "f6466001", "test byte [esi+0x60],1"),
    ("block_skip_transform", 0x74fd75, "742c", "je 0x74fda3"),
    ("block_transform_buffer", 0x74fd93, "8b8e80000000", "mov ecx,[esi+0x80]"),
    ("block_transform_call", 0x74fd9b, "e858030000", "call 0x7500f8"),
    ("transform_zero_key_test", 0x75010b, "e89cf6ffff", "call 0x74f7ac"),
    ("transform_skip_nonzero", 0x750115, "7520", "jne 0x750137"),
    ("transform_stage_call", 0x75012f, "e8f4f5ffff", "call 0x74f728"),
    ("transform_prep_state", 0x74f758, "f3a5", "rep movsd"),
    ("transform_state_test", 0x74f75a, "8b03", "mov eax,[ebx]"),
    ("transform_state_cmp", 0x74f75c, "48", "dec eax"),
    ("xor_worker_call", 0x74f78b, "e8ec000000", "call 0x74f87c"),
    ("xor_loop_length_cmp", 0x74f88c, "3b5d10", "cmp ebx,[ebp+0x10]"),
    ("xor_per_byte_key_call", 0x74f893, "e814000000", "call 0x74f8ac"),
    ("xor_in_place", 0x74f89b, "3006", "xor byte [esi],al"),
    ("xor_next_byte", 0x74f89e, "46", "inc esi"),
)
EXPECTED_IMPORTS = (
    ("KERNEL32.DLL", "CreateFileA", 0x00a1675c),
    ("KERNEL32.DLL", "ReadFile", 0x00a16998),
)


class FlowError(ValueError):
    pass


def validate_edges(anchors=ANCHORS):
    """Fail closed when a call's encoded rel32 target differs from the model."""
    index = {name: (address, bytes.fromhex(code)) for name, address, code, _ in anchors}
    edges = (
        ("context_open_wrapper", 0x75256c),
        ("open_wrapper_forward", 0x752234),
        ("createfile_import_call", 0x900d44),
        ("header_read_wrapper", 0x752670),
        ("readfile_import_call", 0x9010c2),
        ("header_dispatch", 0x74fb20),
        ("block_dispatch", 0x74fd34),
        ("block_read_wrapper", 0x752670),
        ("block_transform_call", 0x7500f8),
        ("transform_zero_key_test", 0x74f7ac),
        ("transform_stage_call", 0x74f728),
        ("xor_worker_call", 0x74f87c),
        ("xor_per_byte_key_call", 0x74f8ac),
    )
    verified = []
    for label, dest in edges:
        if label not in index:
            raise FlowError("Missing call edge " + label)
        address, code = index[label]
        if len(code) != 5 or code[0] != 0xe8:
            raise FlowError("Not a rel32 CALL at " + label)
        delta = int.from_bytes(code[1:], "little", signed=True)
        if address + 5 + delta != dest:
            raise FlowError("CALL destination mismatch: " + label)
        verified.append({"instruction_va": "0x%08x" % address,
                         "destination_va": "0x%08x" % dest,
                         "kind": "pinned_direct_call"})
    return verified


def static_contract():
    """Assertions reflect observed operations, NOT observed runtime outcomes."""
    return {
        "schema": "rea-015-handle-block-flow-v1",
        "source_pe_sha256": ROOT_SHA,
        "handle_provenance": [
            {"va": "0x00750B9A", "action": "pass caller filename to buffer helper using [owner+0xDC]"},
            {"va": "0x00750BB4", "action": "load context pointer from [owner+0x0C]"},
            {"va": "0x00750BB8", "action": "forward context and path to 0x75256C"},
            {"va": "0x0075258A", "action": "forward to file open helper 0x752234"},
            {"va": "0x007522CC", "action": "call imported CreateFileA"},
            {"va": "0x007522D1", "action": "store returned HANDLE in [context+0x04]"},
            {"va": "0x007526AA", "action": "load [context+0x04] as ReadFile hFile"},
            {"va": "0x007526AE", "action": "call imported ReadFile"},
        ],
        "after_header": [
            {"va": "0x0074FE61", "action": "dispatch 0x74FB20 header reader"},
            {"va": "0x0074FE91", "action": "dispatch 0x74FD34 block reader"},
            {"va": "0x0074FD58", "action": "length from [owner+0x58]"},
            {"va": "0x0074FD5C", "action": "destination from [owner+0x80]"},
            {"va": "0x0074FD67", "action": "read via 0x752670"},
            {"va": "0x0074FD71", "action": "test low bit of [owner+0x60]"},
            {"va": "0x0074FD75", "action": "zero flag branches over transform"},
            {"va": "0x0074FD9B", "action": "on flagged path, forward to 0x7500F8"},
        ],
        "conditional_data_transform": [
            {"va": "0x007500F8", "action": "conditional transform dispatcher"},
            {"va": "0x0075010B", "action": "validate a four-DWORD key argument set"},
            {"va": "0x0075012F", "action": "forward to state processor 0x74F728"},
            {"va": "0x0074F78B", "action": "call byte XOR worker 0x74F87C"},
            {"va": "0x0074F893", "action": "call per-position key-byte function 0x74F8AC"},
            {"va": "0x0074F89B", "action": "XOR key byte into buffer byte in-place"},
        ],
        "filename_origin": "caller-supplied pathname forwarded through buffer at [owner+0xDC]; upstream provenance beyond initializer not yet confirmed",
        "required_runtime_conditions": [
            "successful file open and read",
            "flag low bit at [owner+0x60] set",
            "nonzero key parameter set; state-dependent branch permits worker",
        ],
        "api_imports": [], "call_edges": [],
        "proven_xor_operation": True,
        "all_body_bytes_transformed_proven": False,
        "link_to_embedded_CLOUD_INSTALLER_proven": False,
        "driver_recovered": False,
        "semantically_equivalent": False,
        "scope_closed": False,
    }


def analyze_pe_bytes(raw):
    if hashlib.sha256(raw).hexdigest() != ROOT_SHA:
        raise FlowError("Source PE SHA-256 differs from pinned evidence")
    result = static_contract()
    result["instruction_anchors"] = inspect_anchors(raw, ANCHORS)
    result["call_edges"] = validate_edges()
    for dll, name, va in EXPECTED_IMPORTS:
        data = resolve_iat_symbol(raw, va)
        if data["dll"].upper() != dll or data["symbol"] != name:
            raise FlowError("Wrong API at pinned IAT: " + name)
        result["api_imports"].append(data)
    return result


def analyze_archive(path):
    archive = pathlib.Path(path)
    digest = hashlib.sha256()
    with archive.open("rb") as fd:
        for chunk in iter(lambda: fd.read(1048576), b""):
            digest.update(chunk)
    if digest.hexdigest() != ZIP_SHA:
        raise FlowError("Pinned ZIP SHA-256 mismatch")
    with zipfile.ZipFile(archive) as z:
        entries = [x for x in z.infolist() if x.filename == ROOT_MEMBER]
        if len(entries) != 1 or entries[0].flag_bits & 1 or entries[0].file_size > MAX_PE:
            raise FlowError("Missing or invalid PE archive entry")
        with z.open(entries[0]) as f:
            data = f.read(MAX_PE + 1)
        if len(data) != entries[0].file_size:
            raise FlowError("PE archive entry length mismatch")
    result = analyze_pe_bytes(data)
    result["source_archive_sha256"] = digest.hexdigest()
    return result


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive", required=True)
    p.add_argument("--json")
    args = p.parse_args(argv)
    try:
        report = analyze_archive(args.archive)
        payload = json.dumps(report, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
        if args.json:
            pathlib.Path(args.json).write_text(payload, encoding="utf-8")
        else:
            print(payload, end="")
        return 0
    except (OSError, ValueError, PEError, ReaderEvidenceError, zipfile.BadZipFile) as exc:
        print("REA handle flow ERROR: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
