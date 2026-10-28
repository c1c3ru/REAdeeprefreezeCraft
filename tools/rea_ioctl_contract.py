#!/usr/bin/env python3
"""REA-008: pinned x86 user-mode buffer/handle provenance and synthetic control model.

Static evidence only; no DeviceIoControl, CreateFileA, driver execution or
proprietary redistribution. The model explores *hypothetical* API outcomes.
Python 3.8+, stdlib + GNU objdump for optional --archive validation.
"""
import argparse
import hashlib
import json
import os
import pathlib
import struct
import sys
import tempfile
import zipfile

try:
    from .rea_function_cfg import decode_function
    from .rea_structural import PEError, PEView
    from .rea_loop import MAX_PE
except ImportError:
    from rea_function_cfg import decode_function
    from rea_structural import PEError, PEView
    from rea_loop import MAX_PE

EXPECTED_SHA256 = "2d7c171d4037660843a7e02c055679c5a26904af84d48fc8c557a67023f55c8b"
TABLE_VA = 0x94af54
EXPECTED_CODES = (0x71c08, 0x7200c, 0x71fc4, 0x71fc0,
                  0x71fbc, 0x71ff4, 0x71ff0, 0x71fec)
ANCHORS = {
    "caller": {
        0x438ad8: ("mov", "esi,0x94af54"),
        0x438add: ("mov", "ecx,0x8"),
        0x438ae2: ("rep", None),
        0x438afd: ("lea", "ecx,[ebp-0x48]"),
        0x438b00: ("push", "ecx"),
        0x438b01: ("lea", "ecx,[ebp-0x4c]"),
        0x438b04: ("push", "0x4"),
        0x438b06: ("push", "ecx"),
        0x438b07: ("mov", "eax,DWORD PTR [edi]"),
        0x438b09: ("push", "eax"),
        0x438b0a: ("call", "0x438b48"),
        0x438b12: ("dec", "eax"),
        0x438b15: ("cmp", "DWORD PTR [ebp-0x48],0x4"),
        0x438b1b: ("cmp", "DWORD PTR [ebp-0x4c],0x0"),
        0x438b33: ("jb", "0x438af3"),
    },
    "helper": {
        0x438b75: ("push", "0x104"),
        0x438b7a: ("lea", "eax,[ebp-0x13c]"),
        0x438b80: ("push", "eax"),
        0x438b81: ("call", "0x900f2a"),
        0x438bd3: ("push", "0x0"),
        0x438bd5: ("push", "0x80"),
        0x438bda: ("push", "0x3"),
        0x438bdc: ("push", "0x0"),
        0x438bde: ("push", "0x0"),
        0x438be0: ("push", "0x0"),
        0x438be2: ("mov", "eax,DWORD PTR [esi]"),
        0x438be4: ("push", "eax"),
        0x438be5: ("call", "0x900d44"),
        0x438bea: ("mov", "ebx,eax"),
        0x438bec: ("cmp", "ebx,0xffffffff"),
        0x438bf1: ("push", "0x0"),
        0x438bf3: ("mov", "eax,DWORD PTR [ebp+0x14]"),
        0x438bf6: ("push", "eax"),
        0x438bf7: ("mov", "edx,DWORD PTR [ebp+0x10]"),
        0x438bfa: ("push", "edx"),
        0x438bfb: ("mov", "ecx,DWORD PTR [ebp+0xc]"),
        0x438bfe: ("push", "ecx"),
        0x438bff: ("push", "0x0"),
        0x438c01: ("push", "0x0"),
        0x438c03: ("mov", "ecx,DWORD PTR [ebp+0x8]"),
        0x438c06: ("push", "ecx"),
        0x438c07: ("push", "ebx"),
        0x438c08: ("call", "0x900d6e"),
        0x438c0d: ("test", "eax,eax"),
        0x438c11: ("mov", "DWORD PTR [ebp-0x28],0x1"),
        0x438c18: ("push", "ebx"),
        0x438c19: ("call", "0x900d20"),
        0x438c26: ("jne", "0x438c2d"),
        0x438c2b: ("jb", "0x438bd3"),
        0x438c2d: ("mov", "eax,DWORD PTR [ebp-0x28]"),
    }
}


class ContractError(ValueError):
    pass


def va(value):
    return "0x%08x" % value


def validate_anchors(decoded, anchors):
    by_va = {item["va"]: item for item in decoded}
    if len(by_va) != len(decoded):
        raise ContractError("Duplicate disassembled instruction VA")
    matched = []
    for address, (mnemonic, operands) in sorted(anchors.items()):
        instruction = by_va.get(address)
        if instruction is None or instruction["mnemonic"] != mnemonic:
            raise ContractError("Missing/mismatched instruction at " + va(address))
        if operands is not None and instruction["operands"] != operands:
            raise ContractError("Operand mismatch at " + va(address))
        matched.append({
            "va": va(address), "mnemonic": mnemonic,
            "operands": instruction["operands"],
        })
    return matched


def table_at_va(raw, addr):
    view = PEView(raw)
    opt = view.u32(0x3c) + 24
    base = view.u64(opt + 24) if view.pe64 else view.u32(opt + 28)
    if addr < base:
        raise ContractError("VA below image base")
    off = view.rva_offset(addr - base, 8 * 4)
    return struct.unpack_from("<8I", raw, off)


def contract_document(codes=EXPECTED_CODES):
    return {
        "schema": "rea-008-user-mode-contract-v1",
        "scope": "DFStd.exe pinned x86 caller/helper windows only",
        "source_sha256": EXPECTED_SHA256,
        "ioctl_code_table_va": va(TABLE_VA),
        "ioctl_code_candidates": ["0x%08x" % c for c in codes],
        "caller_helper_at": va(0x438b0a),
        "caller_arguments": [
            {"position": 1, "source": "[edi] from 8-entry local copy of table",
             "meaning": "candidate control code", "evidence": [va(0x438b07), va(0x438b09)]},
            {"position": 2, "source": "&[ebp-0x4c]", "meaning": "4-byte output dword",
             "evidence": [va(0x438b01), va(0x438b06)]},
            {"position": 3, "source": "0x4", "meaning": "output byte length",
             "evidence": [va(0x438b04)]},
            {"position": 4, "source": "&[ebp-0x48]", "meaning": "bytes returned pointer",
             "evidence": [va(0x438afd), va(0x438b00)]},
        ],
        "deviceiocontrol_at": va(0x438c08),
        "deviceiocontrol_arguments": [
            {"slot": 1, "name": "hDevice", "source": "EBX <- CreateFileA(EAX)",
             "evidence": [va(0x438be5), va(0x438bea), va(0x438c07)]},
            {"slot": 2, "name": "dwIoControlCode", "source": "[ebp+0x8] = helper argument 1",
             "evidence": [va(0x438c03), va(0x438c06)]},
            {"slot": 3, "name": "lpInBuffer", "source": "literal NULL", "evidence": [va(0x438c01)]},
            {"slot": 4, "name": "nInBufferSize", "source": "literal 0", "evidence": [va(0x438bff)]},
            {"slot": 5, "name": "lpOutBuffer", "source": "[ebp+0xc] = helper argument 2",
             "evidence": [va(0x438bfb), va(0x438bfe)]},
            {"slot": 6, "name": "nOutBufferSize", "source": "[ebp+0x10] = helper argument 3",
             "evidence": [va(0x438bf7), va(0x438bfa)]},
            {"slot": 7, "name": "lpBytesReturned", "source": "[ebp+0x14] = helper argument 4",
             "evidence": [va(0x438bf3), va(0x438bf6)]},
            {"slot": 8, "name": "lpOverlapped", "source": "literal NULL", "evidence": [va(0x438bf1)]},
        ],
        "getsystemdirectorya_arguments": [
            {"slot": 1, "name": "lpBuffer", "source": "&[ebp-0x13c]",
             "evidence": [va(0x438b7a), va(0x438b80)]},
            {"slot": 2, "name": "uSize", "source": "literal 0x104",
             "evidence": [va(0x438b75)]},
        ],
        "createfilea_arguments": [
            {"slot": 1, "name": "lpFileName", "source": "[esi], pointer from 2-entry local path table",
             "evidence": [va(0x438be2), va(0x438be4)]},
            {"slot": 2, "name": "dwDesiredAccess", "source": "literal 0",
             "evidence": [va(0x438be0)]},
            {"slot": 3, "name": "dwShareMode", "source": "literal 0",
             "evidence": [va(0x438bde)]},
            {"slot": 4, "name": "lpSecurityAttributes", "source": "literal NULL",
             "evidence": [va(0x438bdc)]},
            {"slot": 5, "name": "dwCreationDisposition", "source": "literal 3 (OPEN_EXISTING)",
             "evidence": [va(0x438bda)]},
            {"slot": 6, "name": "dwFlagsAndAttributes", "source": "literal 0x80 (FILE_ATTRIBUTE_NORMAL)",
             "evidence": [va(0x438bd5)]},
            {"slot": 7, "name": "hTemplateFile", "source": "literal NULL",
             "evidence": [va(0x438bd3)]},
        ],
        "closehandle_arguments": [
            {"slot": 1, "name": "hObject", "source": "EBX from non-invalid CreateFileA",
             "evidence": [va(0x438bea), va(0x438c18), va(0x438c19)]},
        ],
        "other_apis": [
            {"api": "GetSystemDirectoryA", "call_va": va(0x438b81),
             "observed_condition": "EAX == 0 -> helper returns 0 without attempting device open"},
            {"api": "CreateFileA", "call_va": va(0x438be5),
             "observed_condition": "EAX copied to EBX; EBX == 0xffffffff skips IOCTL/close"},
            {"api": "CloseHandle", "call_va": va(0x438c19),
             "observed_condition": "Reached after a valid handle path regardless of IOCTL result"},
        ],
        "return_contract": {
            "helper": "local [ebp-0x28] initialized to 0; changed to 1 only if DeviceIoControl EAX != 0; max 2 path attempts",
            "caller": "tries max 8 candidate codes; on first helper return == 1 stops, returns 1 only if bytesReturned == 4 and output DWORD unsigned > 0; otherwise returns 0",
            "evidence": [va(0x438c0d), va(0x438c11), va(0x438c2d),
                         va(0x438b12), va(0x438b15), va(0x438b1b), va(0x438b33)],
        },
        "unknowns": [
            "Actual device identity behind the two CreateFileA path candidates",
            "Kernel IOCTL implementation, side effects, and Windows 7 compatibility",
            "Runtime outcomes and any exception/nonreturning paths",
        ],
        "behaviorally_equivalent": False,
        "windows7_x86_validated": False,
        "windows7_x64_validated": False,
    }


def hypothetical_helper(system_directory_success, open_and_ioctl_outcomes):
    """Synthetic control model: iterable of pairs (open_ok, ioctl_ok). No IO."""
    trace = []
    if not system_directory_success:
        return {"return": 0, "trace": ["system_directory_failed"], "attempts": 0}
    if len(open_and_ioctl_outcomes) != 2:
        raise ValueError("Exactly two hypothetical path outcomes required")
    for index, (open_ok, ioctl_ok) in enumerate(open_and_ioctl_outcomes):
        trace.append({"attempt": index, "open_ok": bool(open_ok)})
        if not open_ok:
            continue
        trace.append({"attempt": index, "ioctl_ok": bool(ioctl_ok), "closed": True})
        if ioctl_ok:
            return {"return": 1, "trace": trace, "attempts": index + 1}
    return {"return": 0, "trace": trace, "attempts": 2}


def hypothetical_caller(candidate_outcomes, codes=EXPECTED_CODES):
    """Synthetic code iteration. Each outcome=(helper_success, bytes_returned, dword)."""
    if len(candidate_outcomes) != len(codes):
        raise ValueError("Expected one hypothetical outcome for each code")
    tried = []
    for code, (success, returned, value) in zip(codes, candidate_outcomes):
        tried.append("0x%08x" % code)
        if success:
            accepted = returned == 4 and 0 < value <= 0xffffffff
            return {"return": int(accepted), "codes_attempted": tried,
                    "stopped_on_first_helper_success": True}
    return {"return": 0, "codes_attempted": tried,
            "stopped_on_first_helper_success": False}


def analyze_file(path):
    p = pathlib.Path(path)
    if p.stat().st_size > MAX_PE:
        raise ContractError("PE exceeds limit")
    raw = p.read_bytes()
    if hashlib.sha256(raw).hexdigest() != EXPECTED_SHA256:
        raise ContractError("Pinned PE SHA-256 mismatch")
    codes = table_at_va(raw, TABLE_VA)
    if codes != EXPECTED_CODES:
        raise ContractError("Control code table changed")
    evidence = {}
    for label, start, end in (("caller", 0x438ac0, 0x438b48),
                              ("helper", 0x438b48, 0x438c41)):
        insns = decode_function(p, start, end)
        evidence[label] = validate_anchors(insns, ANCHORS[label])
    result = contract_document(codes)
    result["anchored_instructions"] = evidence
    result["verified_static_source"] = True
    return result


def analyze_archive(archive, member="Faronics_DFS/DFStd.exe"):
    with zipfile.ZipFile(archive) as zf:
        entries = [i for i in zf.infolist() if i.filename == member]
        if len(entries) != 1 or entries[0].flag_bits & 1 or entries[0].file_size > MAX_PE:
            raise ContractError("Missing, duplicated or oversized PE member")
        with tempfile.TemporaryDirectory(prefix="rea-008-") as folder:
            target = pathlib.Path(folder) / "sample.exe"
            with zf.open(entries[0]) as src, target.open("xb") as dst:
                os.chmod(str(target), 0o600)
                total = 0
                for chunk in iter(lambda: src.read(1048576), b""):
                    total += len(chunk)
                    if total > entries[0].file_size:
                        raise ContractError("ZIP member size mismatch")
                    dst.write(chunk)
            if total != entries[0].file_size:
                raise ContractError("Truncated ZIP PE member")
            return analyze_file(target)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    options = parser.add_mutually_exclusive_group(required=True)
    options.add_argument("--archive")
    options.add_argument("--pe")
    parser.add_argument("--json")
    args = parser.parse_args(argv)
    try:
        report = analyze_archive(args.archive) if args.archive else analyze_file(args.pe)
        content = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        if args.json:
            pathlib.Path(args.json).write_text(content, encoding="utf-8")
        else:
            print(content, end="")
        return 0
    except (OSError, ValueError, PEError, zipfile.BadZipFile) as exc:
        print("REA-008 contract ERROR: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
