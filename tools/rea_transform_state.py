#!/usr/bin/env python3
"""REA-015/J: static flag/key provenance and synthetic byte-key arithmetic.

Reconstructs bounded x86 *instruction semantics* for research validation.
No original payload is decoded, transformed, dumped, or executed.
The connection from the observed routines to a specific embedded installer
resource and the full transformation protocol are NOT proven.
Python 3.8+, stdlib.
"""
import argparse
import hashlib
import json
import pathlib
import sys
import zipfile

from .rea_structural import PEError, MAX_PE
from .rea_overlay_inventory import ZIP_SHA, ROOT_SHA, ROOT_MEMBER
from .rea_overlay_reader_trace import inspect_anchors, ReaderEvidenceError

# Address, verified opcode bytes, and the narrowly justified observation.
ANCHORS = (
    ("default_flag_nine", 0x750b1a, "c786a400000009000000", "mov [esi+0xa4],9"),
    ("direct_flag_setter", 0x750c19, "8990a4000000", "mov [eax+0xa4],edx"),
    ("split_flags_zero", 0x750c2c, "8990a4000000", "mov [eax+0xa4],edx"),
    ("split_flag_bit3", 0x750c38, "b908000000", "mov ecx,8"),
    ("split_flag_or_bit3", 0x750c41, "0988a4000000", "or [eax+0xa4],ecx"),
    ("split_flag_bit0", 0x750c4d, "ba01000000", "mov edx,1"),
    ("split_flag_or_bit0", 0x750c56, "0990a4000000", "or [eax+0xa4],edx"),
    ("caller_provided_string", 0x750b38, "8b4d10", "mov ecx,[ebp+0x10]"),
    ("caller_string_key_dest", 0x750b3c, "8d8ebc000000", "lea ecx,[esi+0xbc]"),
    ("caller_string_key_call", 0x750b43, "e8bcecffff", "call 0x74f804"),
    ("alternative_key_dest", 0x750c7d, "81c3ac000000", "add ebx,0xac"),
    ("alternative_string_key_call", 0x750c84, "e87bebffff", "call 0x74f804"),
    ("string_key_zero_word", 0x74f811, "8908", "mov [eax],ecx"),
    ("string_key_shift7", 0x74f846, "c12007", "shl [eax],7"),
    ("string_key_xor_char", 0x74f849, "3110", "xor [eax],edx"),
    ("string_key_shift19", 0x74f85e, "c1fa13", "sar edx,19"),
    ("string_key_xor_mix", 0x74f861, "3110", "xor [eax],edx"),
    ("flag_source", 0x750616, "8b93a4000000", "mov edx,[ebx+0xa4]"),
    ("flag_clear_bit3", 0x75061c, "83e2f7", "and edx,0xfffffff7"),
    ("flag_store", 0x75061f, "895360", "mov [ebx+0x60],edx"),
    ("block_flag_test", 0x74fd71, "f6466001", "test byte [esi+0x60],1"),
    ("block_flag_skip", 0x74fd75, "742c", "je 0x74fda3"),
    ("secondary_key_word3", 0x750504, "ffb3c8000000", "push [ebx+0xc8]"),
    ("secondary_key_word2", 0x75050a, "ffb3c4000000", "push [ebx+0xc4]"),
    ("secondary_key_word1", 0x750510, "ffb3c0000000", "push [ebx+0xc0]"),
    ("secondary_key_word0", 0x750516, "ffb3bc000000", "push [ebx+0xbc]"),
    ("secondary_key_zero_call", 0x75051c, "e88bf2ffff", "call 0x74f7ac"),
    ("secondary_zero_branch", 0x750526, "7417", "je 0x75053f"),
    ("primary_key_source", 0x750529, "8db3ac000000", "lea esi,[ebx+0xac]"),
    ("primary_key_destination", 0x75052f, "8dbbcc000000", "lea edi,[ebx+0xcc]"),
    ("primary_copy_four_dwords", 0x750535, "b904000000", "mov ecx,4"),
    ("primary_copy", 0x75053a, "f3a5", "rep movsd"),
    ("secondary_key_source", 0x750540, "8db3bc000000", "lea esi,[ebx+0xbc]"),
    ("secondary_key_destination", 0x750546, "8dbbcc000000", "lea edi,[ebx+0xcc]"),
    ("secondary_copy_four_dwords", 0x75054c, "b904000000", "mov ecx,4"),
    ("secondary_copy", 0x750551, "f3a5", "rep movsd"),
    ("current_key_source", 0x7505ec, "8db3cc000000", "lea esi,[ebx+0xcc]"),
    ("header_key_destination", 0x7505f2, "8d7b40", "lea edi,[ebx+0x40]"),
    ("copy_current_key_words", 0x7505fa, "f3a5", "rep movsd"),
    ("transform_word3", 0x74fd77, "ffb6d8000000", "push [esi+0xd8]"),
    ("transform_word2", 0x74fd7d, "ffb6d4000000", "push [esi+0xd4]"),
    ("transform_word1", 0x74fd83, "ffb6d0000000", "push [esi+0xd0]"),
    ("transform_word0", 0x74fd89, "ffb6cc000000", "push [esi+0xcc]"),
    ("nonzero_key_call", 0x75010b, "e89cf6ffff", "call 0x74f7ac"),
    ("nonzero_key_branch", 0x750115, "7520", "jne 0x750137"),
    ("four_state_words", 0x74f758, "f3a5", "rep movsd"),
    ("state_kind", 0x74f75a, "8b03", "mov eax,[ebx]"),
    ("state_kind_dec", 0x74f75c, "48", "dec eax"),
    ("state_kind_branch", 0x74f75d, "7402", "je 0x74f761"),
    ("seed_zero", 0x74f763, "895314", "mov [ebx+0x14],edx"),
    ("seed_word", 0x74f76b, "8b08", "mov ecx,[eax]"),
    ("seed_xor_each_word", 0x74f76d, "314b14", "xor [ebx+0x14],ecx"),
    ("seed_shift_arithmetic", 0x74f77c, "c1f910", "sar ecx,16"),
    ("seed_fold", 0x74f77f, "314b14", "xor [ebx+0x14],ecx"),
    ("xor_worker_call", 0x74f78b, "e8ec000000", "call 0x74f87c"),
    ("key_add_state_word", 0x74f8b2, "668b5014", "mov dx,[eax+0x14]"),
    ("key_add_index", 0x74f8b6, "6603550c", "add dx,[ebp+0xc]"),
    ("key_call_arithmetic", 0x74f8c0, "e80f000000", "call 0x74f8d4"),
    ("key_extract_high_byte", 0x74f8c8, "c1fa08", "sar edx,8"),
    ("key_xor_high_low", 0x74f8ce, "32c2", "xor al,dl"),
    ("arith_sign_extend", 0x74f8e1, "0fbfd9", "movsx ebx,cx"),
    ("arith_divisor", 0x74f8dc, "beb1000000", "mov esi,177"),
    ("arith_div1", 0x74f8ec, "f7fe", "idiv esi"),
    ("arith_mul5", 0x74f8ee, "8d0492", "lea eax,[edx+edx*4]"),
    ("arith_mul21", 0x74f8f1, "8d0482", "lea eax,[edx+eax*4]"),
    ("arith_mul85", 0x74f8f4, "8d0482", "lea eax,[edx+eax*4]"),
    ("arith_mul171", 0x74f8f7, "8d0442", "lea eax,[edx+eax*2]"),
    ("arith_div2", 0x74f8fe, "f7f9", "idiv ecx"),
    ("arith_times2", 0x74f900, "03c0", "add eax,eax"),
    ("arith_sub2q", 0x74f904, "2bc2", "sub eax,edx"),
    ("arith_shift15", 0x74f908, "c1e10f", "shl ecx,15"),
    ("arith_minus_original", 0x74f90b, "2bc8", "sub ecx,eax"),
    ("worker_key_call", 0x74f893, "e814000000", "call 0x74f8ac"),
    ("worker_xor_in_place", 0x74f89b, "3006", "xor byte [esi],al"),
)

DIRECT_EDGES = (
    ("secondary_key_zero_call", 0x74f7ac),
    ("nonzero_key_call", 0x74f7ac),
    ("xor_worker_call", 0x74f87c),
    ("key_call_arithmetic", 0x74f8d4),
    ("worker_key_call", 0x74f8ac),
    ("caller_string_key_call", 0x74f804),
    ("alternative_string_key_call", 0x74f804),
)


class StateEvidenceError(ValueError):
    pass


def u32(value):
    return value & 0xffffffff


def s16(value):
    value &= 0xffff
    return value-0x10000 if value & 0x8000 else value


def s32(value):
    value = u32(value)
    return value-0x100000000 if value & 0x80000000 else value


def select_words(primary, secondary):
    """Synthetic model of 750504..750551: copy primary iff secondary is all zero."""
    if len(primary) != 4 or len(secondary) != 4:
        raise ValueError("Exactly four DWORDs per array")
    if not all(isinstance(x, int) and 0 <= x <= 0xffffffff
               for x in list(primary)+list(secondary)):
        raise ValueError("Invalid unsigned DWORD")
    chosen = primary if all(x == 0 for x in secondary) else secondary
    return tuple(chosen)


def configured_flag(bit3_enabled, bit0_enabled):
    """Synthetic interpretation of setter 750C24: two independent Boolean bits."""
    if type(bit3_enabled) is not bool or type(bit0_enabled) is not bool:
        raise ValueError("Expected Boolean settings")
    return (8 if bit3_enabled else 0) | (1 if bit0_enabled else 0)


def copied_flag(source):
    if not isinstance(source, int) or not 0 <= source <= 0xffffffff:
        raise ValueError("Invalid flag DWORD")
    return source & 0xfffffff7


def derive_state_word(words):
    """State+0x14 from four DWORD xor, then xor arithmetic right shift 16."""
    if len(words) != 4 or any(
            not isinstance(x, int) or not 0 <= x <= 0xffffffff for x in words):
        raise ValueError("Four unsigned DWORDs required")
    v = words[0] ^ words[1] ^ words[2] ^ words[3]
    return u32(v ^ (s32(v) >> 16))


def trunc_divmod(x, base):
    """x86 IDIV: truncation toward zero; remainder has sign of dividend."""
    q = abs(x)//base * (1 if x >= 0 else -1)
    return q, x - q*base


def candidate_key_byte(seed_word, byte_position):
    """Synthetic model of 74F8AC -> 74F8D4; never processes original data."""
    if not isinstance(seed_word, int) or not 0 <= seed_word <= 0xffffffff:
        raise ValueError("Invalid seed")
    if not isinstance(byte_position, int) or byte_position < 0:
        raise ValueError("Invalid byte index")
    index = s16((seed_word & 0xffff) + (byte_position & 0xffff))
    q, r = trunc_divmod(index, 177)
    # LEA chain 5r -> 21r -> 85r -> 171r; then subtract 2q,
    # followed by (x << 15) - x, i.e. x*32767 (32-bit wrap).
    word = u32((171*r - 2*q)*32767) & 0xffff
    return (word & 0xff) ^ ((word >> 8) & 0xff)


def hypothetical_transform(payload, flag, primary, secondary, state_kind):
    """Entirely synthetic test vectors; NOT proof of installed payload decoding."""
    if not isinstance(payload, bytes) or len(payload) > 4096:
        raise ValueError("Synthetic payload maximum 4096 bytes")
    if not isinstance(state_kind, int):
        raise ValueError("Invalid state kind")
    selected = select_words(primary, secondary)
    # F7AC returns 1 iff all four params are zero; transform is then skipped.
    enabled = bool(copied_flag(flag) & 1 and any(selected)
                   and state_kind == 1)
    if not enabled:
        return {"applied": False, "output_hex": payload.hex(),
                "selected_seed_word": None}
    seed = derive_state_word(selected)
    changed = bytes(byte ^ candidate_key_byte(seed, index)
                    for index, byte in enumerate(payload))
    return {"applied": True, "output_hex": changed.hex(),
            "selected_seed_word": "0x%08x" % seed}


def validate_direct_calls():
    index = {name: (addr, bytes.fromhex(op)) for name, addr, op, _ in ANCHORS}
    ret = []
    for name, target in DIRECT_EDGES:
        address, code = index[name]
        if len(code) != 5 or code[0] != 0xe8:
            raise StateEvidenceError("Non-relative CALL anchor: "+name)
        rel32 = int.from_bytes(code[1:], "little", signed=True)
        if address+5+rel32 != target:
            raise StateEvidenceError("CALL target changed: "+name)
        ret.append({"name": name, "caller_va": "0x%08x" % address,
                    "callee_va": "0x%08x" % target})
    return ret


def analyze_pe(raw):
    if hashlib.sha256(raw).hexdigest() != ROOT_SHA:
        raise StateEvidenceError("Pinned PE SHA-256 mismatch")
    return {
        "schema": "rea-015-flag-key-model-v1",
        "source_sha256": ROOT_SHA,
        "opcode_anchors": inspect_anchors(raw, ANCHORS),
        "verified_call_edges": validate_direct_calls(),
        "flag_word_source": "[owner+0xA4]",
        "flag_initial_value": 9,
        "flag_setters": ["0x00750C10 (direct DWORD)", "0x00750C24 (bit3/bit0 Boolean settings)"],
        "flag_word_destination": "[owner+0x60]",
        "flag_mask": "0xFFFFFFF7",
        "bit0_preserved": True,
        "secondary_key_source": "[owner+0xBC..0xC8]",
        "secondary_key_provenance": "caller string [ebp+0x10] via 0x74F804, before selective copy",
        "fallback_key_provenance": "helper 0x750C60 calls 0x74F804 on a separate string; upstream source not fully proven",
        "string_hash_known_operations": "zero 4 words, shift 7, xor signed byte, xor shifted high bits",
        "primary_fallback_source": "[owner+0xAC..0xB8]",
        "active_key_destination": "[owner+0xCC..0xD8]",
        "key_selection": "primary only when secondary has all 4 DWORDs zero",
        "key_byte_source": "0x74F8AC -> 0x74F8D4; IDIV by 177; high-byte xor low-byte",
        "model_scope": "synthetic-only arithmetic, not an observed unpacking run",
        "actual_cloud_overlay_processed": False,
        "key_origin_before_owner_fields_known": False,
        "whole_product_equivalence": False,
    }


def analyze_archive(path):
    file = pathlib.Path(path)
    h = hashlib.sha256()
    with file.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            h.update(chunk)
    if h.hexdigest() != ZIP_SHA:
        raise StateEvidenceError("Pinned archive SHA-256 mismatch")
    with zipfile.ZipFile(file) as archive:
        entries = [item for item in archive.infolist()
                   if item.filename == ROOT_MEMBER]
        if len(entries) != 1 or entries[0].flag_bits & 1 or entries[0].file_size > MAX_PE:
            raise StateEvidenceError("Pinned archive member unavailable")
        with archive.open(entries[0]) as inp:
            data = inp.read(MAX_PE + 1)
        if len(data) != entries[0].file_size:
            raise StateEvidenceError("Truncated archive member")
    result = analyze_pe(data)
    result["source_archive_sha256"] = h.hexdigest()
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--json")
    args = parser.parse_args(argv)
    try:
        result = analyze_archive(args.archive)
        output = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False)+"\n"
        if args.json:
            pathlib.Path(args.json).write_text(output, encoding="utf-8")
        else:
            print(output, end="")
        return 0
    except (OSError, ValueError, ReaderEvidenceError,
            PEError, zipfile.BadZipFile) as exc:
        print("REA state model ERROR: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
