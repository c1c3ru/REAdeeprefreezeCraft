#!/usr/bin/env python3
"""REA cycle 6: bounded, evidence-linked x86 I/O call contract.

Offline only. Reads PE data, candidate caller/callee instructions, and exact
import thunks. Never executes IOCTLs, installs drivers or interprets effects.
Supports Python 3.8+, GNU objdump. Pinning by SHA-256 prevents version drift.
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
    from .rea_structural import PEView, PEError
    from .rea_function_cfg import decode_function, target_number, inspect_function
    from .rea_loop import MAX_PE
except ImportError:
    from rea_structural import PEView, PEError
    from rea_function_cfg import decode_function, target_number, inspect_function
    from rea_loop import MAX_PE

EXPECTED_SHA = '2d7c171d4037660843a7e02c055679c5a26904af84d48fc8c557a67023f55c8b'
ANCHORS = {
    'caller_entry': 0x438ac0, 'caller_end': 0x438b48,
    'helper_entry': 0x438b48, 'helper_end': 0x438c41,
    'table_va': 0x94af54, 'table_len': 8,
    'prefix_va': 0x94b078, 'fallback_ptr_va': 0x94b084,
}


def is_pe64(view):
    return getattr(view, 'pe32plus', getattr(view, 'pe64', False))


def image_base(view):
    opt = view.u32(0x3c) + 24
    return view.u64(opt + 24) if is_pe64(view) else view.u32(opt + 28)


def mapped_bytes(view, va, size):
    offset = view.rva_offset(va - image_base(view), size)
    return view.data[offset:offset + size]


def little_endian_table(view, va, count):
    if not 1 <= count <= 256:
        raise ValueError('Table entry count outside limit')
    raw = mapped_bytes(view, va, count * 4)
    return list(struct.unpack('<%dI' % count, raw))


def ascii_at_va(view, va, limit=128):
    return view.asciiz(view.rva_offset(va - image_base(view)), limit)


def all_import_slots(view):
    """Resolve all named and ordinal IAT slots with bounded traversal."""
    rva, size = view.directory(1)
    if not rva or not size:
        return {}
    width = 8 if is_pe64(view) else 4
    high_bit = 1 << (63 if is_pe64(view) else 31)
    slots = {}
    terminated = False
    for idx in range(min(256, size // 20)):
        at = view.rva_offset(rva + idx * 20, 20)
        lookup, stamp, chain, name_rva, iat = struct.unpack_from('<IIIII', view.data, at)
        if not any((lookup, stamp, chain, name_rva, iat)):
            terminated = True
            break
        dll = view.asciiz(view.rva_offset(name_rva))
        for i in range(4096):
            at = view.rva_offset((lookup or iat) + i * width, width)
            value = view.u64(at) if width == 8 else view.u32(at)
            if value == 0:
                break
            name = ('#%d' % (value & 0xffff) if value & high_bit
                    else view.asciiz(view.rva_offset(value + 2)))
            slots[image_base(view) + iat + i * width] = {'dll': dll, 'name': name}
        else:
            raise PEError('Unterminated import lookup table')
    if not terminated:
        raise PEError('Unterminated import descriptor table')
    return slots


def resolve_iat_jump(view, thunk_va, slots):
    """Resolve only direct x86 FF25 import thunks, without simulating them."""
    if is_pe64(view) or view.machine != 0x14c:
        raise ValueError('Only x86 PE32 is supported')
    raw = mapped_bytes(view, thunk_va, 6)
    if raw[:2] != b'\xff\x25':
        return None
    iat_va = struct.unpack_from('<I', raw, 2)[0]
    if iat_va not in slots:
        return None
    return dict(slots[iat_va], thunk_va='0x%08x' % thunk_va,
                iat_va='0x%08x' % iat_va)


def instruction_evidence(insns, va, op=None, fragment=None):
    inst = next((i for i in insns if i['va'] == va), None)
    if (inst is None or (op and inst['mnemonic'] != op)
            or (fragment and fragment not in inst['operands'])):
        return {'va': '0x%08x' % va, 'present': False}
    return {'va': '0x%08x' % va, 'present': True,
            'mnemonic': inst['mnemonic'], 'operands': inst['operands']}


def derive_contract(view, caller, helper):
    """Verify explicit interprocedural evidence in this one pinned version."""
    anchors = ANCHORS
    table = little_endian_table(view, anchors['table_va'], anchors['table_len'])
    prefix = ascii_at_va(view, anchors['prefix_va'])
    fallback_pointer = struct.unpack('<I', mapped_bytes(view, anchors['fallback_ptr_va'], 4))[0]
    fallback = ascii_at_va(view, fallback_pointer) if fallback_pointer else None

    required = [
        instruction_evidence(caller, 0x438ad8, 'mov', '0x94af54'),
        instruction_evidence(caller, 0x438add, 'mov', '0x8'),
        instruction_evidence(caller, 0x438ae2, 'rep', 'movs'),
        instruction_evidence(caller, 0x438b07, 'mov', '[edi]'),
        instruction_evidence(caller, 0x438b09, 'push', 'eax'),
        instruction_evidence(caller, 0x438b0a, 'call', '0x438b48'),
        instruction_evidence(caller, 0x438b30, 'cmp', 'esi,0x8'),
        instruction_evidence(caller, 0x438b33, 'jb', '0x438af3'),
        instruction_evidence(helper, 0x438c03, 'mov', '[ebp+0x8]'),
        instruction_evidence(helper, 0x438c06, 'push', 'ecx'),
        instruction_evidence(helper, 0x438c07, 'push', 'ebx'),
    ]
    expected_calls = {
        0x438b81: 'GetSystemDirectoryA',
        0x438be5: 'CreateFileA',
        0x438c08: 'DeviceIoControl',
        0x438c19: 'CloseHandle',
    }
    slots = all_import_slots(view)
    resolved = {}
    for site, expected in sorted(expected_calls.items()):
        inst = next((i for i in helper if i['va'] == site and i['mnemonic'] == 'call'), None)
        target = target_number(inst['operands']) if inst else None
        thunk = resolve_iat_jump(view, target, slots) if target is not None else None
        resolved[site] = {'site_va': '0x%08x' % site,
                          'expected_api': expected, 'thunk': thunk,
                          'matched': bool(thunk and thunk['name'] == expected)}

    movement = {
        'createfile_return_to_ebx': instruction_evidence(helper, 0x438bea, 'mov', 'ebx,eax'),
        'invalid_handle_compare': instruction_evidence(helper, 0x438bec, 'cmp', 'ebx,0xffffffff'),
        'skip_on_invalid_handle': instruction_evidence(helper, 0x438bef, 'je', '0x438c1e'),
        'open_path_from_candidate': instruction_evidence(helper, 0x438be2, 'mov', '[esi]'),
        'drive_letter_patch': instruction_evidence(helper, 0x438bba, 'mov', 'BYTE PTR [ebp-0x2c],cl'),
        'control_return_test': instruction_evidence(helper, 0x438c0d, 'test', 'eax,eax'),
        'status_flag_write': instruction_evidence(helper, 0x438c11, 'mov', '[ebp-0x28],0x1'),
        'closehandle_argument': instruction_evidence(helper, 0x438c18, 'push', 'ebx'),
        'early_stop_check': instruction_evidence(helper, 0x438c22, 'cmp', '[ebp-0x28],0x0'),
    }
    caller_graph = inspect_function(caller, ANCHORS['caller_entry'])
    helper_targets = {int(info['thunk']['thunk_va'], 16): info['expected_api']
                      for info in resolved.values() if info['matched']}
    helper_graph = inspect_function(
        helper, ANCHORS['helper_entry'], helper_targets, set(expected_calls.values()))
    return {
        'schema': 'rea-cycle6-contract-v1',
        'candidate_codes': ['0x%08x' % x for x in table],
        'code_count': len(table),
        'code_table': {'va': '0x%08x' % anchors['table_va'],
                       'byte_count': len(table) * 4, 'format': 'dword_le'},
        'code_to_api_hypothesis': {
            'observed_instruction_links': all(e['present'] for e in required)
            and all(info['matched'] for info in resolved.values()),
            'edges': ('PE data table -> stack copy -> caller loop -> '
                      'helper argument [EBP+8] -> DeviceIoControl argument 2'),
            'instruction_evidence': required,
            'limitations': 'Control flow can skip calls or exit early; no runtime data observed.',
        },
        'import_calls': list(resolved.values()),
        'candidate_paths': {
            'template': prefix, 'fallback_string': fallback,
            'fallback_pointer_va': '0x%08x' % fallback_pointer,
            'dynamic_drive_letter_evidence': bool(
                movement['drive_letter_patch']['present'] and resolved[0x438b81]['matched']),
            'limitations': 'Actual target drive, handles and successful opens are unknown.',
        },
        'handle_and_status_evidence': movement,
        'graphs': {
            'caller': {'entry_va': '0x%08x' % ANCHORS['caller_entry'],
                       'reachable_instructions': caller_graph['reachable_instructions'],
                       'backward_edges': caller_graph['loop_back_edges'],
                       'unresolved_edges': caller_graph['unresolved_edges']},
            'helper': {'entry_va': '0x%08x' % ANCHORS['helper_entry'],
                       'reachable_instructions': helper_graph['reachable_instructions'],
                       'backward_edges': helper_graph['loop_back_edges'],
                       'unresolved_edges': helper_graph['unresolved_edges'],
                       'calls_to_imports': helper_graph['calls_to_imports']},
        },
        'unknowns': [
            'No execution, emulation, or kernel driver inspection.',
            'IOCTL semantics and buffers are not established.',
            'Function limits are candidates and runtime reachability is unverified.',
            'Windows 7 SP1 x86/x64 compatibility is not validated.',
        ],
    }


def analyze_path(path):
    path = pathlib.Path(path)
    if path.stat().st_size > MAX_PE:
        raise ValueError('PE above size limit')
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA:
        raise ValueError('Unexpected SHA-256; contracts apply only to pinned PE version')
    view = PEView(data)
    if is_pe64(view) or view.machine != 0x14c:
        raise ValueError('Only x86 PE32 is supported')
    caller = decode_function(path, ANCHORS['caller_entry'], ANCHORS['caller_end'])
    helper = decode_function(path, ANCHORS['helper_entry'], ANCHORS['helper_end'])
    result = derive_contract(view, caller, helper)
    result.update({'source': path.name, 'sha256': digest})
    return result


def analyze_archive(path, member='Faronics_DFS/DFStd.exe'):
    with zipfile.ZipFile(path) as archive:
        matches = [i for i in archive.infolist() if i.filename == member]
        if len(matches) != 1:
            raise ValueError('Missing or duplicate ZIP member')
        info = matches[0]
        if info.is_dir() or info.flag_bits & 1 or info.file_size > MAX_PE:
            raise ValueError('Invalid ZIP member')
        with tempfile.TemporaryDirectory(prefix='rea-contract-') as directory:
            local_path = pathlib.Path(directory) / 'sample.exe'
            with archive.open(info) as source, local_path.open('xb') as target:
                os.chmod(str(local_path), 0o600)
                count = 0
                for chunk in iter(lambda: source.read(1024 * 1024), b''):
                    count += len(chunk)
                    if count > info.file_size:
                        raise ValueError('Invalid decompressed size')
                    target.write(chunk)
                if count != info.file_size:
                    raise ValueError('Truncated ZIP member')
            result = analyze_path(local_path)
    result['source'] = member
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--archive')
    group.add_argument('--pe')
    parser.add_argument('--member', default='Faronics_DFS/DFStd.exe')
    parser.add_argument('--json', dest='output')
    args = parser.parse_args(argv)
    try:
        result = (analyze_archive(args.archive, args.member) if args.archive
                  else analyze_path(args.pe))
        body = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + '\n'
        if args.output:
            pathlib.Path(args.output).write_text(body, encoding='utf-8')
        else:
            sys.stdout.write(body)
        return 0
    except (PEError, OSError, ValueError, zipfile.BadZipFile) as exc:
        print('REA cycle 6 failed: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
