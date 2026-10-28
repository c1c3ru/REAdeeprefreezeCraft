#!/usr/bin/env python3
"""REA cycle 5: bounded, read-only x86 function CFG and structural contracts.

GNU objdump decodes a candidate function. Worklists identify reachable
instructions, basic blocks, branch dominators and backward edges. No execution.
Python 3.8+, stdlib and binutils. Never claims full semantic equivalence.
"""
import argparse
import collections
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import zipfile

try:
    from .rea_structural import PEError, PEView
    from .rea_loop import analyze_pe as inspect_metadata, MAX_PE
except ImportError:
    from rea_structural import PEError, PEView
    from rea_loop import analyze_pe as inspect_metadata, MAX_PE

INSTRUCTION = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)\s+([a-zA-Z][.\w]*)\s*(.*?)\s*$")
FRAME_ARG = re.compile(r"\[ebp\+0x[0-9a-f]+\]", re.I)
MAX_WINDOW = 4096
MAX_INSTRUCTIONS = 1000


def target_number(value):
    if "[" in value or "PTR" in value:
        return None
    match = re.match(r"^\s*(?:0x)?([0-9a-fA-F]+)(?:\s|$)", value)
    return int(match.group(1), 16) if match else None


def decode_function(path, entry, stop, objdump="objdump"):
    if not 0 < stop - entry <= MAX_WINDOW:
        raise ValueError("Function window must be 1..4096 bytes")
    command = [objdump, "-D", "-M", "intel", "--start-address=0x%x" % entry,
               "--stop-address=0x%x" % stop, str(path)]
    try:
        run = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             timeout=12, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("Disassembler unavailable: %s" % exc)
    if run.returncode or len(run.stdout) > 512 * 1024:
        raise ValueError("Invalid or oversized disassembly output")
    instructions = []
    for line in run.stdout.decode("utf-8", "replace").splitlines():
        match = INSTRUCTION.match(line)
        if match:
            instructions.append({
                "va": int(match.group(1), 16),
                "size": len(bytes.fromhex(match.group(2))),
                "mnemonic": match.group(3).lower(),
                "operands": match.group(4).strip(),
            })
        if len(instructions) > MAX_INSTRUCTIONS:
            raise ValueError("Too many instructions")
    if not instructions or instructions[0]["va"] != entry:
        raise ValueError("Function entry not decoded at expected boundary")
    return instructions


def build_graph(insns, entry):
    by_addr = {item["va"]: item for item in insns}
    if len(by_addr) != len(insns) or entry not in by_addr:
        raise ValueError("Duplicate/missing decoded addresses")
    edges, unresolved = {}, []
    visited = set()
    queue = collections.deque([entry])
    while queue:
        addr = queue.popleft()
        if addr in visited:
            continue
        visited.add(addr)
        instruction = by_addr[addr]
        op = instruction["mnemonic"]
        nextva = addr + instruction["size"]
        if op.startswith("ret") or op in ("int3", "ud2"):
            targets = []
        elif op == "jmp":
            target = target_number(instruction["operands"])
            targets = [target] if target is not None else []
            if target is None:
                unresolved.append({"va": "0x%x" % addr, "reason": "indirect_jump"})
        elif op.startswith("j") or op in ("loop", "loope", "loopne"):
            target = target_number(instruction["operands"])
            targets = [nextva] + ([target] if target is not None else [])
            if target is None:
                unresolved.append({"va": "0x%x" % addr, "reason": "unknown_conditional_target"})
        else:
            targets = [nextva]
        edges[addr] = []
        for dest in dict.fromkeys(targets):
            if dest in by_addr:
                edges[addr].append(dest)
                if dest not in visited:
                    queue.append(dest)
            else:
                unresolved.append({
                    "va": "0x%x" % addr,
                    "reason": "edge_out_of_window",
                    "target": None if dest is None else "0x%x" % dest,
                })
    return by_addr, visited, edges, unresolved


def dominators(entry, reachable, edges):
    predecessors = {addr: set() for addr in reachable}
    for source, targets in edges.items():
        for target in targets:
            if target in predecessors:
                predecessors[target].add(source)
    dom = {addr: ({entry} if addr == entry else set(reachable)) for addr in reachable}
    for _ in range(max(1, len(reachable) + 1)):
        changed = False
        for addr in sorted(reachable):
            if addr == entry:
                continue
            parents = predecessors[addr]
            new = {addr} | (set.intersection(*(dom[p] for p in parents)) if parents else set())
            if new != dom[addr]:
                changed = True
                dom[addr] = new
        if not changed:
            return dom
    raise ValueError("Dominator analysis did not converge")


def basic_blocks(by_addr, reachable, edges, entry):
    leaders = {entry}
    for addr in reachable:
        targets = edges[addr]
        nextva = addr + by_addr[addr]["size"]
        if len(targets) != 1 or targets[0] != nextva:
            leaders.update(targets)
            if nextva in reachable:
                leaders.add(nextva)
    result, consumed = [], set()
    for leader in sorted(leaders):
        if leader in consumed or leader not in reachable:
            continue
        collected = []
        pos = leader
        while pos in reachable and pos not in consumed:
            consumed.add(pos)
            collected.append(pos)
            dests = edges[pos]
            fallthrough = pos + by_addr[pos]["size"]
            if len(dests) != 1 or dests[0] != fallthrough or fallthrough in leaders:
                break
            pos = fallthrough
        last = collected[-1]
        result.append({
            "start_va": "0x%x" % leader,
            "end_va": "0x%x" % last,
            "instruction_count": len(collected),
            "successors": ["0x%x" % value for value in edges[last]],
        })
    return result


def inspect_function(insns, entry, api_targets=None, interesting=None):
    """Pure graph analysis: no binary, emulator or external process required."""
    api_targets = api_targets or {}
    interesting = set(interesting or ("CreateFileA", "DeviceIoControl", "CloseHandle"))
    by_addr, reachable, edges, unresolved = build_graph(insns, entry)
    dom = dominators(entry, reachable, edges)
    calls, direct_calls, back_edges = [], [], []
    for addr in sorted(reachable):
        inst = by_addr[addr]
        if inst["mnemonic"] == "call":
            dest = target_number(inst["operands"])
            if dest is not None:
                direct_calls.append({
                    "from_va": "0x%x" % addr, "to_va": "0x%x" % dest,
                    "inside_window": dest in by_addr,
                })
            api = api_targets.get(dest)
            if api in interesting:
                calls.append({
                    "va": "0x%x" % addr, "api": api,
                    "target_va": "0x%x" % dest,
                    "dominator_count": len(dom[addr]),
                })
        for dest in edges[addr]:
            if dest <= addr:
                back_edges.append({
                    "from_va": "0x%x" % addr, "to_va": "0x%x" % dest,
                    "type": ("natural_loop_back_edge_candidate" if dest in dom[addr]
                             else "backward_edge_without_dominance"),
                })
    guards = []
    for addr in sorted(reachable):
        inst = by_addr[addr]
        nextva = addr + inst["size"]
        if not (inst["mnemonic"].startswith("j") and inst["mnemonic"] != "jmp"
                and nextva in edges[addr]):
            continue
        for call in calls:
            if addr in dom[int(call["va"], 16)]:
                guards.append({
                    "branch_va": "0x%x" % addr, "mnemonic": inst["mnemonic"],
                    "call_va": call["va"], "fallthrough_va": "0x%x" % nextva,
                    "target_va": inst["operands"],
                    "certainty": "branch_dominates_call_not_condition",
                })
    frame_reads = sorted({
        match.group(0).lower()
        for addr in reachable
        for match in FRAME_ARG.finditer(by_addr[addr]["operands"])
    })
    return {
        "schema": "rea-function-cfg-v1",
        "entry_va": "0x%x" % entry,
        "entry_prologue_candidate": (
            len(insns) > 1 and insns[0]["mnemonic"] == "push"
            and insns[0]["operands"] == "ebp"
            and insns[1]["mnemonic"] == "mov"
            and insns[1]["operands"] == "ebp,esp"),
        "end_ret_observed": insns[-1]["mnemonic"].startswith("ret"),
        "decoded_instructions": len(insns),
        "reachable_instructions": len(reachable),
        "unreachable_instructions": len(insns) - len(reachable),
        "basic_blocks": basic_blocks(by_addr, reachable, edges, entry),
        "direct_calls": direct_calls,
        "calls_to_imports": calls,
        "conditional_guards": guards,
        "loop_back_edges": back_edges,
        "frame_argument_reads_candidates": frame_reads,
        "unresolved_edges": unresolved,
        "limits": [
            "Bounds are candidate function boundaries, not verified symbols.",
            "Only static direct branch targets; indirect targets unresolved.",
            "Frame reads cannot establish types, device identity or runtime behavior.",
        ],
    }


def analyze_pe_file(path, entry, stop):
    path = pathlib.Path(path)
    if path.stat().st_size > MAX_PE:
        raise ValueError("PE above maximum size")
    payload = path.read_bytes()
    view = PEView(payload)
    if getattr(view, "pe64", getattr(view, "pe32plus", False)) or view.machine != 0x14c:
        raise ValueError("Only x86 PE32 supported")
    metadata, _ = inspect_metadata(payload, path.name)
    image_base = int(metadata["image_base"], 16)
    for va in (entry, stop - 1):
        rva = va - image_base
        view.rva_offset(rva)
        if not any(s["rva"] <= rva < s["rva"] + s["raw_size"]
                   and s["name"] in (".text", "CODE", ".code") for s in view.sections):
            raise ValueError("Selected address not in known code section")
    thunks = {image_base + item["rva"]: item["api"]
              for item in metadata["import_thunks"]}
    result = inspect_function(decode_function(path, entry, stop), entry, thunks)
    result["input_sha256"] = hashlib.sha256(payload).hexdigest()
    result["source"] = path.name
    result["stop_va"] = "0x%x" % stop
    return result


def analyze_archive(path, member, entry, stop):
    with zipfile.ZipFile(path) as archive:
        entries = [info for info in archive.infolist() if info.filename == member]
        if len(entries) != 1:
            raise ValueError("Missing or ambiguous archive member")
        info = entries[0]
        if info.is_dir() or info.flag_bits & 1 or info.file_size > MAX_PE:
            raise ValueError("Invalid PE member")
        with tempfile.TemporaryDirectory(prefix="rea-func-") as folder:
            temporary = pathlib.Path(folder) / "sample.exe"
            with archive.open(info) as source, temporary.open("xb") as dest:
                os.chmod(temporary, 0o600)
                seen = 0
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    seen += len(block)
                    if seen > info.file_size:
                        raise ValueError("ZIP size mismatch")
                    dest.write(block)
                if seen != info.file_size:
                    raise ValueError("ZIP truncated")
            result = analyze_pe_file(temporary, entry, stop)
    result["source"] = member
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--archive")
    group.add_argument("--pe")
    parser.add_argument("--member", default="Faronics_DFS/DFStd.exe")
    parser.add_argument("--entry", type=lambda s: int(s, 0), required=True)
    parser.add_argument("--stop", type=lambda s: int(s, 0), required=True)
    parser.add_argument("--json", dest="outfile")
    args = parser.parse_args(argv)
    try:
        report = (analyze_archive(args.archive, args.member, args.entry, args.stop)
                  if args.archive else analyze_pe_file(args.pe, args.entry, args.stop))
        output = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        if args.outfile:
            pathlib.Path(args.outfile).write_text(output, encoding="utf-8")
        else:
            sys.stdout.write(output)
        return 0
    except (ValueError, PEError, OSError, zipfile.BadZipFile) as exc:
        print("REA function CFG error: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
