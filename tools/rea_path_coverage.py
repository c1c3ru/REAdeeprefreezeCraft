#!/usr/bin/env python3
"""REA-007: bounded static branch-outcome/exit enumeration for candidate x86 functions.

No PE execution or IOCTL invocation. Finite path exploration OVER-approximates
branch outcomes (it does not solve register/memory constraints). Loops are cut
after bounded revisits. Reports distinguish explicit returns from unknown exits.
Python 3.8+; objdump needed only for --pe/--archive.
"""
import argparse
import collections
import hashlib
import json
import os
import pathlib
import tempfile
import zipfile

try:
    from .rea_function_cfg import decode_function, build_graph, dominators, target_number
    from .rea_structural import PEError, PEView
    from .rea_loop import MAX_PE
except ImportError:
    from rea_function_cfg import decode_function, build_graph, dominators, target_number
    from rea_structural import PEError, PEView
    from rea_loop import MAX_PE

EXPECTED_SHA256 = "2d7c171d4037660843a7e02c055679c5a26904af84d48fc8c557a67023f55c8b"
FUNCTIONS = (
    ("caller", 0x438ac0, 0x438b48),
    ("helper", 0x438b48, 0x438c41),
)
CONDITIONAL_PREFIX = ("j", "loop")
MAX_STATES = 5000
MAX_PATHS = 256
MAX_DEPTH = 500
MAX_VISITS = 2


def hx(value):
    return "0x%08x" % value


def classify(inst):
    mnemonic = inst["mnemonic"].lower()
    if mnemonic.startswith("ret"):
        return "return"
    if mnemonic in ("ud2", "int3", "hlt"):
        return "trap_or_halt"
    if mnemonic == "jmp":
        return "jump"
    if (mnemonic.startswith("j") and mnemonic != "jmp"
            or mnemonic.startswith("loop")):
        return "conditional"
    return "fallthrough"


def successors(instruction):
    """Edge labels are syntactic and deliberately do not assert feasibility."""
    kind = classify(instruction)
    addr = instruction["va"]
    next_va = addr + instruction["size"]
    direct = target_number(instruction["operands"])
    if kind in ("return", "trap_or_halt"):
        return []
    if kind == "jump":
        return [("jump", direct)]
    if kind == "conditional":
        return [("not_taken", next_va), ("taken", direct)]
    return [("next", next_va)]


def previous_predicate(insns, index):
    """Nearby flags-setting candidate; never evidence of a proven condition."""
    for previous in reversed(insns[max(0, index - 5):index]):
        op = previous["mnemonic"].lower()
        if op in ("cmp", "test"):
            return {"va": hx(previous["va"]), "mnemonic": op,
                    "operands": previous["operands"], "strength": "nearby_candidate"}
        if op in ("call", "jmp") or op.startswith("ret"):
            break
    return None


def analyze_paths(insns, entry, max_states=MAX_STATES,
                  max_paths=MAX_PATHS, max_depth=MAX_DEPTH, max_visits=MAX_VISITS):
    """Finite DFS of decoded instruction boundaries; never models conditions.

    Each distinct syntactic outcome is tracked even if another path can reach
    the same instruction. A loop cut is NOT an observed function exit.
    """
    if min(max_states, max_paths, max_depth, max_visits) < 1:
        raise ValueError("Exploration limits must be positive")
    if max_states > 200000 or max_paths > 10000 or max_depth > 2000 or max_visits > 10:
        raise ValueError("Exploration limits exceed safety cap")
    by, reachable, edges, unresolved_graph = build_graph(insns, entry)
    positions = {item["va"]: i for i, item in enumerate(insns)}
    dom = dominators(entry, reachable, edges)
    branch_sites = []
    for va in sorted(reachable):
        inst = by[va]
        if classify(inst) != "conditional":
            continue
        branch_sites.append({
            "site_va": hx(va), "mnemonic": inst["mnemonic"],
            "predicate_candidate": previous_predicate(insns, positions[va]),
            "outcomes": [
                {"decision": decision, "target_va": None if dst is None else hx(dst),
                 "in_window": dst in by}
                for decision, dst in successors(inst)
            ],
        })
    seen = collections.defaultdict(set)
    terminals = collections.Counter()
    examples = []
    reasons = collections.Counter()
    state_count = 0
    truncated = False
    # (va, per-instruction visits, decision history, depth)
    stack = [(entry, {}, (), 0)]
    while stack:
        if state_count >= max_states or len(examples) >= max_paths:
            truncated = True
            break
        va, visits, decisions, depth = stack.pop()
        state_count += 1
        def finish(reason, at):
            terminals[reason] += 1
            examples.append({"reason": reason, "last_va": hx(at),
                             "decisions": list(decisions)})
        if depth >= max_depth:
            finish("depth_limit", va)
            continue
        if va not in by:
            finish("edge_out_of_window", va)
            continue
        if visits.get(va, 0) >= max_visits:
            finish("loop_visit_limit", va)
            continue
        inst = by[va]
        visits = dict(visits)
        visits[va] = visits.get(va, 0) + 1
        kind = classify(inst)
        if kind == "return":
            finish("explicit_return", va)
            continue
        if kind == "trap_or_halt":
            finish("trap_or_halt", va)
            continue
        transitions = successors(inst)
        if not transitions:
            finish("no_successor", va)
            continue
        for decision, target in reversed(transitions):
            newdecisions = decisions
            if kind == "conditional":
                seen[va].add(decision)
                newdecisions += ({"site_va": hx(va), "decision": decision,
                                  "target_va": hx(target) if target is not None else None},)
            if target is None:
                # Indirect conditional branch cannot be treated as a feasible target.
                terminals["indirect_or_unresolved_target"] += 1
                examples.append({"reason": "indirect_or_unresolved_target",
                                 "last_va": hx(va), "decisions": list(newdecisions)})
            else:
                stack.append((target, visits, newdecisions, depth + 1))
    if stack:
        truncated = True
    for b in branch_sites:
        va = int(b["site_va"], 16)
        b["explored_outcomes"] = sorted(seen[va])
        b["unexplored_outcomes"] = sorted({"taken", "not_taken"} - seen[va])
        b["dominates_return_candidates"] = [
            hx(addr) for addr in sorted(reachable)
            if classify(by[addr]) == "return" and va in dom[addr]
        ]
    backwards = []
    for source, dests in sorted(edges.items()):
        for dest in dests:
            if dest <= source:
                backwards.append({
                    "from_va": hx(source), "to_va": hx(dest),
                    "classification": ("natural_loop_back_edge_candidate" if dest in dom[source]
                                       else "backward_edge_without_dominance"),
                })
    return {
        "schema": "rea-branch-coverage-v1",
        "entry_va": hx(entry),
        "reachable_instruction_count": len(reachable),
        "conditional_sites": branch_sites,
        "conditional_count": len(branch_sites),
        "return_sites": [hx(addr) for addr in sorted(reachable)
                         if classify(by[addr]) == "return"],
        "backward_edges": backwards,
        "unresolved_edges": unresolved_graph,
        "terminal_path_samples": dict(sorted(terminals.items())),
        "path_samples": examples,
        "states_explored": state_count,
        "truncated": truncated,
        "all_syntactic_outcomes_explored": (
            not truncated and all(not b["unexplored_outcomes"] for b in branch_sites)),
        "coverage_meaning": ("Bounded syntactic exploration only: branch choices are not "
                             "verified as satisfiable. Loop visit caps are not program exits."),
        "limits": {"max_states": max_states, "max_paths": max_paths,
                   "max_depth": max_depth, "max_visits_per_instruction": max_visits},
        "warnings": [
            "External calls assumed to fall through; non-returning callees not resolved.",
            "Conditional flags and memory constraints not symbolically evaluated.",
            "Candidate function boundaries are not proven global function boundaries.",
        ],
    }


def analyze_file(path):
    path = pathlib.Path(path)
    if path.stat().st_size > MAX_PE:
        raise ValueError("PE exceeds limit")
    raw = path.read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    if actual != EXPECTED_SHA256:
        raise ValueError("SHA-256 mismatch: known offsets apply only to pinned DFStd.exe")
    view = PEView(raw)
    if view.machine != 0x14c or view.pe64:
        raise ValueError("Expected PE32 x86")
    results = []
    for label, entry, stop in FUNCTIONS:
        decoded = decode_function(path, entry, stop)
        result = analyze_paths(decoded, entry)
        result["function"] = label
        result["stop_va_exclusive"] = hx(stop)
        results.append(result)
    return {
        "schema": "rea-007-v1",
        "source": path.name, "sha256": actual,
        "functions": results,
        "verified_behavior": False,
        "windows7_x86_validated": False, "windows7_x64_validated": False,
    }


def analyze_archive(path, member="Faronics_DFS/DFStd.exe"):
    with zipfile.ZipFile(path) as archive:
        matched = [item for item in archive.infolist() if item.filename == member]
        if len(matched) != 1 or matched[0].is_dir() or matched[0].flag_bits & 1:
            raise ValueError("Missing, duplicated, or encrypted archive member")
        info = matched[0]
        if info.file_size > MAX_PE:
            raise ValueError("PE exceeds limit")
        with tempfile.TemporaryDirectory(prefix="rea-007-") as folder:
            temp = pathlib.Path(folder) / "sample.exe"
            with archive.open(info) as source, temp.open("xb") as target:
                os.chmod(str(temp), 0o600)
                total = 0
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    total += len(chunk)
                    if total > info.file_size:
                        raise ValueError("Uncompressed ZIP size mismatch")
                    target.write(chunk)
                if total != info.file_size:
                    raise ValueError("Truncated ZIP entry")
            report = analyze_file(temp)
    report["source"] = member
    return report


def markdown(report):
    lines = ["# REA-007 — Control-flow exit/branch evidence", "",
             "**File:** " + report["source"], "**SHA-256:** " + report["sha256"], "",
             "**Not runtime evidence.** Bounded graph traversal overapproximates paths.", ""]
    for item in report["functions"]:
        lines += ["## " + item["function"], "",
                  "- Candidate entry: " + item["entry_va"],
                  "- Reachable instructions: " + str(item["reachable_instruction_count"]),
                  "- Conditional sites: " + str(item["conditional_count"]),
                  "- Return sites: " + ", ".join(item["return_sites"]),
                  "- Backward edges: " + str(len(item["backward_edges"])),
                  "- All syntactic outcomes explored: " + str(item["all_syntactic_outcomes_explored"]),
                  "- Exploration truncated: " + str(item["truncated"]), "",
                  "| Branch VA | Condition | Nearby predicate | Taken / not-taken |",
                  "|---|---|---|---|"]
        for branch in item["conditional_sites"]:
            pred = branch["predicate_candidate"]
            predicate = ((pred["mnemonic"] + " " + pred["operands"])
                         if pred else "unresolved")
            choices = " ; ".join(e["decision"] + ":" + (e["target_va"] or "?")
                                 for e in branch["outcomes"])
            lines.append("| " + branch["site_va"] + " | " + branch["mnemonic"]
                         + " | " + predicate + " | " + choices + " |")
        lines.extend(["", "- Terminal **sample** counts: " +
                      json.dumps(item["terminal_path_samples"], sort_keys=True),
                      "- Unresolved graph edges: " + str(len(item["unresolved_edges"])), ""])
    lines += [
        "## Limitations", "",
        "Syntactic outcomes have not been proven feasible. Calls may not return. "
        "Loop cuts are analytical, not product exits. No driver/Windows 7 execution occurred.", "",
    ]
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pe")
    group.add_argument("--archive")
    parser.add_argument("--member", default="Faronics_DFS/DFStd.exe")
    parser.add_argument("--json", dest="json_path")
    parser.add_argument("--markdown", dest="markdown_path")
    args = parser.parse_args(argv)
    try:
        result = analyze_archive(args.archive, args.member) if args.archive else analyze_file(args.pe)
        output = json.dumps(result, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
        if args.json_path:
            pathlib.Path(args.json_path).write_text(output, encoding="utf-8")
        else:
            print(output, end="")
        if args.markdown_path:
            pathlib.Path(args.markdown_path).write_text(markdown(result), encoding="utf-8")
        return 0
    except (OSError, ValueError, PEError, zipfile.BadZipFile) as exc:
        print("REA-007 failed: " + str(exc), file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
