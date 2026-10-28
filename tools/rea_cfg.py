#!/usr/bin/env python3
"""REA ciclo 4: validação localizada de chamadas x86 com GNU objdump (offline).

A execução de objdump apenas lê e desmonta arquivos; o executável analisado
NUNCA é executado. O resultado é um grafo LOCAL com fluxo de dados conservador,
não um CFG global nem uma prova semântica. Requer binutils + Python 3.8+.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

try:
    from .rea_loop import analyze_pe, MAX_PE
    from .rea_structural import PEError
except ImportError:
    from rea_loop import analyze_pe, MAX_PE
    from rea_structural import PEError

INSTRUCTION = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)\s+([a-zA-Z][.\w]*)\s*(.*?)\s*$"
)
REGISTERS = {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}
IOCTL_ARGS = (
    "hDevice", "dwIoControlCode", "lpInBuffer", "nInBufferSize",
    "lpOutBuffer", "nOutBufferSize", "lpBytesReturned", "lpOverlapped"
)
MAX_SITES = 96
MAX_OBJ_TIMEOUT = 8
MAX_OUTPUT = 64 * 1024


class DisassemblyError(ValueError):
    pass


def disassemble_window(path, start, stop, objdump="objdump"):
    if stop <= start or stop - start > 256:
        raise DisassemblyError("Janela invalida")
    args = [
        objdump, "-D", "-M", "intel",
        "--start-address=0x%x" % start,
        "--stop-address=0x%x" % stop,
        str(path),
    ]
    try:
        process = subprocess.run(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=MAX_OBJ_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DisassemblyError("objdump indisponivel ou expirado: %s" % exc)
    if process.returncode != 0 or len(process.stdout) > MAX_OUTPUT:
        raise DisassemblyError("objdump falhou ou excedeu limite de saida")
    insns = []
    for line in process.stdout.decode("utf-8", "replace").splitlines():
        match = INSTRUCTION.match(line)
        if not match:
            continue
        address = int(match.group(1), 16)
        raw = bytes.fromhex(match.group(2))
        insns.append({
            "address": address, "size": len(raw), "bytes": raw.hex(),
            "mnemonic": match.group(3).lower(),
            "operands": match.group(4).strip(),
        })
    return insns


def target_number(operands):
    """Somente operandos hexadecimais diretos, sem referencias a memoria."""
    if "[" in operands or "PTR" in operands:
        return None
    match = re.match(r"^\s*(?:0x)?([0-9a-fA-F]+)(?:\s|$)", operands)
    if not match:
        return None
    return int(match.group(1), 16)


def last_assignment(insns, before, reg, thunk_addresses, depth=0):
    """Inferencia local de reaching-definition; caminhos condicionais incertos."""
    if depth > 3:
        return {"source": "register:" + reg, "confidence": "unknown"}
    uncertain = False
    for i in range(before - 1, max(-1, before - 64), -1):
        instruction = insns[i]
        op = instruction["mnemonic"]
        arg = instruction["operands"]
        if op.startswith("j") and op not in ("jmp",):
            uncertain = True
        if op in ("ret", "retn", "retf", "jmp"):
            return {"source": "register:" + reg, "confidence": "unknown",
                    "reason": "control_flow_boundary"}
        if op == "call":
            dest = target_number(arg)
            if reg == "eax":
                api = thunk_addresses.get(dest)
                if api:
                    return {"source": "return:" + api,
                            "confidence": "low" if uncertain else "medium"}
                return {"source": "unknown_call_return", "confidence": "unknown"}
            if reg in ("ecx", "edx"):
                return {"source": "register_clobbered_by_call", "confidence": "unknown"}
        if op not in ("mov", "lea", "xor") or "," not in arg:
            continue
        dst, value = [part.strip() for part in arg.split(",", 1)]
        if dst != reg:
            continue
        if op == "xor" and value == reg:
            return {"source": "0x0", "confidence": "low" if uncertain else "high"}
        if op == "lea":
            return {"source": "address_of:" + value,
                    "confidence": "low" if uncertain else "medium"}
        if op == "mov":
            if value in REGISTERS:
                prev = last_assignment(insns, i, value, thunk_addresses, depth + 1)
                if uncertain:
                    prev["confidence"] = "low"
                    prev["path_uncertain"] = True
                return prev
            return {"source": value,
                    "confidence": "low" if uncertain else "medium",
                    "path_uncertain": uncertain}
    return {"source": "register:" + reg, "confidence": "unknown"}


def stack_trace(insns, call_index, thunk_addresses, api):
    """Apenas as ultimas instrucoes do caminho linear ate uma fronteira."""
    ordered = []
    boundary = None
    for i in range(call_index - 1, max(-1, call_index - 64), -1):
        op = insns[i]["mnemonic"]
        if op in ("call", "ret", "retn", "retf", "jmp"):
            boundary = op + "_barrier"
            break
        if op == "push":
            value = insns[i]["operands"].strip()
            if value in REGISTERS:
                symbolic = last_assignment(insns, i, value, thunk_addresses)
            else:
                symbolic = {"source": value, "confidence": "high" if value.startswith("0x") else "low"}
            ordered.append({
                "source_rva": None,
                "instruction_va": "0x%x" % insns[i]["address"],
                "operand": value,
                "symbolic": symbolic,
            })
            if len(ordered) >= 8:
                break
    labels = IOCTL_ARGS if api == "DeviceIoControl" else ()
    for i, item in enumerate(ordered):
        item["argument"] = labels[i] if i < len(labels) else "stack_arg_%d" % (i + 1)
    candidate = None
    if api == "DeviceIoControl" and len(ordered) >= 2:
        source = ordered[1]["symbolic"]["source"]
        if re.fullmatch(r"0x[0-9a-fA-F]+", source):
            candidate = "0x%08x" % int(source, 16)
    return {
        "arguments": ordered,
        "complete_eight_argument_sequence": api == "DeviceIoControl" and len(ordered) == 8,
        "second_argument_source": ordered[1]["symbolic"] if len(ordered) > 1 else None,
        "constant_candidate": candidate,
        "boundary": boundary,
        "limitations": "Linear stack reconstruction; jumps, aliases and reaching paths may invalidate origins.",
    }


def local_branches(insns, call_index, lookback=35, lookahead=12):
    """Arestas de saltos diretos dentro de uma janela (CFG parcial)."""
    window = insns[max(0, call_index - lookback):call_index + lookahead]
    known = {x["address"] for x in window}
    edges = []
    for inst in window:
        mnemonic = inst["mnemonic"]
        if not mnemonic.startswith("j"):
            continue
        target = target_number(inst["operands"])
        if target is None:
            continue
        edges.append({
            "from_va": "0x%x" % inst["address"],
            "to_va": "0x%x" % target,
            "within_window": target in known,
            "type": "unconditional" if mnemonic == "jmp" else "conditional",
            "fallthrough_va": None if mnemonic == "jmp"
            else "0x%x" % (inst["address"] + inst["size"]),
        })
    return edges


def inspect_call(path, image_base, candidate, thunks, objdump):
    va = image_base + candidate["rva"]
    expected = image_base + candidate.get("destination_rva", -1)
    alignments = []
    # Tres pontos de partida independentes mitigam alguns falsos positivos,
    # mas nao substituem a decodificacao desde um inicio de funcao conhecido.
    for backward in (112, 104, 96):
        start = max(image_base, va - backward)
        lines = disassemble_window(path, start, va + 48, objdump)
        for index, inst in enumerate(lines):
            if inst["address"] != va or inst["mnemonic"] != "call":
                continue
            if inst["bytes"][:2] != "e8" or target_number(inst["operands"]) != expected:
                continue
            alignments.append((backward, lines, index))
            break
    record = {
        "rva": "0x%x" % candidate["rva"], "va": "0x%x" % va,
        "api": candidate["api"], "target_rva": "0x%x" % candidate.get("destination_rva", 0),
        "alignment_count": len(alignments), "classification": "unconfirmed",
    }
    if not alignments:
        return record
    record["classification"] = ("decoded_in_multiple_windows" if len(alignments) >= 2
                                 else "decoded_in_one_window")
    # Janela de maior profundidade, uma vez verificada a chamada.
    _, decoded, call_index = max(alignments, key=lambda x: (len(x[1][:x[2]]), x[0]))
    call = decoded[call_index]
    record["instruction_bytes"] = call["bytes"]
    record["cfg_local_edges"] = local_branches(decoded, call_index)
    mapping = {image_base + t["rva"]: t["api"] for t in thunks}
    record["stack_trace"] = stack_trace(decoded, call_index, mapping, candidate["api"])
    return record


def analyze_path(path, limit=MAX_SITES, objdump="objdump"):
    path = pathlib.Path(path)
    if path.stat().st_size > MAX_PE:
        raise ValueError("PE acima do limite")
    content = path.read_bytes()
    metadata, view = analyze_pe(content, path.name)
    if view.machine != 0x014c or view.pe64:
        raise ValueError("Este validador de instrucoes atualmente suporta somente x86 PE32")
    base = int(metadata["image_base"], 16)
    calls = [item for item in metadata["call_candidates"] if item.get("destination_rva") is not None]
    if len(calls) > limit:
        raise ValueError("Numero de chamadas acima do limite solicitado")
    results = [inspect_call(path, base, item, metadata["import_thunks"], objdump)
               for item in calls]
    classified = {}
    for item in results:
        key = item["classification"]
        classified[key] = classified.get(key, 0) + 1
    return {
        "schema": "rea-cfg-local-v1",
        "input_sha256": hashlib.sha256(content).hexdigest(),
        "source": path.name,
        "disassembler": "GNU objdump (binutils)",
        "validation": {
            "total_candidates": len(results),
            "classifications": classified,
            "interpretation": "Multiple decoding windows are heuristic evidence, not a verified global CFG.",
        },
        "calls": results,
        "limitations": [
            "No driver execution, IOCTL invocation, dynamic tracing, or full reachability analysis.",
            "Local decoding may start inside instructions; candidate instruction not guaranteed reachable.",
            "CFG edges cover only short local windows, not all function paths.",
            "Argument origin is path-insensitive and conservative; unresolved sources remain unknown.",
        ],
    }


def analyze_zip(path, member, limit=MAX_SITES, objdump="objdump"):
    with zipfile.ZipFile(path) as archive:
        matches = [i for i in archive.infolist() if i.filename == member and not i.is_dir()]
        if len(matches) != 1:
            raise ValueError("Membro ZIP nao encontrado ou duplicado")
        info = matches[0]
        if info.flag_bits & 1 or info.file_size > MAX_PE:
            raise ValueError("Entrada criptografada ou acima do limite")
        # Isolamento temporal: copia sob nome controlado, perms 0600,
        # eliminada ao terminar. Nunca usar o nome de arquivo do ZIP.
        with tempfile.TemporaryDirectory(prefix="rea-cfg-") as folder:
            temporary = pathlib.Path(folder) / "analysis.exe"
            with archive.open(info) as src, temporary.open("xb") as dest:
                os.chmod(str(temporary), 0o600)
                consumed = 0
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    consumed += len(chunk)
                    if consumed > info.file_size:
                        raise ValueError("Entrada ZIP inconsistente")
                    dest.write(chunk)
            if consumed != info.file_size:
                raise ValueError("Entrada ZIP truncada")
            report = analyze_path(temporary, limit=limit, objdump=objdump)
        report["source"] = member
        report["zip_sha256"] = hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
        return report


def render_markdown(report):
    lines = [
        "# REA — ciclo 4: decodificacao x86 e CFG local", "",
        "Arquivo: " + report["source"], "",
        "SHA-256: " + report["input_sha256"], "",
        "Confirmacao de opcode via objdump, **nao validacao de alcance em runtime**.", "",
        "| RVA | API | Janelas coerentes | Parametro 2 (hipotese) |",
        "|---|---|---:|---|",
    ]
    for call in report["calls"]:
        if call["api"] != "DeviceIoControl":
            continue
        trace = call.get("stack_trace", {})
        arg = trace.get("second_argument_source") or {}
        lines.append("| %s | %s | %d | %s |" % (
            call["rva"], call["api"], call["alignment_count"], arg.get("source", "indeterminado")))
    lines += [
        "", "## Resultado da checagem", "",
        "- Candidatos: " + str(report["validation"]["total_candidates"]),
        "- Classes: " + json.dumps(report["validation"]["classifications"], sort_keys=True),
        "", "## Limites", "",
    ]
    lines += ["- " + item for item in report["limitations"]]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pe", help="PE x86 local, somente leitura")
    group.add_argument("--archive", help="ZIP local")
    parser.add_argument("--member", default="Faronics_DFS/DFStd.exe",
                        help="Membro exato do ZIP para analisar; unico")
    parser.add_argument("--objdump", default="objdump")
    parser.add_argument("--json", dest="json_out")
    parser.add_argument("--markdown", dest="markdown_out")
    args = parser.parse_args(argv)
    try:
        if not shutil.which(args.objdump):
            raise DisassemblyError("GNU objdump nao encontrado")
        if args.pe:
            result = analyze_path(args.pe, objdump=args.objdump)
        else:
            result = analyze_zip(args.archive, args.member, objdump=args.objdump)
        payload = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        if args.json_out:
            pathlib.Path(args.json_out).write_text(payload, encoding="utf-8")
        else:
            sys.stdout.write(payload)
        if args.markdown_out:
            pathlib.Path(args.markdown_out).write_text(render_markdown(result), encoding="utf-8")
        return 0
    except (OSError, ValueError, PEError, DisassemblyError, zipfile.BadZipFile) as exc:
        print("Falha na validacao REA: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
