#!/usr/bin/env python3
"""Loop REA: importacoes PE -> thunks x86 -> xrefs E8/FF15 -> hipoteses de argumentos.

Analisador OFFLINE, Python 3.8+, biblioteca padrao. Nunca executa, descompacta
UPX, instala drivers ou exporta recursos proprietarios. Achados sao candidatos.
"""
import argparse
import hashlib
import json
import pathlib
import struct
import sys
import zipfile

try:
    from .rea_structural import PEView, PEError, MAX_PE
except ImportError:
    from rea_structural import PEView, PEError, MAX_PE

MAX_ZIP_ENTRIES = 512
MAX_ZIP_TOTAL = 256 * 1024 * 1024
MAX_CALLSITES = 20000
TARGETS = {
    "DeviceIoControl": "device_interface",
    "CreateFileW": "handle_candidate",
    "CreateFileA": "handle_candidate",
    "CreateServiceW": "service_control",
    "StartServiceW": "service_control",
    "ControlService": "service_control",
    "OpenServiceW": "service_control",
    "OpenSCManagerW": "service_control",
    "RegLoadKeyW": "registry",
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def image_base(view):
    opt = view.u32(0x3c) + 24
    return view.u64(opt + 24) if view.pe64 else view.u32(opt + 28)


def executable_sections(view):
    pe = view.u32(0x3c)
    offset = pe + 24 + view.u16(pe + 20)
    return [section for index, section in enumerate(view.sections)
            if section["raw_size"] and view.u32(offset + 40 * index + 36) & 0x20000000]


def import_slots(view):
    """Rastreia nomes de importacao ate slots na IAT, validando limites RVA."""
    rva, size = view.directory(1)
    if not rva or not size:
        return []
    width = 8 if view.pe64 else 4
    ordinal = 1 << (63 if view.pe64 else 31)
    slots = []
    terminated = False
    for i in range(min(256, size // 20)):
        at = view.rva_offset(rva + 20 * i, 20)
        lookup, stamp, chain, name, first = struct.unpack_from("<IIIII", view.data, at)
        if not any((lookup, stamp, chain, name, first)):
            terminated = True
            break
        dll = view.asciiz(view.rva_offset(name))
        for j in range(4096):
            entry = view.rva_offset((lookup or first) + j * width, width)
            value = view.u64(entry) if view.pe64 else view.u32(entry)
            if not value:
                break
            if value & ordinal:
                continue
            name = view.asciiz(view.rva_offset(value + 2))
            if name in TARGETS:
                slots.append({
                    "dll": dll, "api": name, "category": TARGETS[name],
                    "iat_rva": first + j * width,
                    "iat_va": image_base(view) + first + j * width,
                })
        else:
            raise PEError("Importacoes excederam limite")
    if not terminated:
        raise PEError("Descritores de importacao nao terminados")
    return slots


def ioctl_candidate(data, pos):
    """Padroes locais x86: valor na pilha; sem afirmar o significado semantico."""
    if pos >= 6 and data[pos - 6] == 0x68 and 0x50 <= data[pos - 1] <= 0x57:
        code = struct.unpack_from("<I", data, pos - 5)[0]
        return {"candidate_code": "0x%08x" % code,
                "pattern": "push_imm32_push_reg", "confidence": "medium"}
    if (pos >= 9 and data[pos - 9] == 0x68 and data[pos - 4] == 0x8b
            and 0x50 <= data[pos - 1] <= 0x57):
        code = struct.unpack_from("<I", data, pos - 8)[0]
        return {"candidate_code": "0x%08x" % code,
                "pattern": "push_imm32_mov_push_reg", "confidence": "low"}
    return {"candidate_code": None, "pattern": "dynamic_or_unknown", "confidence": "unknown"}


def find_import_thunks(view, slots):
    """FF25 e FF15 com enderecos absolutos de IAT, candidatos x86."""
    index = {item["iat_va"]: item for item in slots}
    thunks, direct = [], []
    if view.pe64 or view.machine != 0x14c:
        return thunks, direct
    for section in executable_sections(view):
        start = section["offset"]
        raw = view.data[start:start + section["raw_size"]]
        cursor = 0
        while True:
            pos = raw.find(b"\xff", cursor)
            if pos < 0 or pos + 6 > len(raw):
                break
            cursor = pos + 1
            opcode = raw[pos + 1]
            if opcode not in (0x25, 0x15):
                continue
            imported = index.get(struct.unpack_from("<I", raw, pos + 2)[0])
            if imported is None:
                continue
            info = {"rva": section["rva"] + pos, "file_offset": start + pos,
                    "api": imported["api"], "dll": imported["dll"],
                    "iat_va": imported["iat_va"],
                    "evidence": "ff25_jump_iat_candidate" if opcode == 0x25
                    else "ff15_call_iat_candidate"}
            (thunks if opcode == 0x25 else direct).append(info)
    return sorted(thunks, key=lambda x: (x["rva"], x["api"])), direct


def find_calls(view, thunks, direct):
    """E8 rel32 ate thunks candidatos; correspondencia por bytes, nao CFG."""
    calls = list(direct)
    by_rva = {item["rva"]: item for item in thunks}
    if view.pe64 or view.machine != 0x14c:
        return calls
    for section in executable_sections(view):
        raw = view.data[section["offset"]:section["offset"] + section["raw_size"]]
        cursor = 0
        while True:
            pos = raw.find(b"\xe8", cursor)
            if pos < 0 or pos + 5 > len(raw):
                break
            cursor = pos + 1
            rva = section["rva"] + pos
            dest = rva + 5 + struct.unpack_from("<i", raw, pos + 1)[0]
            imported = by_rva.get(dest)
            if imported is None:
                continue
            item = {"rva": rva, "file_offset": section["offset"] + pos,
                    "destination_rva": dest, "api": imported["api"],
                    "dll": imported["dll"],
                    "evidence": "e8_rel32_to_import_thunk_candidate"}
            if imported["api"] == "DeviceIoControl":
                item["ioctl_argument_hypothesis"] = ioctl_candidate(raw, pos)
            calls.append(item)
            if len(calls) > MAX_CALLSITES:
                raise PEError("Excesso de candidatos a chamada")
    return sorted(calls, key=lambda x: (x["rva"], x["api"]))


def analyze_pe(data, identifier):
    view = PEView(data)
    slots = import_slots(view)
    thunks, direct = find_import_thunks(view, slots)
    calls = find_calls(view, thunks, direct)
    codes = sorted({call["ioctl_argument_hypothesis"]["candidate_code"]
                    for call in calls
                    if call.get("ioctl_argument_hypothesis", {}).get("candidate_code")})
    rounds = [
        {"iteration": 1, "phase": "IAT_imports", "new_candidates": len(slots)},
        {"iteration": 2, "phase": "FF25_FF15_thunks", "new_candidates": len(thunks) + len(direct)},
        {"iteration": 3, "phase": "E8_call_sites", "new_candidates": len(calls) - len(direct)},
        {"iteration": 4, "phase": "IOCTL_stack_literals", "new_candidates": len(codes)},
        {"iteration": 5, "phase": "fixed_point_no_new_candidates", "new_candidates": 0},
    ]
    result = {
        "id": identifier, "sha256": sha(data), "format": "PE32+" if view.pe64 else "PE32",
        "machine": "0x%04x" % view.machine, "image_base": "0x%x" % image_base(view),
        "entry_rva": "0x%x" % view.entry_rva, "imports_of_interest": slots,
        "import_thunks": thunks, "direct_iat_candidates": direct,
        "call_candidates": calls, "ioctl_literal_hypotheses": codes,
        "iterations": rounds,
        "limitations": [
            "Byte-pattern scanning does not validate instruction boundaries.",
            "IOCTL argument constants are hypotheses, not verified device contracts.",
            "Imports do not prove runtime calls or loaded drivers.",
            "Packed UPX code and PE32+ instruction xrefs are not reconstructed.",
        ],
    }
    return result, view


def safe_name(name):
    name = name.replace("\\", "/")
    return bool(name) and not name.startswith("/") and ":" not in name and ".." not in name.split("/")


def scan_package(zip_path=None, pe_path=None):
    sources = []
    if zip_path:
        budget = 0
        with zipfile.ZipFile(zip_path) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ZIP_ENTRIES:
                raise ValueError("ZIP excede limite de entradas")
            for info in infos:
                if info.is_dir() or not safe_name(info.filename) or info.flag_bits & 1:
                    continue
                budget += info.file_size
                if info.file_size > MAX_PE or budget > 256 * 1024 * 1024:
                    raise ValueError("ZIP excede limite de descompressao")
                if info.filename.lower().endswith((".exe", ".dll", ".sys")):
                    with archive.open(info) as source:
                        payload = source.read(MAX_PE + 1)
                    if len(payload) != info.file_size:
                        raise ValueError("Tamanho ZIP inconsistente")
                    sources.append((info.filename, payload))
    else:
        path = pathlib.Path(pe_path)
        if path.stat().st_size > MAX_PE:
            raise ValueError("Arquivo PE excede limite")
        sources.append((path.name, path.read_bytes()))
    results = []
    for identifier, data in sources:
        try:
            root, view = analyze_pe(data, identifier)
        except PEError as exc:
            results.append({"id": identifier, "sha256": sha(data), "parse_error": str(exc)})
            continue
        results.append(root)
        # Um nivel extra; nunca extrair arquivos para o disco.
        for resource in view.resources(depth=1):
            if resource["magic"] != "MZ":
                continue
            name = identifier + "::" + "/".join(resource["path"])
            offset, size = resource["file_offset"], resource["size"]
            payload = data[offset:offset + size]
            try:
                nested, _ = analyze_pe(payload, name)
                nested["parent_sha256"] = root["sha256"]
                results.append(nested)
            except PEError as exc:
                results.append({"id": name, "sha256": sha(payload), "parse_error": str(exc)})
    return {"schema": "rea-loop-v1", "source": pathlib.Path(zip_path or pe_path).name,
            "items": results, "safety": "Offline; no binaries extracted or executed."}


def markdown(report):
    lines = ["# Loop REA — resultados estaticos", "",
             "Fases: IAT -> thunks -> call sites -> argumentos -> ponto fixo.", "",
             "**ATENCAO:** candidatos sem validacao de limites de instrucao ou execucao.", ""]
    for item in report["items"]:
        lines += ["## " + item["id"], "", "- SHA-256: " + item["sha256"]]
        if item.get("parse_error"):
            lines += ["- Falha de parser: " + item["parse_error"], ""]
            continue
        calls = [c for c in item["call_candidates"] if c["api"] == "DeviceIoControl"]
        lines += ["- Importacoes de interesse: " + str(len(item["imports_of_interest"])),
                  "- Thunks candidatos: " + str(len(item["import_thunks"])),
                  "- Chamadas candidatas: " + str(len(item["call_candidates"])),
                  "- Chamadas DeviceIoControl candidatas: " + str(len(calls)),
                  "- Constantes distintas candidatas: " + str(len(item["ioctl_literal_hypotheses"])),
                  "", "| RVA | API | Codigo candidato | Confianca |",
                  "|---|---|---|---|"]
        for call in calls:
            h = call.get("ioctl_argument_hypothesis", {})
            lines.append("| 0x%x | %s | %s | %s |" %
                         (call["rva"], call["api"],
                          h.get("candidate_code") or "dinamico/indeterminado",
                          h.get("confidence", "unknown")))
        lines += ["", "| Loop | Etapa | Novos candidatos |", "|---:|---|---:|"]
        for rd in item["iterations"]:
            lines.append("| %s | %s | %s |" %
                         (rd["iteration"], rd["phase"], rd["new_candidates"]))
        lines += ["", "Limitacoes: " + "; ".join(item["limitations"]), ""]
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--archive", help="ZIP original; somente leitura")
    group.add_argument("--pe", help="PE isolado; somente leitura")
    parser.add_argument("--json", dest="json_path", help="Checkpoint JSON")
    parser.add_argument("--markdown", help="Relatorio Markdown")
    args = parser.parse_args(argv)
    try:
        report = scan_package(zip_path=args.archive, pe_path=args.pe)
        output = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        if args.json_path:
            pathlib.Path(args.json_path).write_text(output, encoding="utf-8")
        else:
            sys.stdout.write(output)
        if args.markdown:
            pathlib.Path(args.markdown).write_text(markdown(report), encoding="utf-8")
        return 0
    except (PEError, ValueError, OSError, zipfile.BadZipFile, RuntimeError) as exc:
        print("Erro no loop REA: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
