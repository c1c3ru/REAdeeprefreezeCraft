#!/usr/bin/env python3
"""Inventário estático e não executável de ZIPs com artefatos Windows PE.

Compatível com Python 3.8+ e sem dependências externas. Não extrai arquivos.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import struct
import sys
import zipfile

DEFAULT_MAX_MEMBER = 64 * 1024 * 1024
DEFAULT_MAX_TOTAL = 512 * 1024 * 1024
DEFAULT_MAX_ENTRIES = 1000
MARKERS = (
    "DeepFrz.sys", "DeepFrzx64.sys", "FarSpace.sys", "FarSpaceX64.sys",
    "DeviceIoControl", "CreateServiceW", "StartServiceW", "ControlService",
    "RegLoadKeyW", "InitiateSystemShutdownExW", "WinHttpSendRequest",
    "Thawspacehelper", "Authenticateuser", "Dflicense",
)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _u16(data, offset):
    if offset < 0 or offset + 2 > len(data):
        raise ValueError("Campo PE truncado")
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data, offset):
    if offset < 0 or offset + 4 > len(data):
        raise ValueError("Campo PE truncado")
    return struct.unpack_from("<I", data, offset)[0]


def inspect_pe(data):
    """Retorna metadados de um PE; dados não PE retornam None."""
    if len(data) < 64 or data[:2] != b"MZ":
        return None
    pe_offset = _u32(data, 0x3c)
    if pe_offset < 64 or pe_offset > len(data) - 24:
        raise ValueError("Ponteiro PE inválido")
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError("Assinatura PE ausente")
    coff = pe_offset + 4
    machine = _u16(data, coff)
    nsections = _u16(data, coff + 2)
    timestamp = _u32(data, coff + 4)
    opt_size = _u16(data, coff + 16)
    opt = coff + 20
    if nsections > 96 or opt + opt_size > len(data):
        raise ValueError("Cabeçalho PE/COFF fora dos limites")
    magic = _u16(data, opt)
    if magic not in (0x10b, 0x20b):
        raise ValueError("Formato OptionalHeader desconhecido")
    if opt_size < (96 if magic == 0x10b else 112):
        raise ValueError("OptionalHeader truncado")
    sections = []
    section_start = opt + opt_size
    for index in range(nsections):
        at = section_start + 40 * index
        if at + 40 > len(data):
            raise ValueError("Tabela de seções truncada")
        name = data[at:at + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        raw_size = _u32(data, at + 16)
        raw_offset = _u32(data, at + 20)
        if raw_size and (raw_offset > len(data) or raw_size > len(data) - raw_offset):
            raise ValueError("Seção aponta para fora do arquivo")
        sections.append({"name": name, "raw_size": raw_size})
    directory_offset = opt + (96 if magic == 0x10b else 112)
    number_directories = _u32(data, opt + (92 if magic == 0x10b else 108))
    cert_size = 0
    if number_directories >= 5 and directory_offset + 40 <= opt + opt_size:
        cert_size = _u32(data, directory_offset + 4 * 8 + 4)
    hits = []
    for marker in MARKERS:
        candidate = marker.encode("ascii")
        if candidate in data or marker.encode("utf-16le") in data:
            hits.append(marker)
    return {
        "format": "PE32" if magic == 0x10b else "PE32+",
        "machine": "0x%04x" % machine,
        "timestamp_utc": datetime.datetime.fromtimestamp(
            timestamp, datetime.timezone.utc
        ).isoformat(),
        "sections": sections,
        "dll_characteristics": "0x%04x" % _u16(data, opt + 70),
        "certificate_table_size": cert_size,
        "string_references": hits,
    }


def _safe_name(name):
    normalized = name.replace("\\", "/")
    return (bool(normalized) and not normalized.startswith("/")
            and not re.match(r"^[a-zA-Z]:", normalized)
            and all(part not in ("", "..") for part in normalized.split("/") if part != ""))


def inspect_zip(path, max_member=DEFAULT_MAX_MEMBER, max_total=DEFAULT_MAX_TOTAL,
                max_entries=DEFAULT_MAX_ENTRIES):
    """Inventaria membros ZIP com limites de memória e sem escrever no disco."""
    result = {"schema_version": 1, "archive": os.path.basename(path),
              "archive_sha256": sha256_file(path), "members": [], "warnings": []}
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if len(infos) > max_entries:
            raise ValueError("Número de entradas excede limite configurado")
        total = 0
        for info in infos:
            if info.is_dir():
                continue
            item = {"path": info.filename, "size": info.file_size}
            if not _safe_name(info.filename):
                result["warnings"].append("Caminho inseguro ignorado: %s" % info.filename)
                continue
            if info.flag_bits & 1:
                result["warnings"].append("Entrada criptografada ignorada: %s" % info.filename)
                continue
            total += info.file_size
            if info.file_size > max_member or total > max_total:
                raise ValueError("Tamanho descomprimido excede limite configurado")
            digest = hashlib.sha256()
            content = bytearray() if info.filename.lower().endswith((".exe", ".dll", ".sys")) else None
            with archive.open(info) as source:
                consumed = 0
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    consumed += len(chunk)
                    if consumed > info.file_size or consumed > max_member:
                        raise ValueError("Tamanho real excede limite declarado")
                    digest.update(chunk)
                    if content is not None:
                        content.extend(chunk)
            item["sha256"] = digest.hexdigest()
            if content is not None:
                try:
                    pe = inspect_pe(content)
                    if pe is not None:
                        item["pe"] = pe
                except (ValueError, OverflowError) as exc:
                    item["pe_error"] = str(exc)
            result["members"].append(item)
    result["member_count"] = len(result["members"])
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", help="Arquivo ZIP para inventário estático")
    parser.add_argument("--output", help="Gravar relatório JSON neste caminho")
    args = parser.parse_args(argv)
    try:
        result = inspect_zip(args.archive)
        payload = json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
        if args.output:
            with open(args.output, "w", encoding="utf-8") as out:
                out.write(payload)
        else:
            sys.stdout.write(payload)
        return 0 if not result["warnings"] else 2
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as exc:
        print("Falha no inventário: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
