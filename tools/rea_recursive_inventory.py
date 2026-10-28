#!/usr/bin/env python3
"""REA-015: recursive, read-only component discovery from ZIP and PE resources.

Maps every ZIP member and every PE resource leaf by SHA-256, scans PE headers
regardless of extension, and recursively visits embedded PE/ZIP payloads.
Never executes, installs, unpacks UPX, writes binaries, or invents driver files.
Python >=3.8, stdlib only. Limits are global and fail closed.
"""
import argparse
import hashlib
import io
import json
import pathlib
import struct
import sys
import zipfile

try:
    from .rea_structural import PEError, PEView, MAX_PE
except ImportError:
    from rea_structural import PEError, PEView, MAX_PE

MAX_DEPTH = 4
MAX_ZIP_ENTRIES = 512
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_RESOURCE_LEAVES = 4096
KNOWN_DRIVER_NAMES = ("DeepFrz.sys", "DeepFrzx64.sys",
                      "FarSpace.sys", "FarSpaceX64.sys")


class InventoryError(ValueError):
    pass


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def classify(data, name):
    if data.startswith(b"MZ"):
        return "pe_candidate"
    if data.startswith(b"PK\x03\x04"):
        return "zip_container"
    if data.startswith(b"SIB file"):
        return "sib_container_unknown"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png_image"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg_image"
    if data.startswith(b"{\\rtf"):
        return "rtf_document"
    if data.startswith(b"TPF0"):
        return "delphi_form_data"
    if name.lower().endswith(".url"):
        return "url_shortcut"
    if name.lower().endswith(".txt"):
        return "text"
    return "unclassified_data"


def safe_path(name):
    normalized = name.replace("\\", "/")
    return (bool(normalized) and not normalized.startswith("/")
            and ":" not in normalized and
            all(p not in ("", ".", "..") for p in normalized.split("/")))


def probe_executable(view):
    pe = view.u32(0x3c)
    section_table = pe + 24 + view.u16(pe + 20)
    executable = []
    packed_markers = []
    for i, sec in enumerate(view.sections):
        characteristics = view.u32(section_table + i * 40 + 36)
        if characteristics & 0x20000000:
            executable.append({
                "name": sec["name"], "rva": "0x%x" % sec["rva"],
                "raw_bytes": sec["raw_size"],
                "virtual_bytes": sec["virtual_size"],
            })
        if sec["name"].upper().startswith("UPX"):
            packed_markers.append(sec["name"])
    return executable, packed_markers


def scan_payload(data, label, origin, depth, state, declared_path=None):
    if depth > MAX_DEPTH:
        raise InventoryError("Nested payload depth cap reached")
    if len(data) > MAX_PE:
        raise InventoryError("PE/container payload exceeds byte limit")
    checksum = sha(data)
    kind = classify(data, label)
    record = {
        "path": label, "parent": origin, "size_bytes": len(data),
        "sha256": checksum, "classification": kind,
    }
    if declared_path is not None:
        record["resource_path"] = declared_path
    state["artifacts"].append(record)
    state["total_nodes"] += 1
    if state["total_nodes"] > MAX_RESOURCE_LEAVES:
        raise InventoryError("Total analyzed node cap exceeded")
    if kind == "zip_container":
        scan_zip(io.BytesIO(data), label, depth + 1, state)
        return
    if kind != "pe_candidate":
        if kind in ("unclassified_data", "sib_container_unknown"):
            state["unresolved"].append({
                "path": label, "reason": "unknown_container_or_data_format",
            })
        return
    try:
        view = PEView(data)
    except PEError as exc:
        record["classification"] = "invalid_pe_candidate"
        record["parse_error"] = str(exc)
        state["unresolved"].append({"path": label, "reason": "pe_parse_failed"})
        return
    sections, markers = probe_executable(view)
    record["classification"] = "observed_pe"
    record["machine"] = "0x%04x" % view.machine
    record["format"] = "PE32+" if view.pe64 else "PE32"
    record["entry_rva"] = "0x%x" % view.entry_rva
    record["executable_sections"] = sections
    record["packer_markers"] = markers
    record["resource_count"] = 0
    state["pe_count"] += 1
    if markers:
        state["unresolved"].append({
            "path": label,
            "reason": "packed_pe_uncompressed_code_unavailable",
            "markers": markers,
        })
    # Track *references* to drivers separately from actual, fully parsed .sys binaries.
    found = [item for item in KNOWN_DRIVER_NAMES
             if item.encode("ascii") in data or item.encode("utf-16le") in data]
    record["driver_filename_references"] = found
    if label.lower().endswith(".sys"):
        state["confirmed_driver_pe_paths"].append(label)
    try:
        resources = view.resources(depth=1)
    except PEError as exc:
        record["resource_parse_error"] = str(exc)
        state["unresolved"].append({"path": label, "reason": "resource_tree_parse_failed"})
        return
    record["resource_count"] = len(resources)
    for leaf in resources:
        if state["total_nodes"] >= MAX_RESOURCE_LEAVES:
            raise InventoryError("Resource cap exceeded")
        location = "::" + "/".join(leaf["path"])
        start, size = leaf["file_offset"], leaf["size"]
        if size < 0 or start < 0 or start + size > len(data):
            raise InventoryError("Resource leaves parent bounds")
        body = data[start:start + size]
        if sha(body) != leaf["sha256"]:
            raise InventoryError("Resource hash mismatch")
        scan_payload(body, label + location, label, depth + 1, state,
                     declared_path=leaf["path"])


def scan_zip(source, label, depth, state):
    if depth > MAX_DEPTH:
        raise InventoryError("ZIP nesting depth exceeded")
    with zipfile.ZipFile(source) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_ZIP_ENTRIES:
            raise InventoryError("ZIP contains too many entries")
        for info in entries:
            if info.is_dir():
                continue
            path = info.filename.replace("\\", "/")
            if not safe_path(path) or info.flag_bits & 1:
                state["warnings"].append({
                    "source": label, "path": info.filename,
                    "reason": "unsafe_or_encrypted_entry",
                })
                continue
            if info.file_size > MAX_PE:
                raise InventoryError("ZIP entry exceeds maximum size")
            state["total_decompressed"] += info.file_size
            if state["total_decompressed"] > MAX_TOTAL_BYTES:
                raise InventoryError("Combined ZIP decompressed byte cap exceeded")
            payload = bytearray()
            with archive.open(info) as member:
                while True:
                    chunk = member.read(1024 * 1024)
                    if not chunk:
                        break
                    payload.extend(chunk)
                    if len(payload) > info.file_size:
                        raise InventoryError("ZIP declared length exceeded")
            if len(payload) != info.file_size:
                raise InventoryError("ZIP entry truncated")
            scan_payload(bytes(payload), label + "::" + path, label, depth + 1, state)


def analyze_archive(path, expected_sha256=None):
    archive = pathlib.Path(path)
    source_hash = hashlib.sha256()
    with archive.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            source_hash.update(chunk)
    if expected_sha256 and source_hash.hexdigest() != expected_sha256:
        raise InventoryError("Archive SHA-256 does not match pinned sample")
    state = {
        "artifacts": [], "warnings": [], "unresolved": [],
        "pe_count": 0, "total_nodes": 0, "total_decompressed": 0,
        "confirmed_driver_pe_paths": [],
    }
    scan_zip(archive, archive.name, 0, state)
    counts = {}
    for record in state["artifacts"]:
        counts[record["classification"]] = counts.get(record["classification"], 0) + 1
    return {
        "schema": "rea-recursive-inventory-v1", "archive_name": archive.name,
        "archive_sha256": source_hash.hexdigest(),
        "artifacts_discovered": len(state["artifacts"]),
        "pe_count": state["pe_count"],
        "top_level_archive_files": sum(1 for r in state["artifacts"]
                                       if r["parent"] == archive.name),
        "class_counts": dict(sorted(counts.items())),
        "confirmed_driver_pe_paths": state["confirmed_driver_pe_paths"],
        "artifacts": state["artifacts"],
        "warnings": state["warnings"],
        "unresolved": state["unresolved"],
        "scope_closed": False,
        "scope_reason": ("Recursive syntactic discovery does not prove completeness "
                         "of packed payloads, runtime dependencies, or drivers."),
    }


def to_markdown(report):
    lines = ["# REA-015 — inventário recursivo", "",
             "**SHA-256:** " + report["archive_sha256"], "",
             "- Entradas de arquivo ZIP: %d" % report["top_level_archive_files"],
             "- Artefatos/recursos visitados: %d" % report["artifacts_discovered"],
             "- PEs com cabeçalho válido: %d" % report["pe_count"],
             "- Drivers PE confirmados: %d" % len(report["confirmed_driver_pe_paths"]),
             "- Inventário integral fechado: **não**", "",
             "## Artefatos PE", ""]
    for item in report["artifacts"]:
        if item["classification"] == "observed_pe":
            lines += ["- " + item["path"] + " | " + item["sha256"] +
                      " | " + item["machine"] + " | recursos=" + str(item["resource_count"]) +
                      " | marcadores=" + ",".join(item["packer_markers"])]
    lines += ["", "## Pendências", ""]
    for item in report["unresolved"]:
        lines.append("- " + item["path"] + ": " + item["reason"])
    lines += ["", "Este relatório não contém payloads nem comprova extração UPX, "
              "driver em disco ou execução de qualquer código.", ""]
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--expect-sha256")
    parser.add_argument("--json")
    parser.add_argument("--markdown")
    args = parser.parse_args(argv)
    try:
        result = analyze_archive(args.archive, args.expect_sha256)
        if args.json:
            pathlib.Path(args.json).write_text(
                json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8")
        else:
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        if args.markdown:
            pathlib.Path(args.markdown).write_text(to_markdown(result), encoding="utf-8")
        return 0
    except (OSError, ValueError, PEError, zipfile.BadZipFile) as exc:
        print("REA recursive inventory error: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
