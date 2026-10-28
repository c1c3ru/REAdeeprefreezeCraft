#!/usr/bin/env python3
"""REA-015/D: validate packed UPX PE surfaces without unpacking or executing.

Offline header inspection, RVA-to-file entry mapping and SHA-256 provenance.
Only on-disk UPX1 bytes are measured; the virtual UPX0 region is NOT counted
as recovered code. Python 3.8+, stdlib; no redistributable binary output.
"""
import argparse
import hashlib
import json
import pathlib
import sys
import zipfile

try:
    from .rea_structural import PEError, PEView, MAX_PE
except ImportError:
    from rea_structural import PEError, PEView, MAX_PE

ROOT_MEMBER = "Faronics_DFS/DFStd.exe"
ROOT_SHA256 = "2d7c171d4037660843a7e02c055679c5a26904af84d48fc8c557a67023f55c8b"
ARCHIVE_SHA256 = "f2e1a70e3becff235c886c6092d3d8a5928404bbe43f9c0c6360e428daa64671"
EXPECTED_COMPONENTS = {
    "BINARY/CLOUD_INSTALLER/4105": "145c6b8461132fd077a42cee775aca318c2b697b5720283749e04fc6aa5b4772",
    "BINARY/RSC_WU_CMD_LINE/4105": "454a1a6a576cce0b69acbf320fbeebb4909891ee7592f20afd9df992db6a1351",
}


class PackedSurfaceError(ValueError):
    pass


def sha(data):
    return hashlib.sha256(data).hexdigest()


def analyze_pe(raw):
    """Return verified packed layout. Never decode, decompress or execute bytes."""
    view = PEView(raw)
    pe_offset = view.u32(0x3c)
    section_table = pe_offset + 24 + view.u16(pe_offset + 20)
    entries = []
    for i, sec in enumerate(view.sections):
        characteristics = view.u32(section_table + i * 40 + 36)
        data_start, size = sec["offset"], sec["raw_size"]
        if size and (data_start < 0 or data_start + size > len(raw)):
            raise PackedSurfaceError("Section raw span outside file")
        entries.append({
            "name": sec["name"], "rva": sec["rva"],
            "virtual_bytes": sec["virtual_size"], "raw_bytes": size,
            "raw_offset": data_start, "executable_flag": bool(characteristics & 0x20000000),
            "raw_sha256": sha(raw[data_start:data_start + size]) if size else None,
        })
    sections = {s["name"]: s for s in entries}
    zero = sections.get("UPX0")
    packed = sections.get("UPX1")
    if zero is None or packed is None:
        raise PackedSurfaceError("UPX0/UPX1 section pair not found")
    if zero["raw_bytes"] != 0 or zero["virtual_bytes"] <= 0:
        raise PackedSurfaceError("UPX0 is not a zero-raw, nonzero-virtual section")
    if packed["raw_bytes"] <= 0 or not packed["executable_flag"]:
        raise PackedSurfaceError("UPX1 has no on-disk executable bytes")
    ep = view.entry_rva
    delta = ep - packed["rva"]
    if delta < 0 or delta >= packed["raw_bytes"]:
        raise PackedSurfaceError("Entry RVA not backed by raw UPX1 bytes")
    ep_offset = packed["raw_offset"] + delta
    if ep_offset >= len(raw):
        raise PackedSurfaceError("Entry offset outside file")
    signature_positions = []
    # Scan only the PE headers for UPX!'s packer marker, not arbitrary payload strings.
    signature_bound = min(view.size_headers, len(raw))
    position = raw.find(b"UPX!", 0, signature_bound)
    while position >= 0:
        signature_positions.append("0x%x" % position)
        position = raw.find(b"UPX!", position + 4, signature_bound)
        if len(signature_positions) > 16:
            raise PackedSurfaceError("Too many UPX signature markers")
    if not signature_positions:
        raise PackedSurfaceError("No UPX! marker in PE headers")
    return {
        "sha256": sha(raw),
        "architecture": "x64" if view.pe64 else "x86",
        "entrypoint_rva": "0x%x" % ep,
        "entrypoint_file_offset": "0x%x" % ep_offset,
        "entrypoint_section": "UPX1",
        "entrypoint_first_32_bytes_sha256": sha(raw[ep_offset:ep_offset + 32]),
        "upx_header_markers": signature_positions,
        "upx0": zero,
        "upx1": packed,
        "packed_executable_on_disk_bytes": sum(
            s["raw_bytes"] for s in entries if s["executable_flag"]
        ),
        "unpacked_code_recovered": False,
        "original_entrypoint_recovered": False,
        "code_coverage_percent": None,
        "caveat": "UPX0 contains no on-disk code bytes; UPX1 entry is the loader stub, not proof of original code recovery.",
    }


def analyze_archive(path, expected_archive_sha=ARCHIVE_SHA256):
    path = pathlib.Path(path)
    archive_digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            archive_digest.update(chunk)
    if expected_archive_sha and archive_digest.hexdigest() != expected_archive_sha:
        raise PackedSurfaceError("Archive SHA-256 mismatch")
    with zipfile.ZipFile(path) as archive:
        members = [i for i in archive.infolist() if i.filename == ROOT_MEMBER]
        if len(members) != 1 or members[0].file_size > MAX_PE or members[0].flag_bits & 1:
            raise PackedSurfaceError("Missing, duplicate, oversized or encrypted root PE")
        with archive.open(members[0]) as stream:
            root = stream.read(MAX_PE + 1)
        if len(root) != members[0].file_size:
            raise PackedSurfaceError("Root PE ZIP size mismatch")
    if sha(root) != ROOT_SHA256:
        raise PackedSurfaceError("Unexpected root PE SHA-256")
    leaves = PEView(root).resources(depth=1)
    found = {}
    for leaf in leaves:
        key = "/".join(leaf["path"])
        if key not in EXPECTED_COMPONENTS:
            continue
        if key in found:
            raise PackedSurfaceError("Duplicated selected PE resource")
        start, length = leaf["file_offset"], leaf["size"]
        if length > MAX_PE or start < 0 or start + length > len(root):
            raise PackedSurfaceError("Bad selected PE resource bounds")
        raw = root[start:start + length]
        if sha(raw) != EXPECTED_COMPONENTS[key]:
            raise PackedSurfaceError("Pinned embedded PE SHA-256 mismatch: " + key)
        metadata = analyze_pe(raw)
        metadata["source_resource"] = key
        found[key] = metadata
    if set(found) != set(EXPECTED_COMPONENTS):
        raise PackedSurfaceError("Required embedded PE resources missing")
    return {
        "schema": "rea-015-upx-surface-v1",
        "archive_sha256": archive_digest.hexdigest(),
        "root_pe_sha256": sha(root),
        "components": [found[k] for k in sorted(found)],
        "packed_modules_verified": len(found),
        "full_reverse_engineering_complete": False,
        "windows7_runtime_tested": False,
        "method": "Bounded static PE header and raw section inspection; no binary execution, unpacking or publication.",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--json")
    opts = parser.parse_args(argv)
    try:
        result = analyze_archive(opts.archive)
        output = json.dumps(result, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
        if opts.json:
            pathlib.Path(opts.json).write_text(output, encoding="utf-8")
        else:
            print(output, end="")
        return 0
    except (OSError, ValueError, PEError, zipfile.BadZipFile) as exc:
        print("REA UPX surface ERROR: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
