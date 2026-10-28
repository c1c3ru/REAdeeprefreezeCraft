#!/usr/bin/env python3
"""REA-009: offline, bounded driver/certificate/overlay provenance scanner.

Does not execute binaries, extract drivers, or certify Authenticode signatures.
Distinguishes actual .sys PE files from textual references, and PE certificate
table presence from a verified signature/trust chain. Python 3.8, stdlib.
"""
import argparse
import hashlib
import json
import pathlib
import struct
import sys
import zipfile

try:
    from .rea_structural import PEError, PEView, MAX_PE
except ImportError:
    from rea_structural import PEError, PEView, MAX_PE

MAX_ENTRIES = 512
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_NESTED_DEPTH = 3
MAX_RESOURCES = 4096
DRIVER_NAMES = ("DeepFrz.sys", "DeepFrzx64.sys", "FarSpace.sys", "FarSpaceX64.sys")


class EvidenceError(ValueError):
    pass


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


def certificate_surface(data, view):
    """Security Directory uses FILE OFFSETS rather than RVAs (PE specification)."""
    offset, size = view.directory(4)
    if not offset and not size:
        return {"present": False, "win_certificate_count": 0,
                "signature_cryptographically_verified": False,
                "chain_trust_verified": False, "certificates": []}
    if not offset or size < 8 or offset + size > len(data):
        raise EvidenceError("Invalid PE security directory bounds")
    current, certificates = offset, []
    end = offset + size
    while current < end:
        if end - current < 8:
            raise EvidenceError("Trailing bytes in certificate table")
        length, revision, cert_type = struct.unpack_from("<IHH", data, current)
        if length < 8 or current + length > end:
            raise EvidenceError("Invalid WIN_CERTIFICATE length")
        payload = data[current + 8:current + length]
        certificates.append({
            "file_offset": current, "length": length,
            "revision": "0x%04x" % revision,
            "certificate_type": "0x%04x" % cert_type,
            "blob_sha256": sha(payload),
            "pkcs7_der_prefix_present": bool(
                cert_type == 2 and payload.startswith(b"\x30")),
        })
        current += (length + 7) & ~7
        if len(certificates) > 32:
            raise EvidenceError("Too many PE certificates")
    if current != end:
        raise EvidenceError("Non-aligned PE certificate directory size")
    return {
        "present": True, "directory_file_offset": offset, "directory_size": size,
        "win_certificate_count": len(certificates),
        "signature_cryptographically_verified": False,
        "chain_trust_verified": False, "certificates": certificates,
    }


def scan_pe(data, name):
    view = PEView(data)
    pe = view.u32(0x3c)
    table = pe + 24 + view.u16(pe + 20)
    sections = []
    end_sections = 0
    for i, sec in enumerate(view.sections):
        flags = view.u32(table + 40 * i + 36)
        raw_end = sec["offset"] + sec["raw_size"]
        if sec["raw_size"]:
            end_sections = max(end_sections, raw_end)
        sections.append({"name": sec["name"], "raw_size": sec["raw_size"],
                         "virtual_size": sec["virtual_size"],
                         "executable": bool(flags & 0x20000000)})
    signature = certificate_surface(data, view)
    # Keep the security table separate from any other data after raw sections.
    certified_end = (signature["directory_file_offset"] +
                     signature["directory_size"]) if signature["present"] else end_sections
    overlay_start = max(end_sections, certified_end)
    overlay = data[overlay_start:]
    if end_sections > len(data) or overlay_start > len(data):
        raise EvidenceError("Invalid PE section or certificate offset")
    refs = []
    for label in DRIVER_NAMES:
        narrow = data.count(label.encode("ascii"))
        wide = data.count(label.encode("utf-16le"))
        if narrow or wide:
            refs.append({"filename": label,
                         "ascii_hits": narrow, "utf16le_hits": wide,
                         "kind": "filename_string_only"})
    return {
        "path": name, "sha256": sha(data), "size_bytes": len(data),
        "machine": "0x%04x" % view.machine,
        "architecture": ("x64" if view.machine == 0x8664 else
                         "x86" if view.machine == 0x14c else "other"),
        "subsystem": view.u16(pe + 24 + 68),
        "sections": sections,
        "certificate_surface": signature,
        "last_section_end_file_offset": end_sections,
        "unclassified_overlay": {
            "file_offset": overlay_start, "size_bytes": len(overlay),
            "sha256": sha(overlay) if overlay else None,
            "format_identified": False if overlay else None,
            "executable_code_recovered": False,
            "driver_found_in_overlay": False,
        },
        "driver_filename_references": refs,
        "is_named_sys": name.lower().endswith(".sys"),
    }


def read_limited(stream, expected_size):
    if expected_size > MAX_PE:
        raise EvidenceError("PE exceeds size cap")
    data = bytearray()
    for part in iter(lambda: stream.read(1048576), b""):
        data.extend(part)
        if len(data) > expected_size:
            raise EvidenceError("ZIP expanded length exceeded declared size")
    if len(data) != expected_size:
        raise EvidenceError("ZIP entry size mismatch")
    return bytes(data)


def safe_name(name):
    n = name.replace("\\", "/")
    return bool(n) and not n.startswith("/") and ":" not in n and all(
        part not in ("", ".", "..") for part in n.split("/"))


def analyze_archive(path, expected_sha256=None):
    path = pathlib.Path(path)
    with path.open("rb") as stream:
        h = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1048576), b""):
            h.update(chunk)
    checksum = h.hexdigest()
    if expected_sha256 and checksum != expected_sha256:
        raise EvidenceError("Archive SHA-256 does not match pinned source")
    result = {
        "schema": "rea-009-driver-provenance-v1",
        "source_archive": path.name, "archive_sha256": checksum,
        "direct_zip_members_examined": 0,
        "observed_pe": [],
        "confirmed_sys_pe": [],
        "filename_only_references": [],
        "unclassified_regions": [],
        "unresolved": [],
        "cryptographically_verified_signatures": 0,
        "windows7_x86_tested": False, "windows7_x64_tested": False,
        "scope_closed": False,
    }
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_ENTRIES:
            raise EvidenceError("ZIP entry count cap exceeded")
        total = 0
        visited = 0
        def scan_nested(data, label, depth):
            nonlocal visited
            if depth > MAX_NESTED_DEPTH:
                result["unresolved"].append({"path": label, "reason": "depth_limit"})
                return
            visited += 1
            if visited > MAX_RESOURCES:
                raise EvidenceError("Resource visit cap exceeded")
            try:
                metadata = scan_pe(data, label)
            except PEError:
                result["unresolved"].append({"path": label, "reason": "invalid_pe_candidate"})
                return
            result["observed_pe"].append(metadata)
            if metadata["is_named_sys"]:
                result["confirmed_sys_pe"].append({
                    "path": label, "sha256": metadata["sha256"],
                    "size_bytes": metadata["size_bytes"],
                    "machine": metadata["machine"],
                    "certificate_surface": metadata["certificate_surface"],
                })
            if metadata["unclassified_overlay"]["size_bytes"]:
                result["unclassified_regions"].append({
                    "path": label, "kind": "overlay_unknown",
                    **metadata["unclassified_overlay"],
                })
            for item in metadata["driver_filename_references"]:
                result["filename_only_references"].append({"source": label, **item})
            try:
                view = PEView(data)
                leaves = view.resources(depth=1)
            except PEError as exc:
                result["unresolved"].append({
                    "path": label, "reason": "resource_tree_parse_failed", "detail": str(exc)})
                return
            for leaf in leaves:
                visited += 1
                if visited > MAX_RESOURCES:
                    raise EvidenceError("Resource visit cap exceeded")
                start, size = leaf["file_offset"], leaf["size"]
                if size > MAX_PE or start < 0 or start + size > len(data):
                    raise EvidenceError("Resource bounds exceed parent")
                body = data[start:start + size]
                if sha(body) != leaf["sha256"]:
                    raise EvidenceError("Resource hash mismatch")
                child = label + "::" + "/".join(leaf["path"])
                if body.startswith(b"MZ"):
                    scan_nested(body, child, depth + 1)
                if leaf["path"] and leaf["path"][-1].lower().endswith(".sys"):
                    # Name alone is not proof; only report valid PE as confirmed.
                    if not body.startswith(b"MZ"):
                        result["unresolved"].append({
                            "path": child, "reason": "sys_named_resource_not_validated_as_pe"})
        for info in infos:
            if info.is_dir():
                continue
            if not safe_name(info.filename) or info.flag_bits & 1:
                result["unresolved"].append({
                    "path": info.filename, "reason": "unsafe_or_encrypted_zip_member"})
                continue
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise EvidenceError("ZIP expanded total byte cap exceeded")
            result["direct_zip_members_examined"] += 1
            if info.filename.lower().endswith((".sys", ".exe", ".dll")):
                with archive.open(info) as stream:
                    payload = read_limited(stream, info.file_size)
                if payload.startswith(b"MZ"):
                    scan_nested(payload, info.filename, 0)
                else:
                    result["unresolved"].append({
                        "path": info.filename, "reason": "named_executable_without_PE_header"})
    result["unresolved"].extend([
        {"reason": "packed_modules_not_unpacked"},
        {"reason": "installed_driver_files_not_available_from_static_archive"},
        {"reason": "driver_signature_chain_and_runtime_unverified"},
    ])
    result["confirmed_sys_pe_count"] = len(result["confirmed_sys_pe"])
    result["observed_pe_count"] = len(result["observed_pe"])
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--expect-sha256")
    parser.add_argument("--json")
    args = parser.parse_args(argv)
    try:
        report = analyze_archive(args.archive, args.expect_sha256)
        output = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if args.json:
            pathlib.Path(args.json).write_text(output, encoding="utf-8")
        else:
            print(output, end="")
        return 0
    except (OSError, ValueError, PEError, zipfile.BadZipFile) as exc:
        print("REA driver evidence ERROR: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
