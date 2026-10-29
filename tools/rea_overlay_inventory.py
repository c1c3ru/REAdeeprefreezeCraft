#!/usr/bin/env python3
"""REA-015: offline, bounded inspection of opaque installer overlay.

Framing signatures and entropy are observations, not proof of a known
archive, executable, encrypted payload, or driver. Python 3.8 stdlib only.
Never executes/unpacks or writes commercial executable bytes.
"""
import argparse
import hashlib
import json
import math
import pathlib
import struct
import sys
import zipfile

try:
    from .rea_structural import PEError, PEView, MAX_PE
except ImportError:
    from rea_structural import PEError, PEView, MAX_PE

ZIP_SHA = "f2e1a70e3becff235c886c6092d3d8a5928404bbe43f9c0c6360e428daa64671"
ROOT_SHA = "2d7c171d4037660843a7e02c055679c5a26904af84d48fc8c557a67023f55c8b"
ROOT_MEMBER = "Faronics_DFS/DFStd.exe"
CHILD_RESOURCE = "BINARY/CLOUD_INSTALLER/4105"
CHILD_SHA = "145c6b8461132fd077a42cee775aca318c2b697b5720283749e04fc6aa5b4772"
OVERLAY_SHA = "9453669c5ae280cb8718761159895da425168ccbba1e4e56d376b5165554b9e2"
FRAME_MAGIC = b"\x69\xcd\xab\x69"
MAX_OVERLAY = 16 * 1024 * 1024
MAX_MAGIC_HITS = 20000
STRONG_MAGIC = {
    "zip_local_header": b"PK\x03\x04",
    "zip_end_directory": b"PK\x05\x06",
    "seven_zip": b"7z\xbc\xaf\x27\x1c",
    "cabinet": b"MSCF",
    "rar": b"Rar!\x1a\x07",
    "xz": b"\xfd7zXZ\x00",
    "elf": b"\x7fELF",
}


class OverlayError(ValueError):
    pass


def digest(payload):
    return hashlib.sha256(payload).hexdigest()


def locations(data, needle, max_hits=MAX_MAGIC_HITS):
    out, offset = [], 0
    while True:
        at = data.find(needle, offset)
        if at < 0:
            return out
        out.append(at)
        if len(out) > max_hits:
            raise OverlayError("Too many signature matches")
        offset = at + len(needle)


def pe_candidate(data, at):
    """A literal MZ marker alone must never become a confirmed PE."""
    remaining = len(data) - at
    if remaining < 256:
        return False
    off = struct.unpack_from("<I", data, at + 0x3c)[0]
    if off < 64 or off > 4096 or off + 24 > remaining:
        return False
    if data[at + off:at + off + 4] != b"PE\x00\x00":
        return False
    number = struct.unpack_from("<H", data, at + off + 6)[0]
    opt_bytes = struct.unpack_from("<H", data, at + off + 20)[0]
    if number < 1 or number > 96 or off + 24 + opt_bytes + 40 * number > remaining:
        return False
    if struct.unpack_from("<H", data, at + off + 24)[0] not in (0x10b, 0x20b):
        return False
    try:
        view = PEView(data[at:])
    except PEError:
        return False
    return view.machine in (0x14c, 0x8664)


def shannon(payload):
    if not payload:
        return None
    counts = [0] * 256
    for value in payload:
        counts[value] += 1
    n = float(len(payload))
    return round(-sum((c / n) * math.log2(c / n) for c in counts if c), 5)


def analyze_overlay(overlay):
    if not isinstance(overlay, bytes) or len(overlay) < 104 or len(overlay) > MAX_OVERLAY:
        raise OverlayError("Overlay size outside bounded inspection range")
    first_word = struct.unpack_from("<I", overlay, 0)[0]
    second_word = struct.unpack_from("<I", overlay, 4)[0]
    version_word = struct.unpack_from("<I", overlay, 8)[0]
    size_field = struct.unpack_from("<I", overlay, 0x24)[0]
    magic_offsets = locations(overlay, FRAME_MAGIC)
    frame = (first_word == 96 and second_word == 86
             and magic_offsets == [0x0c, len(overlay) - 8]
             and size_field == len(overlay))
    header_len = (first_word if 0 < first_word <= 4096
                  and first_word < len(overlay) - 8 else None)
    body = overlay[header_len:-8] if header_len is not None else b""
    signature_counts = {label: len(locations(overlay, magic))
                        for label, magic in STRONG_MAGIC.items()}
    mz = locations(overlay, b"MZ")
    valid_pe = [at for at in mz if pe_candidate(overlay, at)]
    windows = []
    if body:
        size = min(65536, len(body))
        for label, at in (("start", 0), ("middle", (len(body)-size)//2),
                          ("end", len(body)-size)):
            sample = body[at:at+size]
            windows.append({"region": label, "offset_from_body": at,
                            "bytes": len(sample),
                            "shannon_bits_per_byte": shannon(sample)})
    return {
        "schema": "rea-015-overlay-structure-v1",
        "overlay_bytes": len(overlay), "overlay_sha256": digest(overlay),
        "leading_words": {"offset_0x00": first_word, "offset_0x04": second_word,
                          "offset_0x08": version_word, "offset_0x24": size_field},
        "magic_69abcd69_offsets": ["0x%x" % p for p in magic_offsets],
        "frame_hypothesis_consistent": frame,
        "candidate_header_length": header_len,
        "candidate_header_sha256": digest(overlay[:header_len]) if header_len is not None else None,
        "candidate_body_bytes": len(body) if header_len is not None else None,
        "candidate_body_sha256": digest(body) if header_len is not None else None,
        "last_eight_bytes_sha256": digest(overlay[-8:]),
        "last_four_bytes_hex": overlay[-4:].hex(),
        "strong_archive_magic_counts": signature_counts,
        "mz_marker_count": len(mz),
        "validated_embedded_pe_at_mz_offsets": len(valid_pe),
        "validated_embedded_pe_offsets": ["0x%x" % p for p in valid_pe],
        "entropy_windows": windows,
        "format_identified": False,
        "compression_or_encryption_identified": False,
        "driver_found": False, "driver_absence_proven": False,
        "code_recovered": False, "scope_closed": False,
        "limitations": ("Frame fields and high entropy are observations only; "
                        "no decompression, executable interpretation, driver recovery, "
                        "or evidence of absence behind opaque data."),
    }


def analyze_archive(path, expected_zip_sha=ZIP_SHA):
    zpath = pathlib.Path(path)
    h = hashlib.sha256()
    with zpath.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            h.update(chunk)
    if expected_zip_sha and h.hexdigest() != expected_zip_sha:
        raise OverlayError("Pinned ZIP SHA-256 mismatch")
    with zipfile.ZipFile(zpath) as archive:
        matches = [m for m in archive.infolist() if m.filename == ROOT_MEMBER]
        if len(matches) != 1 or matches[0].flag_bits & 1 or matches[0].file_size > MAX_PE:
            raise OverlayError("Missing, encrypted or oversized pinned PE member")
        root = bytearray()
        with archive.open(matches[0]) as fd:
            for chunk in iter(lambda: fd.read(1048576), b""):
                root.extend(chunk)
                if len(root) > matches[0].file_size:
                    raise OverlayError("Root ZIP member exceeds declared size")
        if len(root) != matches[0].file_size or digest(root) != ROOT_SHA:
            raise OverlayError("Root ZIP member length/SHA-256 mismatch")
    resources = PEView(root).resources(depth=1)
    matches = [r for r in resources if "/".join(r["path"]) == CHILD_RESOURCE]
    if len(matches) != 1:
        raise OverlayError("Missing or duplicate cloud PE resource")
    item = matches[0]
    offset, size = item["file_offset"], item["size"]
    if size > MAX_PE or offset < 0 or offset + size > len(root):
        raise OverlayError("Invalid resource bounds")
    child = bytes(root[offset:offset+size])
    if digest(child) != CHILD_SHA or item["sha256"] != CHILD_SHA:
        raise OverlayError("Cloud PE SHA-256 mismatch")
    view = PEView(child)
    end = max(s["offset"] + s["raw_size"] for s in view.sections if s["raw_size"])
    sec_off, sec_size = view.directory(4)
    if sec_off or sec_size:
        if not sec_off or not sec_size or sec_off + sec_size > len(child):
            raise OverlayError("Invalid certificate bounds")
        end = max(end, sec_off + sec_size)
    if end >= len(child):
        raise OverlayError("No data after PE sections")
    report = analyze_overlay(child[end:])
    if report["overlay_sha256"] != OVERLAY_SHA:
        raise OverlayError("Known overlay SHA-256 changed")
    report.update({"zip_sha256": h.hexdigest(), "root_pe_sha256": digest(root),
                   "embedded_pe_sha256": digest(child),
                   "embedded_resource": CHILD_RESOURCE,
                   "overlay_file_offset": "0x%x" % end})
    return report


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive", required=True)
    p.add_argument("--json")
    args = p.parse_args(argv)
    try:
        report = analyze_archive(args.archive)
        output = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        if args.json:
            pathlib.Path(args.json).write_text(output, encoding="utf-8")
        else:
            print(output, end="")
        return 0
    except (OSError, ValueError, PEError, zipfile.BadZipFile) as exc:
        print("REA overlay inspection ERROR: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
