#!/usr/bin/env python3
"""REA-015/G: bounded static zlib/gzip candidate checks in an opaque PE overlay.

This DOES NOT identify encryption, unpack the installer, recover drivers or
execute code. Positive results identify only a decodable standard stream.
Requires Python >=3.8; standard library only. Never emits proprietary bytes.
"""
import argparse
import hashlib
import json
import pathlib
import struct
import sys
import zipfile
import zlib

from .rea_structural import PEView, PEError, MAX_PE
from .rea_overlay_inventory import (
    ZIP_SHA, ROOT_SHA, ROOT_MEMBER, CHILD_RESOURCE, CHILD_SHA, OVERLAY_SHA,
    FRAME_MAGIC, MAX_OVERLAY,
)

MAX_CANDIDATES = 10000
INPUT_LIMIT = 2048
OUTPUT_LIMIT = 131072


class CodecProbeError(ValueError):
    pass


def sha(x):
    return hashlib.sha256(x).hexdigest()


def plausible_zlib_header(cmf, flg):
    return ((cmf & 15) == 8 and (cmf >> 4) <= 7 and
            (((cmf << 8) | flg) % 31) == 0 and not (flg & 0x20))


def bounded_probe(body, pos, wbits):
    try:
        stream = zlib.decompressobj(wbits)
        out = stream.decompress(body[pos:pos + INPUT_LIMIT], OUTPUT_LIMIT)
        return "complete" if stream.eof and out else "partial"
    except zlib.error:
        return "invalid"


def scan_body(body):
    if not isinstance(body, bytes) or not body or len(body) > MAX_OVERLAY:
        raise CodecProbeError("Body size outside bounds")
    z = []
    for i in range(len(body)-1):
        if plausible_zlib_header(body[i], body[i+1]):
            z.append(i)
            if len(z) > MAX_CANDIDATES:
                raise CodecProbeError("Too many zlib candidates")
    g = []
    pos = body.find(b"\x1f\x8b\x08")
    while pos != -1:
        g.append(pos)
        if len(g) > MAX_CANDIDATES:
            raise CodecProbeError("Too many gzip candidates")
        pos = body.find(b"\x1f\x8b\x08", pos+1)
    def counts(positions, wbits):
        out = {"invalid": 0, "partial": 0, "complete": 0}
        for at in positions:
            out[bounded_probe(body, at, wbits)] += 1
        return out
    return {
        "body_sha256": sha(body), "body_bytes": len(body),
        "zlib_rfc1950_header_candidates": len(z),
        "zlib_probe_results": counts(z, 15),
        "gzip_header_candidates": len(g),
        "gzip_probe_results": counts(g, 31),
        "input_cap_per_candidate": INPUT_LIMIT,
        "output_cap_per_candidate": OUTPUT_LIMIT,
        "tested_codecs": ["RFC1950_zlib", "RFC1952_gzip"],
        "other_codecs_or_transformations_not_tested": True,
        "bounded_negative_result_is_not_absence_proof": True,
        "files_recovered": 0,
    }


def inspect_overlay(overlay):
    if not isinstance(overlay, bytes) or len(overlay) < 104 or len(overlay) > MAX_OVERLAY:
        raise CodecProbeError("Overlay outside size bounds")
    length = struct.unpack_from("<I", overlay, 0)[0]
    duplicate_length = struct.unpack_from("<I", overlay, 0x44)[0]
    paired1 = struct.unpack_from("<I", overlay, 0x48)[0]
    paired2 = struct.unpack_from("<I", overlay, 0x4c)[0]
    declared_size = struct.unpack_from("<I", overlay, 0x24)[0]
    if (length < 64 or length > 4096 or length + 8 >= len(overlay) or
            overlay[0xc:0x10] != FRAME_MAGIC or
            overlay[-8:-4] != FRAME_MAGIC or declared_size != len(overlay)):
        raise CodecProbeError("Overlay frame fails pinned invariants")
    report = scan_body(overlay[length:-8])
    report.update({
        "schema": "rea-015-codec-candidates-v1", "overlay_sha256": sha(overlay),
        "overlay_bytes": len(overlay), "header_length": length,
        "duplicate_header_length": duplicate_length,
        "header_length_fields_match": length == duplicate_length,
        "paired_field_0x48": paired1, "paired_field_0x4c": paired2,
        "paired_fields_match": paired1 == paired2,
        "frame_size_and_magic_verified": True,
        "payload_format_identified": False,
        "unpacked_original_code": False,
        "drivers_confirmed": False,
        "coverage_complete": False,
        "interpretation": ("Only candidates with RFC 1950 / 1952 headers were tested. "
                           "A bounded rejection is not proof of ciphering, non-compression "
                           "or absence of hidden files."),
    })
    return report


def analyze_archive(path):
    archive = pathlib.Path(path)
    h = hashlib.sha256()
    with archive.open("rb") as fd:
        for chunk in iter(lambda: fd.read(1048576), b""):
            h.update(chunk)
    if h.hexdigest() != ZIP_SHA:
        raise CodecProbeError("Pinned archive SHA-256 mismatch")
    with zipfile.ZipFile(archive) as zf:
        entries = [x for x in zf.infolist() if x.filename == ROOT_MEMBER]
        if len(entries) != 1 or entries[0].flag_bits & 1 or entries[0].file_size > MAX_PE:
            raise CodecProbeError("Missing/oversize root PE")
        with zf.open(entries[0]) as stream:
            root = stream.read(MAX_PE + 1)
        if len(root) != entries[0].file_size or sha(root) != ROOT_SHA:
            raise CodecProbeError("Root PE hash/size mismatch")
    matches = [x for x in PEView(root).resources(depth=1)
               if "/".join(x["path"]) == CHILD_RESOURCE]
    if len(matches) != 1:
        raise CodecProbeError("Expected one cloud resource")
    leaf = matches[0]
    child = root[leaf["file_offset"]:leaf["file_offset"]+leaf["size"]]
    if sha(child) != CHILD_SHA or leaf["sha256"] != CHILD_SHA:
        raise CodecProbeError("Embedded PE hash mismatch")
    view = PEView(child)
    end = max(sec["offset"] + sec["raw_size"] for sec in view.sections if sec["raw_size"])
    offset, length = view.directory(4)
    if offset or length:
        if not offset or not length or offset + length > len(child):
            raise CodecProbeError("PE certificate offset invalid")
        end = max(end, offset + length)
    overlay = child[end:]
    if sha(overlay) != OVERLAY_SHA:
        raise CodecProbeError("Overlay SHA-256 mismatch")
    report = inspect_overlay(overlay)
    report.update({"archive_sha256": h.hexdigest(), "root_pe_sha256": sha(root),
                   "cloud_pe_sha256": sha(child), "overlay_file_offset": "0x%x" % end,
                   "inspection": "offline_headers_and_bounded_codecs_only"})
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--json")
    args = parser.parse_args(argv)
    try:
        result = analyze_archive(args.archive)
        body = json.dumps(result, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
        if args.json:
            pathlib.Path(args.json).write_text(body, encoding="utf-8")
        else:
            print(body, end="")
        return 0
    except (OSError, ValueError, PEError, zipfile.BadZipFile) as exc:
        print("REA-015 codec probe ERROR: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
