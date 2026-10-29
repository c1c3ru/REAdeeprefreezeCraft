#!/usr/bin/env python3
"""REA-015/P: offline byte-difference profiler for locally supplied buffer pairs.

Hashes alone cannot reveal XOR. The input contains small byte samples; do not
commit captured proprietary material. No dynamic instrumentation or execution.
Python 3.8+ standard library.
"""
import argparse
import hashlib
import json
import pathlib
import re
import sys

MAX_INPUT = 1024 * 1024
MAX_PAIRS = 128
MAX_SAMPLE = 4096
HEX = re.compile(r"^[0-9a-fA-F]+$")


class BufferDiffError(ValueError):
    pass


def decode_hex(value, label):
    if not isinstance(value, str) or not value or len(value) > 2 * MAX_SAMPLE:
        raise BufferDiffError("Invalid " + label + " length")
    if len(value) % 2 or not HEX.fullmatch(value):
        raise BufferDiffError("Invalid hex in " + label)
    return bytes.fromhex(value)


def profile(document):
    if not isinstance(document, dict) or document.get("schema") != "rea-015-local-buffer-pairs-v1":
        raise BufferDiffError("Unknown sample schema")
    pairs = document.get("pairs")
    if not isinstance(pairs, list) or not 1 <= len(pairs) <= MAX_PAIRS:
        raise BufferDiffError("Invalid pairs")
    rows = []
    for index, item in enumerate(pairs):
        if not isinstance(item, dict):
            raise BufferDiffError("Invalid pair")
        before = decode_hex(item.get("before_hex"), "before")
        after = decode_hex(item.get("after_hex"), "after")
        if len(before) != len(after):
            raise BufferDiffError("Pair lengths differ")
        offset = item.get("offset")
        if type(offset) is not int or not 0 <= offset <= 2**31:
            raise BufferDiffError("Invalid offset")
        mask = bytes(a ^ b for a, b in zip(before, after))
        constant = len(set(mask)) == 1
        changed = sum(a != b for a, b in zip(before, after))
        rows.append({
            "pair_index": index,
            "offset": offset,
            "length": len(before),
            "bytes_changed": changed,
            "all_bytes_unchanged": changed == 0,
            "single_byte_xor_mask_consistent": constant,
            # No masks, keys or raw bytes in output; preserve comparisons locally.
            "before_sha256": hashlib.sha256(before).hexdigest(),
            "after_sha256": hashlib.sha256(after).hexdigest(),
        })
    return {
        "schema": "rea-015-buffer-differential-report-v1",
        "classification": "LOCAL_PAIRWISE_PATTERN_ONLY",
        "observation_authentication": "unverified",
        "original_execution_verified": False,
        "full_body_transformation_proven": False,
        "pairs_processed": len(rows),
        "pairs": rows,
        "warning": "A constant XOR difference is compatible with multiple transformations; hashes alone cannot establish XOR, provenance, key or semantic equivalence.",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pairs", required=True, help="Private local JSON; never commit")
    parser.add_argument("--json", help="Metadata-only JSON output")
    args = parser.parse_args(argv)
    try:
        path = pathlib.Path(args.pairs)
        if path.stat().st_size > MAX_INPUT:
            raise BufferDiffError("Input too large")
        result = profile(json.loads(path.read_text(encoding="utf-8")))
        rendered = json.dumps(result, sort_keys=True, indent=2) + "\n"
        if args.json:
            pathlib.Path(args.json).write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
        return 0
    except (OSError, ValueError) as exc:
        print("REA buffer diff ERROR: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
