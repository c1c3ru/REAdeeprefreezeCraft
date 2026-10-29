#!/usr/bin/env python3
"""REA-015/Q: validate self-reported ReadFile-to-transform buffer lineage.

Offline only. No sample execution, memory capture, payload bytes or certification.
Python 3.8+ standard library.
"""
import argparse
import json
import pathlib
import re
import sys

SHA = re.compile(r"^[0-9a-f]{64}$")
PTR = re.compile(r"^0x[0-9a-fA-F]{1,16}$")
MAX_EVENTS = 512
MAX_FILE = 2 * 1024 * 1024


class LineageError(ValueError):
    pass


def number(value, minimum, maximum, name):
    if type(value) is not int or not minimum <= value <= maximum:
        raise LineageError("Invalid " + name)
    return value


def pointer(value):
    if not isinstance(value, str) or not PTR.fullmatch(value):
        raise LineageError("Invalid pointer")
    return int(value, 16)


def checksum(value):
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise LineageError("Invalid buffer checksum")
    return value


def validate(trace):
    if not isinstance(trace, dict) or trace.get("schema") != "rea-015-buffer-lineage-v1":
        raise LineageError("Unrecognized lineage schema")
    events = trace.get("events")
    if not isinstance(events, list) or not 1 <= len(events) <= MAX_EVENTS:
        raise LineageError("Invalid events")
    open_handles = set()
    reads = {}
    results = []
    seq_last = 0
    for event in events:
        if not isinstance(event, dict):
            raise LineageError("Malformed event")
        seq = number(event.get("seq"), 1, 100000000, "sequence")
        if seq <= seq_last:
            raise LineageError("Non-monotonic sequence")
        seq_last = seq
        pid = number(event.get("pid"), 1, 0xffffffff, "pid")
        kind = event.get("kind")
        if kind in ("open", "read", "close"):
            handle = pointer(event.get("handle"))
            key = (pid, handle)
            if kind == "open":
                if key in open_handles:
                    raise LineageError("Handle reused without close")
                open_handles.add(key)
            elif kind == "close":
                if key not in open_handles:
                    raise LineageError("Orphan close")
                open_handles.remove(key)
            else:
                if key not in open_handles:
                    raise LineageError("Read without open")
                length = number(event.get("length"), 1, 1048576, "length")
                checksum(event.get("buffer_sha256"))
                address = pointer(event.get("buffer_pointer"))
                rid = event.get("read_id")
                if not isinstance(rid, str) or not rid or len(rid) > 128 or (pid, rid) in reads:
                    raise LineageError("Duplicate or invalid read_id")
                reads[(pid, rid)] = {"seq": seq, "handle": handle, "pointer": address,
                                     "length": length, "hash": event["buffer_sha256"],
                                     "last_consumer": None}
        elif kind == "transform":
            rid = event.get("read_id")
            key = (pid, rid)
            if key not in reads:
                raise LineageError("Transform has no matching read")
            original = reads[key]
            if original["seq"] >= seq or (pid, original["handle"]) not in open_handles:
                raise LineageError("Invalid read-transform lifetime")
            pointer_value = pointer(event.get("input_pointer"))
            length = number(event.get("length"), 1, 1048576, "transform length")
            before = checksum(event.get("before_sha256"))
            after = checksum(event.get("after_sha256"))
            same_region = (pointer_value == original["pointer"] and
                           length == original["length"])
            same_hash = before == original["hash"]
            # Copy/alias of other address is NOT proven merely by matching a digest.
            results.append({"seq": seq, "read_id": rid,
                            "same_buffer_address_and_length": same_region,
                            "pre_transform_hash_matches_read": same_hash,
                            "direct_lineage_consistent": same_region and same_hash,
                            "post_buffer_hash_changed": before != after})
            original["last_consumer"] = seq
        else:
            raise LineageError("Unknown event kind")
    return {"schema": "rea-015-buffer-lineage-report-v1",
            "status": "SELF_REPORTED_CONSISTENCY_ONLY",
            "events_checked": len(events),
            "transform_checks": results,
            "direct_matches": sum(x["direct_lineage_consistent"] for x in results),
            "runtime_authenticated": False,
            "original_executable_verified": False,
            "transformation_semantics_proven": False,
            "certification_receipt_created": False,
            "note": "Address reuse, intervening writes, TOCTOU and fabricated logs are not excluded by this offline validator."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", required=True)
    parser.add_argument("--json")
    args = parser.parse_args(argv)
    try:
        path = pathlib.Path(args.trace)
        if path.stat().st_size > MAX_FILE:
            raise LineageError("Trace too large")
        result = validate(json.loads(path.read_text(encoding="utf-8")))
        rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.json:
            pathlib.Path(args.json).write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
        return 0
    except (ValueError, OSError) as exc:
        print("REA lineage ERROR: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
