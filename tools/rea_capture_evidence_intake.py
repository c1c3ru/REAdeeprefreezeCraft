#!/usr/bin/env python3
"""REA-015/S: offline digest intake for externally obtained Win7 evidence.

A matching digest verifies ONLY local file integrity against the submitted
manifest. It neither authenticates the observer nor signs/certifies a capture.
Private file paths and raw contents must never be committed or emitted.
Python 3.8+, standard library only.
"""
import argparse
import hashlib
import json
import pathlib
import re
import sys

from .rea_overlay_inventory import ROOT_SHA

MAX_MANIFEST_BYTES = 65536
MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
MAX_ITEMS = 12
REQUIRED_ROLES = frozenset(("file_io_trace", "xor_pairs",
                            "observer_log", "vm_environment"))
ALLOWED_ROLES = REQUIRED_ROLES | frozenset(("snapshot_metadata",
                                            "instrumentation_log",
                                            "signature_review"))
SHA = re.compile(r"^[0-9a-f]{64}$")
LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class EvidenceIntakeError(ValueError):
    pass


def required_string(value, label):
    if not isinstance(value, str) or not LABEL.fullmatch(value):
        raise EvidenceIntakeError("Invalid " + label)
    return value


def bounded_bytes(value):
    if type(value) is not int or not 1 <= value <= MAX_ARTIFACT_BYTES:
        raise EvidenceIntakeError("Invalid artifact byte length")
    return value


def verify_bundle(manifest, evidence_dir):
    if not isinstance(manifest, dict) or manifest.get("schema") != \
            "rea-015-win7-evidence-bundle-v1":
        raise EvidenceIntakeError("Unknown evidence manifest schema")
    capture = required_string(manifest.get("capture_id"), "capture label")
    platform = manifest.get("platform")
    if platform not in ("windows7-sp1-x86", "windows7-sp1-x64"):
        raise EvidenceIntakeError("Unsupported capture platform")
    snapshot = required_string(manifest.get("snapshot_id"), "snapshot label")
    method = required_string(manifest.get("instrumentation_method"), "method label")
    if manifest.get("original_pe_sha256") != ROOT_SHA:
        raise EvidenceIntakeError("Original PE identity does not match pinned reference")
    if manifest.get("independently_reviewed") is not False:
        raise EvidenceIntakeError("Observer must not self-assert independent review")
    if manifest.get("network_isolated") is not True:
        raise EvidenceIntakeError("Isolated VM declaration is required")
    items = manifest.get("artifacts")
    if not isinstance(items, list) or not len(REQUIRED_ROLES) <= len(items) <= MAX_ITEMS:
        raise EvidenceIntakeError("Missing or oversized artifact inventory")
    root = pathlib.Path(evidence_dir).resolve(strict=True)
    if not root.is_dir():
        raise EvidenceIntakeError("Evidence root is not a directory")
    roles = set()
    result = []
    for item in items:
        if not isinstance(item, dict):
            raise EvidenceIntakeError("Malformed artifact inventory item")
        role = item.get("role")
        if role not in ALLOWED_ROLES or role in roles:
            raise EvidenceIntakeError("Unknown or repeated artifact role")
        roles.add(role)
        rel = item.get("relative_path")
        if not isinstance(rel, str) or not rel or "\x00" in rel:
            raise EvidenceIntakeError("Invalid private artifact path")
        local = pathlib.Path(rel)
        if local.is_absolute() or ".." in local.parts:
            raise EvidenceIntakeError("Artifact must stay below evidence root")
        path = (root / local).resolve(strict=True)
        if root not in path.parents or not path.is_file():
            raise EvidenceIntakeError("Artifact resolves outside private evidence root")
        expected = item.get("sha256")
        if not isinstance(expected, str) or not SHA.fullmatch(expected):
            raise EvidenceIntakeError("Missing artifact SHA-256")
        expected_size = bounded_bytes(item.get("size_bytes"))
        if path.stat().st_size != expected_size:
            raise EvidenceIntakeError("Artifact byte length does not match manifest")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while True:
                data = stream.read(1048576)
                if not data:
                    break
                digest.update(data)
        if digest.hexdigest() != expected:
            raise EvidenceIntakeError("Artifact SHA-256 differs from manifest")
        result.append({"role": role, "size_bytes": expected_size,
                       "sha256": expected, "local_integrity_match": True})
    if not REQUIRED_ROLES.issubset(roles):
        raise EvidenceIntakeError("Mandatory capture evidence roles are missing")
    return {
        "schema": "rea-015-win7-evidence-intake-report-v1",
        "capture_id_label": capture,
        "platform_label": platform,
        "vm_snapshot_id_label": snapshot,
        "instrumentation_method_label": method,
        "source_pe_sha256": ROOT_SHA,
        "artifact_count": len(result),
        "artifacts": sorted(result, key=lambda item: item["role"]),
        "local_manifest_digest_consistency": True,
        "status": "LOCAL_DIGEST_INTEGRITY_ONLY_REVIEW_REQUIRED",
        "original_executable_run_authenticated": False,
        "instrumentation_trusted": False,
        "independent_reviewer_signature_verified": False,
        "runtime_semantic_equivalence_verified": False,
        "certification_receipt_created": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, help="PRIVATE VM manifest JSON")
    parser.add_argument("--evidence-dir", required=True, help="PRIVATE file root")
    parser.add_argument("--json", help="Metadata-only local output; stdout if omitted")
    args = parser.parse_args(argv)
    try:
        manifest_path = pathlib.Path(args.manifest)
        if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
            raise EvidenceIntakeError("Manifest exceeds size bound")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        report = verify_bundle(manifest, args.evidence_dir)
        output = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.json:
            pathlib.Path(args.json).write_text(output, encoding="utf-8")
        else:
            print(output, end="")
        return 0
    except (OSError, ValueError, UnicodeError) as exc:
        print("REA-015/S evidence intake ERROR: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
