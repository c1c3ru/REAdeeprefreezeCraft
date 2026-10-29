#!/usr/bin/env python3
"""REA-015/S: audit offline report readiness, never certify VM execution.

All input reports are self-reported. Missing reports are deficiencies; a complete
set is NOT proof of authentic execution or equivalence.
Python 3.8+ stdlib.
"""
import argparse
import json
from pathlib import Path

MAX_SIZE = 2 * 1024 * 1024
SCHEMAS = {
    "correlation": "rea-015-file-io-correlation-v1",
    "probes": "rea-015-targeted-probe-plan-v1",
    "differences": "rea-015-buffer-differential-report-v1",
    "lineage": "rea-015-buffer-lineage-report-v1",
}


class ReadinessError(ValueError):
    pass


def load_report(path, expected):
    p = Path(path)
    if p.stat().st_size > MAX_SIZE:
        raise ReadinessError("Report too large: " + expected)
    doc = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMAS[expected]:
        raise ReadinessError("Unexpected schema: " + expected)
    return doc


def audit(docs):
    if not isinstance(docs, dict):
        raise ReadinessError("Invalid collection")
    errors, warnings = [], []
    for key in SCHEMAS:
        if key not in docs:
            errors.append("missing_report:" + key)
        elif not isinstance(docs[key], dict) or docs[key].get("schema") != SCHEMAS[key]:
            errors.append("invalid_schema:" + key)
    corr, probes, diff, lineage = (docs.get(k, {}) if isinstance(docs.get(k), dict) else {}
                                 for k in ("correlation", "probes", "differences", "lineage"))
    if corr:
        if corr.get("opened_file_hash_consistent_with_reference") is not True:
            errors.append("no_reference_file_hash_match")
        if corr.get("reads_matching_expected_bytes", 0) <= 0:
            errors.append("no_matching_read_buffers")
        if corr.get("transformation_applied_to_body_proven") is True or corr.get("certification_receipt_created") is True:
            warnings.append("self_reported_proof_claim_requires_external_audit")
    if probes and corr and probes.get("source_capture_id") != corr.get("capture_id"):
        errors.append("probe_capture_id_mismatch")
    if diff and diff.get("pairs_processed", 0) <= 0:
        errors.append("no_buffer_pairs")
    if lineage and lineage.get("direct_matches", 0) <= 0:
        errors.append("no_direct_lineage_matches")
    if corr and lineage:
        warnings.append("lineage_schema_does_not_bind_to_correlation_capture_id_or_read_event")
    if corr and diff:
        warnings.append("differential_schema_does_not_bind_pairs_to_lineage_transform_events")
    warnings.append("original_vm_execution_and_chain_of_custody_not_authenticated")
    return {
        "schema": "rea-015-capture-readiness-v1",
        "reports_present": sorted(k for k in SCHEMAS if k in docs),
        "gaps": errors,
        "warnings": warnings,
        "local_data_readiness": "INCOMPLETE" if errors else "CONSISTENT_REPORT_SET_UNAUTHENTICATED",
        "original_execution_verified": False,
        "certification_receipt_created": False,
        "ready_for_certification": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for key in SCHEMAS:
        parser.add_argument("--" + key, help="Local JSON report")
    parser.add_argument("--json", help="Metadata-only output path")
    args = parser.parse_args(argv)
    try:
        docs = {key: load_report(getattr(args, key), key) for key in SCHEMAS
                if getattr(args, key)}
        output = json.dumps(audit(docs), indent=2, sort_keys=True) + "\n"
        if args.json:
            Path(args.json).write_text(output, encoding="utf-8")
        else:
            print(output, end="")
        return 0
    except (OSError, ValueError) as exc:
        parser.exit(1, "REA readiness ERROR: %s\n" % exc)


if __name__ == "__main__":
    main()
