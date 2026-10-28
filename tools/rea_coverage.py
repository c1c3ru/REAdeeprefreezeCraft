#!/usr/bin/env python3
"""Auditable full-scope REA coverage, without claiming unverified 100 percent.

Only a known PE's bounded decoded intervals count towards its measured
executable-section byte denominator. All other coverage remains unknown.
Python 3.8 stdlib; never executes or extracts an executable.
"""
import argparse
import hashlib
import json
import pathlib
import re
import sys
import zipfile


class CoverageError(ValueError):
    pass


def rva(value):
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]+", value):
        raise CoverageError("Expected hex RVA: %r" % value)
    return int(value, 16)


def normalized_interval(start, end):
    a, b = rva(start), rva(end)
    if b <= a:
        raise CoverageError("Invalid interval")
    return (a, b)


def union_size(intervals):
    total, previous = 0, -1
    for a, b in sorted(intervals):
        if a < previous:
            raise CoverageError("Overlapping intervals cannot be double-counted")
        total += b - a
        previous = b
    return total


def validate(manifest, root=None):
    if not isinstance(manifest, dict) or manifest.get("schema") != "rea-full-scope-v1":
        raise CoverageError("Unknown manifest schema")
    gates = ("discovery_closed", "reconstruction_complete",
             "semantic_equivalence_verified", "windows7_sp1_x86_verified",
             "windows7_sp1_x64_verified")
    if any(type(manifest.get(gate)) is not bool for gate in gates):
        raise CoverageError("Invalid coverage gates")
    archive = manifest.get("source_archive", {})
    if not re.fullmatch(r"[0-9a-f]{64}", str(archive.get("sha256", ""))):
        raise CoverageError("Archive hash missing")
    components = manifest.get("components")
    if not isinstance(components, list) or not components:
        raise CoverageError("Components missing")
    seen = set()
    for comp in components:
        cid = comp.get("id")
        if not isinstance(cid, str) or not cid or cid in seen:
            raise CoverageError("Invalid or duplicate component")
        seen.add(cid)
        kind = comp.get("kind")
        if kind not in ("observed_pe", "filename_reference"):
            raise CoverageError("Unrecognized component kind")
        sections, windows = comp.get("executable_sections"), comp.get("decoded_intervals")
        if not isinstance(sections, list) or not isinstance(windows, list):
            raise CoverageError("Missing sections or decoded intervals")
        if kind == "filename_reference":
            if comp.get("sha256") is not None or comp.get("size_bytes") is not None:
                raise CoverageError("Filename reference is not a recovered driver")
            if sections or windows or comp.get("behavior_verified"):
                raise CoverageError("Unrecovered driver cannot claim coverage")
            continue
        if not re.fullmatch(r"[0-9a-f]{64}", str(comp.get("sha256", ""))):
            raise CoverageError("Observed PE missing SHA256")
        if type(comp.get("size_bytes")) is not int or comp["size_bytes"] <= 0:
            raise CoverageError("Observed PE missing size")
        if comp.get("semantics_status") not in ("unmeasured", "partial", "verified"):
            raise CoverageError("Invalid semantics status")
        if type(comp.get("behavior_verified")) is not bool:
            raise CoverageError("Missing behavioral status")
        secs = []
        for s in sections:
            length = s.get("raw_size")
            if type(length) is not int or length <= 0:
                raise CoverageError("Invalid executable section size")
            a = rva(s["start_rva"])
            secs.append((a, a + length))
        union_size(secs)
        decoded = []
        for window in windows:
            a, b = normalized_interval(window["start_rva"], window["end_rva_exclusive"])
            if not any(a >= x and b <= y for x, y in secs):
                raise CoverageError("Decoded interval outside executable section")
            evidence = window.get("evidence")
            if not isinstance(evidence, str) or not evidence.startswith("docs/"):
                raise CoverageError("Missing scoped evidence")
            if root is not None:
                base = pathlib.Path(root).resolve()
                file = (base / evidence).resolve()
                if base not in file.parents or not file.is_file():
                    raise CoverageError("Missing or unsafe evidence: " + evidence)
            decoded.append((a, b))
        union_size(decoded)
        if decoded and comp["semantics_status"] == "unmeasured":
            raise CoverageError("Measured intervals cannot be marked unmeasured")
        if comp["semantics_status"] == "verified" and not comp["behavior_verified"]:
            raise CoverageError("Semantic verification requires behavioral evidence")
    if not isinstance(manifest.get("unknowns"), list):
        raise CoverageError("Unknowns must be explicit")
    return manifest


def measure(manifest, root=None):
    validate(manifest, root)
    details = []
    known, decoded, missing_denominator, driver_refs = 0, 0, 0, 0
    fully_measured_and_verified = True
    for item in manifest["components"]:
        if item["kind"] == "filename_reference":
            driver_refs += 1
            continue
        if not item["executable_sections"]:
            missing_denominator += 1
            fully_measured_and_verified = False
            details.append({"id": item["id"], "known_bytes": None,
                            "decoded_bytes": 0, "decoded_percent": None,
                            "semantics": item["semantics_status"]})
            continue
        nbytes = sum(s["raw_size"] for s in item["executable_sections"])
        ndecoded = union_size([
            normalized_interval(w["start_rva"], w["end_rva_exclusive"])
            for w in item["decoded_intervals"]
        ])
        known += nbytes
        decoded += ndecoded
        if ndecoded != nbytes or not item["behavior_verified"] or item["semantics_status"] != "verified":
            fully_measured_and_verified = False
        details.append({"id": item["id"], "known_bytes": nbytes,
                        "decoded_bytes": ndecoded,
                        "decoded_percent": round(100.0 * ndecoded / nbytes, 8),
                        "semantics": item["semantics_status"]})
    gates = {key: manifest[key] for key in (
        "discovery_closed", "reconstruction_complete", "semantic_equivalence_verified",
        "windows7_sp1_x86_verified", "windows7_sp1_x64_verified")}
    certified = (fully_measured_and_verified and all(gates.values())
                 and not missing_denominator and not driver_refs and not manifest["unknowns"])
    return {
        "schema": "rea-coverage-report-v1",
        "known_pes": len(details),
        "unrecovered_driver_name_references": driver_refs,
        "unknown_executable_denominators": missing_denominator,
        "measured_executable_bytes": known,
        "locally_decoded_bytes": decoded,
        "measured_modules_local_percent": round(100.0 * decoded / known, 8) if known else None,
        "global_executable_denominator_closed": bool(
            manifest["discovery_closed"] and not missing_denominator and not driver_refs),
        "global_reverse_engineering_percent": 100 if certified else None,
        "full_coverage_certified": certified,
        "gates": gates, "modules": details,
        "unknowns": manifest["unknowns"],
        "interpretation": "Decoded bytes are a bounded structural sample, not semantic or behavioral coverage.",
    }


def render(manifest, report):
    pct = report["measured_modules_local_percent"]
    lines = [
        "# REA — cobertura integral verificável", "",
        "**Referência:** " + manifest["as_of"],
        "**Produto:** " + manifest["product"], "",
        "**Objetivo:** " + manifest["objective"], "",
        "## Linha de base", "",
        "- PEs identificados: **%d**." % report["known_pes"],
        "- Referências a nomes de driver sem binário: **%d**." %
        report["unrecovered_driver_name_references"],
        "- PEs com denominador executivo desconhecido: **%d**." %
        report["unknown_executable_denominators"],
        "- Bytes executáveis medidos: **%d**." % report["measured_executable_bytes"],
        "- Bytes de janelas estruturalmente desmontadas: **%d**." %
        report["locally_decoded_bytes"],
        "- Fração das janelas sobre o denominador conhecido: **%s**." %
        ("desconhecida" if pct is None else "%.8f%%" % pct),
        "- Denominador global do produto fechado: **%s**." %
        ("sim" if report["global_executable_denominator_closed"] else "não"),
        "- Engenharia reversa integral certificada: **%s**." %
        ("sim" if report["full_coverage_certified"] else "não"), "",
        "> " + report["interpretation"], "",
        "A fração local não é cobertura do produto completo; portanto o percentual "
        "global permanece **indeterminado**, até fechamento de escopo e testes.", "",
        "## Artefatos analisados", "",
        "| Componente | Bytes executáveis conhecidos | Bytes de janelas | Percentual local | Semântica |",
        "|---|---:|---:|---:|---|",
    ]
    for item in report["modules"]:
        value = ("desconhecido" if item["known_bytes"] is None else str(item["known_bytes"]))
        percent = ("—" if item["decoded_percent"] is None else
                   "%.8f%%" % item["decoded_percent"])
        lines.append("| %s | %s | %d | %s | %s |" %
                     (item["id"], value, item["decoded_bytes"], percent, item["semantics"]))
    lines += ["", "## Desconhecidos que impedem 100%", ""]
    lines.extend("- " + str(v) for v in report["unknowns"])
    lines += ["", "## Engenharia de loop — próximos alvos", ""]
    for task in manifest.get("work_queue", []):
        lines.append("- **%s:** %s ([issue](%s))." %
                     (task["id"], task["goal"], task["issue"]))
    lines += ["", "## Regra de conclusão", "",
              "Nunca declarar 100% global com artefatos/denominadores desconhecidos, "
              "drivers não recuperados, bytes não classificados ou testes de equivalência "
              "e Windows 7 SP1 x86/x64 ausentes.", "",
              "Regenerar: python -m tools.rea_coverage --write",
              "Validar: python -m tools.rea_coverage --check", ""]
    return "\n".join(lines)


def verify_archive(path, manifest):
    archive = pathlib.Path(path)
    h = hashlib.sha256()
    with archive.open("rb") as f:
        for chunk in iter(lambda: f.read(1048576), b""):
            h.update(chunk)
    if h.hexdigest() != manifest["source_archive"]["sha256"]:
        raise CoverageError("Archive SHA256 mismatch")
    verified = []
    with zipfile.ZipFile(archive) as zf:
        for item in manifest["components"]:
            if item["kind"] != "observed_pe" or item["origin"] != "archive_member":
                continue
            matches = [i for i in zf.infolist() if i.filename == item["path"]]
            if len(matches) != 1 or matches[0].file_size != item["size_bytes"]:
                raise CoverageError("Archive member not uniquely matched")
            if matches[0].file_size > 64 * 1024 * 1024:
                raise CoverageError("PE too large")
            seen, member_hash = 0, hashlib.sha256()
            with zf.open(matches[0]) as f:
                for chunk in iter(lambda: f.read(1048576), b""):
                    seen += len(chunk)
                    if seen > item["size_bytes"]:
                        raise CoverageError("ZIP size mismatch")
                    member_hash.update(chunk)
            if seen != item["size_bytes"] or member_hash.hexdigest() != item["sha256"]:
                raise CoverageError("PE hash mismatch")
            verified.append(item["id"])
    return verified


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    opts = parser.add_mutually_exclusive_group()
    opts.add_argument("--check", action="store_true")
    opts.add_argument("--write", action="store_true")
    opts.add_argument("--json", action="store_true")
    parser.add_argument("--root", default=".")
    parser.add_argument("--archive")
    args = parser.parse_args(argv)
    root = pathlib.Path(args.root)
    try:
        manifest = json.loads((root / "docs/coverage/scope.json").read_text(encoding="utf-8"))
        report = measure(manifest, root)
        if args.archive:
            report["archive_verified_direct_members"] = verify_archive(args.archive, manifest)
        document = render(manifest, report)
        target = root / "docs/coverage/STATUS.md"
        if args.check:
            if not target.is_file() or target.read_text(encoding="utf-8") != document:
                raise CoverageError("Coverage status is stale; regenerate and commit")
            print("REA full-scope ledger valid; 100 percent gate: %s" %
                  ("certified" if report["full_coverage_certified"] else "not certified"))
        elif args.write:
            target.write_text(document, encoding="utf-8")
            print("Coverage report generated")
        elif args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            print(document, end="")
        return 0
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print("REA coverage ERROR: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
