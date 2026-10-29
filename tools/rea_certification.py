#!/usr/bin/env python3
"""Fail-closed REA internal certification, separate from ordinary CI success.

Requires full coverage, all tasks complete, hashed source-bound signed
receipts, independent reviewer and Win7 x86/x64 observations. Public keys
must be provided OUTSIDE this repository. Not an accredited certification.
Python 3.8+, stdlib; uses openssl only to verify receipts.
"""
import argparse
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys

from .rea_coverage import measure
from .rea_progress import validate as validate_tasks

CLAIMS = ("inventory", "structural", "semantics", "equivalence",
          "drivers", "windows7_x86", "windows7_x64", "independent_review")
HASH = re.compile(r"^[0-9a-f]{64}$")
SIGNER = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{2,63}$")


class CertificateError(ValueError):
    pass


def sha_file(path, limit=64*1024*1024):
    result = hashlib.sha256()
    count = 0
    with pathlib.Path(path).open("rb") as handle:
        for part in iter(lambda: handle.read(1048576), b""):
            count += len(part)
            if count > limit:
                raise CertificateError("Evidence too large")
            result.update(part)
    return result.hexdigest()


def safe_path(root, name, prefix="docs/"):
    if (not isinstance(name, str) or not name.startswith(prefix) or
            "\\" in name or ":" in name or
            any(x in ("", ".", "..") for x in name.split("/"))):
        raise CertificateError("Invalid evidence path: " + repr(name))
    target = (pathlib.Path(root).resolve() / name).resolve()
    try:
        target.relative_to(pathlib.Path(root).resolve())
    except ValueError:
        raise CertificateError("Evidence escapes repository")
    if not target.is_file():
        raise CertificateError("Evidence file missing: " + name)
    return target


def verify_claim_policy(policy):
    if not isinstance(policy, dict) or policy.get("schema") != "rea-certification-v1":
        raise CertificateError("Invalid certification schema")
    records = policy.get("claims")
    if not isinstance(records, list) or [x.get("id") for x in records
                                         if isinstance(x, dict)] != list(CLAIMS):
        raise CertificateError("Missing, duplicate or unordered certification gate")
    for claim in records:
        if claim["status"] not in ("pending", "verified"):
            raise CertificateError("Unknown gate status")
        fields = ("receipt", "receipt_sha256", "signature", "signer")
        if claim["status"] == "pending":
            if any(claim.get(k) is not None for k in fields):
                raise CertificateError("Pending claim has positive evidence")
        elif (not HASH.fullmatch(str(claim.get("receipt_sha256", ""))) or
              not SIGNER.fullmatch(str(claim.get("signer", ""))) or
              not all(isinstance(claim.get(k), str) and claim[k]
                      for k in ("receipt", "signature"))):
            raise CertificateError("Verified gate needs signed receipt")
    return records


def check_receipt(root, record, scope_sha, archive_sha, trusted_keys=None):
    receipt = safe_path(root, record["receipt"], "docs/certification/receipts/")
    signature = safe_path(root, record["signature"], "docs/certification/receipts/")
    if sha_file(receipt, 1048576) != record["receipt_sha256"]:
        raise CertificateError("Receipt digest mismatch: " + record["id"])
    if not 32 <= signature.stat().st_size <= 16384:
        raise CertificateError("Invalid signature length")
    data = json.loads(receipt.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or any((
            data.get("schema") != "rea-signed-receipt-v1",
            data.get("claim_id") != record["id"],
            data.get("scope_sha256") != scope_sha,
            data.get("source_archive_sha256") != archive_sha,
            data.get("result") != "pass")):
        raise CertificateError("Receipt provenance/claim mismatch")
    if not all(isinstance(data.get(k), str) and data[k].strip()
               for k in ("run_id", "method", "reviewed_at")):
        raise CertificateError("Receipt lacking execution provenance")
    cases = data.get("test_cases")
    if (not isinstance(cases, list) or not cases or len(set(cases)) != len(cases)
            or not all(isinstance(x, str) and x for x in cases)):
        raise CertificateError("Receipt missing unique test cases")
    if record["id"] in ("windows7_x86", "windows7_x64"):
        if data.get("platform") != "windows7-sp1-"+record["id"].split("_")[-1]:
            raise CertificateError("Wrong Windows 7 architecture")
    artifacts = data.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise CertificateError("Receipt has no evidence artifacts")
    paths = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise CertificateError("Malformed receipt artifact")
        name, expected = artifact.get("path"), artifact.get("sha256")
        if name in paths or not HASH.fullmatch(str(expected)):
            raise CertificateError("Repeated or unhashed artifact")
        paths.add(name)
        if sha_file(safe_path(root, name)) != expected:
            raise CertificateError("Evidence digest mismatch: "+name)
    if trusted_keys is not None:
        base, trust = pathlib.Path(root).resolve(), pathlib.Path(trusted_keys).resolve()
        if base == trust or base in trust.parents:
            raise CertificateError("Trusted keys must live outside repository")
        key = trust / (record["signer"] + ".pem")
        if not key.is_file() or key.is_symlink():
            raise CertificateError("Missing external trusted signer key")
        if not shutil.which("openssl"):
            raise CertificateError("OpenSSL needed to verify attestations")
        p = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", str(key),
             "-signature", str(signature), str(receipt)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20,
            check=False)
        if p.returncode or b"Verified OK" not in p.stdout:
            raise CertificateError("Cryptographic signature rejected")
    return paths


def assess(root, policy, trusted_keys=None):
    root = pathlib.Path(root)
    records = verify_claim_policy(policy)
    scopefile = root / "docs/coverage/scope.json"
    scope = json.loads(scopefile.read_text(encoding="utf-8"))
    progress = json.loads((root / "docs/progress/tasks.json").read_text(encoding="utf-8"))
    coverage = measure(scope, root)
    tasks = validate_tasks(progress, root)
    blockers = []
    if not coverage["full_coverage_certified"]:
        blockers.append("Global coverage gate is not certified")
    if any(v["status"] != "done" for v in tasks.values()):
        blockers.append("Project tasks not all completed")
    if scope.get("as_of") != progress.get("as_of"):
        blockers.append("Scope/progress checkpoint dates differ")
    receipt_proofs = {}
    for record in records:
        if record["status"] != "verified":
            blockers.append("Unsigned/missing proof: " + record["id"])
        else:
            receipt_proofs[record["id"]] = {
                "signer": record["signer"],
                "artifacts": check_receipt(
                    root, record, sha_file(scopefile),
                    scope["source_archive"]["sha256"], trusted_keys)}
    if len(receipt_proofs) == len(CLAIMS):
        auditor = receipt_proofs["independent_review"]["signer"]
        if auditor in {x["signer"] for name, x in receipt_proofs.items()
                       if name != "independent_review"}:
            blockers.append("Independent reviewer is also evidence executor")
        if receipt_proofs["windows7_x86"]["artifacts"] == receipt_proofs["windows7_x64"]["artifacts"]:
            blockers.append("Windows 7 x86/x64 receipts use identical artifacts")
    if trusted_keys is None:
        blockers.append("Trusted external review keys not provided")
    return {
        "schema": "rea-certification-assessment-v1",
        "certified": not blockers,
        "coverage_passed": coverage["full_coverage_certified"],
        "tasks_done": sum(x["status"] == "done" for x in tasks.values()),
        "tasks_total": len(tasks),
        "signed_receipts_present": len(receipt_proofs),
        "signed_receipts_required": len(CLAIMS),
        "signatures_verified_externally": (trusted_keys is not None and
                                           len(receipt_proofs) == len(CLAIMS)),
        "blockers": blockers,
        "level": "internal_auditable_attestation_not_accredited",
    }


def render(policy, report):
    lines = [
        "# REA — certificacao auditavel", "",
        "**Referencia:** "+policy["as_of"],
        "**Resultado:** "+("CERTIFICADO INTERNAMENTE" if report["certified"]
                           else "NAO CERTIFICADO")+".", "",
        "Esta certificacao e interna e nao substitui auditoria externa independente.",
        "CI Linux verde nao comprova comportamento em Windows 7.", "",
        "- Etapas concluidas: **%d/%d**." % (report["tasks_done"], report["tasks_total"]),
        "- Gate de cobertura integral: **%s**." %
        ("aprovado" if report["coverage_passed"] else "pendente"),
        "- Recibos assinados: **%d/%d**." %
        (report["signed_receipts_present"], report["signed_receipts_required"]),
        "- Assinaturas verificadas com chaves externas: **%s**." %
        ("sim" if report["signatures_verified_externally"] else "nao"),
        "", "## Criterios independentes", "",
        "| Criterio | Estado |", "|---|---|",
    ]
    for claim in policy["claims"]:
        lines.append("| "+claim["id"]+" | "+claim["status"]+" |")
    lines.extend(["", "## Bloqueios presentes", ""])
    lines.extend("- "+block for block in report["blockers"])
    lines.extend(["", "## Procedimento para emitir atestacao", "",
        "1. Fechar componentes, denominadores, instrucoes, CFG e drivers com hashes.",
        "2. Comprovar equivalencia observavel de contratos do original e da reimplementacao.",
        "3. Executar cenarios em VMs isoladas Win7 SP1 x86 e x64, com logs/snapshots distintos.",
        "4. Para cada criterio, gerar um recibo JSON vinculado aos hashes da amostra, do escopo e das evidencias.",
        "5. Assinar os recibos com chaves privadas que NUNCA entram no Git.",
        "6. Verificar assinaturas contra chaves publicas confiaveis FORA do repositorio.",
        "7. Exigir revisor independente distinto dos executores.",
        "", "Validar estado: python -m tools.rea_certification --check",
        "Tentar certificar: python -m tools.rea_certification --require-certified --trusted-keys /trust/keys",
        "Regerar este arquivo: python -m tools.rea_certification --write", "",
    ])
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--write", action="store_true")
    modes.add_argument("--require-certified", action="store_true")
    modes.add_argument("--json", action="store_true")
    parser.add_argument("--root", default=".")
    parser.add_argument("--trusted-keys")
    args = parser.parse_args(argv)
    try:
        root = pathlib.Path(args.root).resolve()
        policy = json.loads((root / "docs/certification/claims.json").read_text(encoding="utf-8"))
        result = assess(root, policy, args.trusted_keys)
        status = render(policy, result)
        destination = root / "docs/certification/STATUS.md"
        if args.check:
            if not destination.is_file() or destination.read_text(encoding="utf-8") != status:
                raise CertificateError("Certification status out of sync")
            print("REA certification status valid: " +
                  ("CERTIFIED" if result["certified"] else "NOT CERTIFIED"))
        elif args.write:
            destination.write_text(status, encoding="utf-8")
            print("Certification report updated")
        elif args.json:
            print(json.dumps(result, sort_keys=True, indent=2))
        elif args.require_certified:
            if not result["certified"]:
                print("NOT CERTIFIED: " + "; ".join(result["blockers"]), file=sys.stderr)
                return 2
            print("Internal certification passed")
        else:
            print(status, end="")
        return 0
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print("REA certification ERROR: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
