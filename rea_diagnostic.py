#!/usr/bin/env python3
"""REA Inspector — read-only CLI for offline reverse-engineering evidence.

Packaging this CLI does not reproduce Deep Freeze, install a driver, run the
original binary or verify execution. Sensitive paired bytes remain PRIVATE.
"""
import json
import platform
import sys

from tools import (
    rea_capture_evidence_intake,
    rea_output_structure,
    rea_private_capture_export,
    rea_runtime_file_correlation,
    rea_xor_differential,
)

COMMANDS = {
    "correlate": rea_runtime_file_correlation.main,
    "xor-check": rea_xor_differential.main,
    "inspect-output": rea_output_structure.main,
    "intake": rea_capture_evidence_intake.main,
    "import-capture": rea_private_capture_export.main,
}

HELP = """REA Inspector — ferramentas offline, sem driver/instalacao

Uso:
  REA-Inspector.exe selfcheck
  REA-Inspector.exe correlate --archive ZIP --trace TRACE --json RESULTADO
  REA-Inspector.exe xor-check --archive ZIP --trace TRACE --pairs PARES --json RESULTADO
  REA-Inspector.exe inspect-output --artifact ARQUIVO --expected-sha256 SHA --capture-id ID --json RESULTADO
  REA-Inspector.exe intake --manifest MANIFESTO --evidence-dir DIRETORIO --json RESULTADO
  REA-Inspector.exe import-capture --private-root DIRETORIO --manifest INDICE --trace-json TRACE --pairs-json PARES

Nao executa o instalador original, nao instala servicos ou drivers.
Arquivo de pares, dumps e amostras originais devem permanecer PRIVADOS.
Use '<comando> --help' para parametros detalhados.
"""


def selfcheck():
    """Environment presence only; never infer Win7/driver semantic equivalence."""
    result = {
        "schema": "rea-diagnostic-portable-selfcheck-v1",
        "platform": platform.system(),
        "platform_release": platform.release(),
        "python_version": "%d.%d.%d" % tuple(sys.version_info[:3]),
        "portable_offline_analyzer": True,
        "installs_drivers": False,
        "modifies_disk_protection": False,
        "runs_original_installer": False,
        "requires_private_samples_for_analysis": True,
        "physical_machine_semantic_equivalence_tested": False,
        "windows7_compatibility_verified": False,
        "certification_receipt_created": False,
        "status": "DIAGNOSTIC_ONLY_NOT_RECONSTRUCTED_PRODUCT",
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)
    if not args or args[0] in ("-h", "--help", "help"):
        print(HELP, end="")
        return 0
    command = args.pop(0)
    if command == "selfcheck":
        if args:
            print("REA Inspector: selfcheck nao recebe parametros", file=sys.stderr)
            return 2
        return selfcheck()
    func = COMMANDS.get(command)
    if func is None:
        print("REA Inspector: comando desconhecido: " + command, file=sys.stderr)
        print("Consulte --help", file=sys.stderr)
        return 2
    return func(args)


if __name__ == "__main__":
    sys.exit(main())
