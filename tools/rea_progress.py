#!/usr/bin/env python3
"""REA status loop: validate evidence, dependencies, and generated documentation.

Python 3.8+ / stdlib. Verifies presence and consistency, NOT semantic truth.
"""
import argparse
import json
import pathlib
import re
import sys

ALLOWED = {"done", "todo", "blocked"}
PRIORITY = ("P0", "P1", "P2")


class ProgressError(ValueError):
    pass


def read_manifest(path):
    with pathlib.Path(path).open("r", encoding="utf-8") as stream:
        return json.load(stream)


def safe_evidence(root, label):
    if (not isinstance(label, str) or not label or "\\" in label
            or label.startswith("/") or any(x in ("", ".", "..") for x in label.split("/"))):
        raise ProgressError("Unsafe evidence path: %r" % label)
    target = pathlib.Path(root).joinpath(*label.split("/"))
    try:
        target.resolve().relative_to(pathlib.Path(root).resolve())
    except ValueError:
        raise ProgressError("Evidence outside repository: " + label)
    if not target.is_file():
        raise ProgressError("Missing evidence: " + label)


def validate(data, root):
    if not isinstance(data, dict) or data.get("schema") != "rea-progress-v1":
        raise ProgressError("Unknown progress manifest")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(data.get("as_of", ""))):
        raise ProgressError("Invalid update date")
    if not isinstance(data.get("objective"), str) or not data["objective"].strip():
        raise ProgressError("Missing project objective")
    tasks = data.get("tasks")
    if not isinstance(tasks, list) or not tasks:
        raise ProgressError("Empty task list")
    index = {}
    for task in tasks:
        if not isinstance(task, dict):
            raise ProgressError("Task must be an object")
        identifier = task.get("id")
        if not isinstance(identifier, str) or not re.fullmatch(r"REA-\d{3}", identifier):
            raise ProgressError("Invalid task identifier")
        if identifier in index:
            raise ProgressError("Duplicate task identifier: " + identifier)
        index[identifier] = task
        if task.get("status") not in ALLOWED or task.get("priority") not in PRIORITY:
            raise ProgressError("Invalid task status/priority: " + identifier)
        for field in ("title", "phase", "next_action"):
            if not isinstance(task.get(field), str) or not task[field].strip():
                raise ProgressError("Missing %s: %s" % (field, identifier))
        for field in ("acceptance", "evidence", "depends_on"):
            value = task.get(field)
            if not isinstance(value, list) or not all(
                    isinstance(x, str) and x.strip() for x in value):
                raise ProgressError("Invalid %s: %s" % (field, identifier))
            if len(value) != len(set(value)):
                raise ProgressError("Duplicated %s: %s" % (field, identifier))
        if not task["acceptance"]:
            raise ProgressError("Acceptance criteria missing: " + identifier)
        if task["status"] == "done" and not task["evidence"]:
            raise ProgressError("Done without evidence: " + identifier)
        if task["status"] == "blocked" and not task.get("blocker"):
            raise ProgressError("Blocked without reason: " + identifier)
        if task.get("issue") and (not isinstance(task["issue"], str)
                                  or not task["issue"].startswith("https://github.com/")
                                  or "/issues/" not in task["issue"]):
            raise ProgressError("Invalid GitHub issue: " + identifier)
        for filename in task["evidence"]:
            safe_evidence(root, filename)
    visiting, visited = set(), set()

    def walk(identifier):
        if identifier in visiting:
            raise ProgressError("Cyclic dependency: " + identifier)
        if identifier in visited:
            return
        visiting.add(identifier)
        task = index[identifier]
        for dependency in task["depends_on"]:
            if dependency == identifier or dependency not in index:
                raise ProgressError("Unknown/self dependency: " + identifier)
            walk(dependency)
            if task["status"] == "done" and index[dependency]["status"] != "done":
                raise ProgressError("Done despite unfinished dependency: " + identifier)
        visiting.remove(identifier)
        visited.add(identifier)
    for identifier in index:
        walk(identifier)
    return index


def groups(index):
    completed = [t for t in index.values() if t["status"] == "done"]
    ready = [t for t in index.values() if t["status"] == "todo"
             and all(index[d]["status"] == "done" for d in t["depends_on"])]
    waiting = [t for t in index.values() if t["status"] == "todo" and t not in ready]
    blocked = [t for t in index.values() if t["status"] == "blocked"]
    return {"done": completed, "ready": ready, "waiting": waiting, "blocked": blocked}


def cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def render(data, root):
    index = validate(data, root)
    result = groups(index)
    lines = [
        "# REAdeeprefreezeCraft — Status atualizado", "",
        "> Documento gerado. Fonte de verdade: [tasks.json](progress/tasks.json). "
        "Para editar, altere o manifesto e rode python -m tools.rea_progress --write.", "",
        "**Data de referência:** " + data["as_of"], "",
        "**Objetivo:** " + data["objective"], "",
        "## Indicadores de entregas", "",
        "- Concluídas: **%d/%d**." % (len(result["done"]), len(index)),
        "- Prontas: **%d**." % len(result["ready"]),
        "- Aguardando dependências: **%d**." % len(result["waiting"]),
        "- Bloqueadas explicitamente: **%d**." % len(result["blocked"]), "",
        "> " + data.get("scope_note", ""), "",
        "## Backlog e estados", "",
        "| ID | Entrega | Estado | Prioridade | Dependências | Issue |",
        "|---|---|---|---|---|---|",
    ]
    for item in index.values():
        issue = item.get("issue", "")
        issue_label = ("[#" + issue.rsplit("/", 1)[-1] + "](" + issue + ")") if issue else "—"
        deps = ", ".join(item["depends_on"]) or "—"
        lines.append("| %s | %s | %s | %s | %s | %s |" %
                     (item["id"], cell(item["title"]), item["status"],
                      item["priority"], deps, issue_label))
    lines += ["", "## Próximo loop: tarefas prontas", "",
              "Priorize P0; cada tarefa avança em um PR, com testes e evidências.", ""]
    ready = sorted(result["ready"],
                   key=lambda item: (PRIORITY.index(item["priority"]), item["id"]))
    if ready:
        for item in ready:
            lines.append("- **%s (%s):** %s" %
                         (item["id"], item["priority"], item["next_action"]))
    else:
        lines.append("- Sem tarefas prontas: resolver dependências.")
    lines += ["", "## Bloqueios e dependências abertas", ""]
    if not result["waiting"] and not result["blocked"]:
        lines.append("- Nenhum.")
    for item in result["waiting"]:
        remaining = [d for d in item["depends_on"] if index[d]["status"] != "done"]
        lines.append("- **%s** aguarda: %s." % (item["id"], ", ".join(remaining)))
    for item in result["blocked"]:
        lines.append("- **%s** bloqueada: %s." %
                     (item["id"], item["blocker"].rstrip(".")))
    lines += ["", "## Evidências e aceite por tarefa", ""]
    for item in index.values():
        lines += ["### " + item["id"] + " — " + item["title"], "",
                  "**Status:** " + item["status"] + " · **Etapa:** " + item["phase"], ""]
        for criterion in item["acceptance"]:
            lines.append("- [x] " + criterion if item["status"] == "done"
                         else "- [ ] " + criterion)
        if item["evidence"]:
            lines += ["", "Evidências:"]
            for filename in item["evidence"]:
                lines.append("- [" + filename + "](../" + filename + ")")
        lines.append("")
    lines += [
        "## Engenharia de loop: protocolo de conclusão", "",
        "1. **Descoberta:** escolher a próxima tarefa pronta e identificar lacunas.",
        "2. **Reconstrução:** produzir evidências com hash, RVA, condições e incertezas.",
        "3. **Teste:** escrever fixtures sintéticas, executar CI Python 3.8/3.12.",
        "4. **Revisão:** abrir PR, registrar resultados e revisar critérios.",
        "5. **Checkpoint:** atualizar tasks.json e regenerar este documento.",
        "6. **Nova iteração:** selecionar a próxima tarefa pronta; não fechar bloqueios sem teste.", "",
        "**Importante:** estes controles validam evidências documentais e testes de "
        "código próprio, não equivalência semântica, assinaturas ou Windows 7.", "",
    ]
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--json", action="store_true")
    parser.add_argument("--root", default=".")
    args = parser.parse_args(argv)
    root = pathlib.Path(args.root)
    try:
        manifest = read_manifest(root / "docs/progress/tasks.json")
        text = render(manifest, root)
        status = root / "docs/STATUS_ATUAL.md"
        if args.check:
            if not status.is_file() or status.read_text(encoding="utf-8") != text:
                raise ProgressError("Status desatualizado: execute --write e versione")
            print("REA: status e evidencias validos; %d tarefas" % len(manifest["tasks"]))
        elif args.write:
            status.write_text(text, encoding="utf-8")
            print("Status atualizado: " + str(status))
        elif args.json:
            tally = {key: len(value) for key, value in groups(
                validate(manifest, root)).items()}
            tally["total"] = len(manifest["tasks"])
            print(json.dumps(tally, sort_keys=True))
        else:
            print(text, end="")
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("REA progress ERROR: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
