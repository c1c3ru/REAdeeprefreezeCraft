# REA — certificacao auditavel

**Referencia:** 2026-10-29
**Resultado:** NAO CERTIFICADO.

Esta certificacao e interna e nao substitui auditoria externa independente.
CI Linux verde nao comprova comportamento em Windows 7.

- Etapas concluidas: **9/17**.
- Gate de cobertura integral: **pendente**.
- Recibos assinados: **0/8**.
- Assinaturas verificadas com chaves externas: **nao**.

## Criterios independentes

| Criterio | Estado |
|---|---|
| inventory | pending |
| structural | pending |
| semantics | pending |
| equivalence | pending |
| drivers | pending |
| windows7_x86 | pending |
| windows7_x64 | pending |
| independent_review | pending |

## Bloqueios presentes

- Global coverage gate is not certified
- Project tasks not all completed
- Unsigned/missing proof: inventory
- Unsigned/missing proof: structural
- Unsigned/missing proof: semantics
- Unsigned/missing proof: equivalence
- Unsigned/missing proof: drivers
- Unsigned/missing proof: windows7_x86
- Unsigned/missing proof: windows7_x64
- Unsigned/missing proof: independent_review
- Trusted external review keys not provided

## Procedimento para emitir atestacao

1. Fechar componentes, denominadores, instrucoes, CFG e drivers com hashes.
2. Comprovar equivalencia observavel de contratos do original e da reimplementacao.
3. Executar cenarios em VMs isoladas Win7 SP1 x86 e x64, com logs/snapshots distintos.
4. Para cada criterio, gerar um recibo JSON vinculado aos hashes da amostra, do escopo e das evidencias.
5. Assinar os recibos com chaves privadas que NUNCA entram no Git.
6. Verificar assinaturas contra chaves publicas confiaveis FORA do repositorio.
7. Exigir revisor independente distinto dos executores.

Validar estado: python -m tools.rea_certification --check
Tentar certificar: python -m tools.rea_certification --require-certified --trusted-keys /trust/keys
Regerar este arquivo: python -m tools.rea_certification --write
