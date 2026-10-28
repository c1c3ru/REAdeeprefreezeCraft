# REAdeeprefreezeCraft — Status atualizado

> Documento gerado. Fonte de verdade: [tasks.json](progress/tasks.json). Para editar, altere o manifesto e rode python -m tools.rea_progress --write.

**Data de referência:** 2026-10-28

**Objetivo:** Especificar e validar comportamentos observáveis dos componentes analisados do Deep Freeze, com contratos rastreáveis e validação independente em Windows 7 SP1 x86 e x64, sem redistribuir código proprietário.

## Indicadores de entregas

- Concluídas: **7/13**.
- Prontas: **2**.
- Aguardando dependências: **2**.
- Bloqueadas explicitamente: **2**.

> Conclusões estáticas não comprovam semântica, operação de drivers, proteção de disco ou compatibilidade do produto. A contagem de tarefas concluídas não mede percentual de engenharia reversa completa.

## Backlog e estados

| ID | Entrega | Estado | Prioridade | Dependências | Issue |
|---|---|---|---|---|---|
| REA-001 | Inventariar o pacote e preservar proveniência | done | P0 | — | — |
| REA-002 | Mapear PE embutidos, importações e interfaces preliminares | done | P0 | REA-001 | — |
| REA-003 | Automatizar descoberta de thunks e calls x86 | done | P0 | REA-002 | — |
| REA-004 | Desmontar chamadas e construir CFGs delimitados | done | P0 | REA-003 | — |
| REA-005 | Rastrear a cadeia interprocedural e dados estáticos | done | P0 | REA-004 | — |
| REA-006 | Instituir plano, status verificável e ciclos de avanço | done | P0 | REA-005 | — |
| REA-007 | Cobrir todas as saídas e condições dos laços das duas funções | done | P0 | REA-006 | [#9](https://github.com/c1c3ru/REAdeeprefreezeCraft/issues/9) |
| REA-008 | Rastrear handles, buffers, tamanhos e retornos | todo | P0 | REA-005 | [#10](https://github.com/c1c3ru/REAdeeprefreezeCraft/issues/10) |
| REA-009 | Localizar drivers reais e validar assinaturas | todo | P0 | REA-002 | [#11](https://github.com/c1c3ru/REAdeeprefreezeCraft/issues/11) |
| REA-010 | Validar Windows 7 SP1 x86 em VM isolada | blocked | P1 | REA-009 | [#12](https://github.com/c1c3ru/REAdeeprefreezeCraft/issues/12) |
| REA-011 | Validar Windows 7 SP1 x64 em VM isolada | blocked | P1 | REA-009 | [#12](https://github.com/c1c3ru/REAdeeprefreezeCraft/issues/12) |
| REA-012 | Construir contratos e testes de equivalência observável | todo | P1 | REA-007, REA-008, REA-009 | [#13](https://github.com/c1c3ru/REAdeeprefreezeCraft/issues/13) |
| REA-013 | Certificar o escopo validado e registrar limites Windows 7 | todo | P1 | REA-010, REA-011, REA-012 | [#13](https://github.com/c1c3ru/REAdeeprefreezeCraft/issues/13) |

## Próximo loop: tarefas prontas

Priorize P0; cada tarefa avança em um PR, com testes e evidências.

- **REA-008 (P0):** Investigar fluxos de EAX/EBX e origens dos argumentos [EBP+n]
- **REA-009 (P0):** Catalogar recursos PE e verificar se os drivers podem ser obtidos sem execução

## Bloqueios e dependências abertas

- **REA-012** aguarda: REA-008, REA-009.
- **REA-013** aguarda: REA-010, REA-011, REA-012.
- **REA-010** bloqueada: Faltam VM Windows 7 SP1 x86 autorizada, snapshots e artefatos/assinaturas verificados.
- **REA-011** bloqueada: Faltam VM Windows 7 SP1 x64 autorizada, snapshots e artefatos/assinaturas verificados.

## Evidências e aceite por tarefa

### REA-001 — Inventariar o pacote e preservar proveniência

**Status:** done · **Etapa:** Fundação

- [x] Identificar o PE, hashes e restrições da análise estática
- [x] Documentar separação entre ZIP comercial e código próprio

Evidências:
- [tools/rea_inventory.py](../tools/rea_inventory.py)
- [docs/analyses/DeepFreeze_9.00.020.5760.md](../docs/analyses/DeepFreeze_9.00.020.5760.md)

### REA-002 — Mapear PE embutidos, importações e interfaces preliminares

**Status:** done · **Etapa:** Fundação

- [x] Catalogar recursos PE, imports e referências a drivers
- [x] Registrar limitações do empacotamento e strings

Evidências:
- [tools/rea_structural.py](../tools/rea_structural.py)
- [docs/analyses/STRUCTURAL_2026-10-28.md](../docs/analyses/STRUCTURAL_2026-10-28.md)
- [docs/INTERFACES_USER_KERNEL.md](../docs/INTERFACES_USER_KERNEL.md)

### REA-003 — Automatizar descoberta de thunks e calls x86

**Status:** done · **Etapa:** Fundação

- [x] Mapear candidatos E8/FF25 e seus endereços
- [x] Classificar constantes como hipóteses, não chamadas comprovadas

Evidências:
- [tools/rea_loop.py](../tools/rea_loop.py)
- [docs/analyses/LOOP_DEVICEIO_2026-10-28.md](../docs/analyses/LOOP_DEVICEIO_2026-10-28.md)

### REA-004 — Desmontar chamadas e construir CFGs delimitados

**Status:** done · **Etapa:** Fundação

- [x] Registrar RVA, bloco, arestas locais e dominadores
- [x] Diferenciar CFG local de cobertura de execução

Evidências:
- [tools/rea_cfg.py](../tools/rea_cfg.py)
- [tools/rea_function_cfg.py](../tools/rea_function_cfg.py)
- [docs/analyses/FUNCTION_CFG_2026-10-28.md](../docs/analyses/FUNCTION_CFG_2026-10-28.md)

### REA-005 — Rastrear a cadeia interprocedural e dados estáticos

**Status:** done · **Etapa:** Fundação

- [x] Documentar a cadeia tabela → função auxiliar → API
- [x] Manter identidade do dispositivo e efeitos como desconhecidos

Evidências:
- [tools/rea_contract_trace.py](../tools/rea_contract_trace.py)
- [docs/analyses/CONTRACT_CHAIN_2026-10-28.md](../docs/analyses/CONTRACT_CHAIN_2026-10-28.md)
- [docs/contracts/cycle6_findings.json](../docs/contracts/cycle6_findings.json)

### REA-006 — Instituir plano, status verificável e ciclos de avanço

**Status:** done · **Etapa:** Governança

- [x] Registrar metas, aceite, dependências, riscos e evidências
- [x] Executar validação automática do status no CI

Evidências:
- [docs/PLANO_DE_ACAO.md](../docs/PLANO_DE_ACAO.md)
- [docs/STATUS_ATUAL.md](../docs/STATUS_ATUAL.md)
- [docs/progress/tasks.json](../docs/progress/tasks.json)
- [tools/rea_progress.py](../tools/rea_progress.py)
- [tests/test_rea_progress.py](../tests/test_rea_progress.py)

### REA-007 — Cobrir todas as saídas e condições dos laços das duas funções

**Status:** done · **Etapa:** Reconstrução

- [x] Inventariar ramos condicionais e saídas por endereço
- [x] Ter teste sintético para saídas antecipadas, saltos não resolvidos e limites
- [x] Atualizar contratos sem afirmar CFG global completo

Evidências:
- [tools/rea_path_coverage.py](../tools/rea_path_coverage.py)
- [tests/test_rea_path_coverage.py](../tests/test_rea_path_coverage.py)
- [docs/contracts/rea007_exit_paths.json](../docs/contracts/rea007_exit_paths.json)
- [docs/analyses/REA_007_BRANCH_EXITS.md](../docs/analyses/REA_007_BRANCH_EXITS.md)

### REA-008 — Rastrear handles, buffers, tamanhos e retornos

**Status:** todo · **Etapa:** Reconstrução

- [ ] Rastrear proveniência dos argumentos de CreateFileA/DeviceIoControl/CloseHandle
- [ ] Criar relatório JSON de proveniência com incerteza e testes

### REA-009 — Localizar drivers reais e validar assinaturas

**Status:** todo · **Etapa:** Reconstrução

- [ ] Separar referências textuais de drivers efetivamente encontrados
- [ ] Registrar SHA-256, arquitetura e verificação de assinatura de cada artefato

### REA-010 — Validar Windows 7 SP1 x86 em VM isolada

**Status:** blocked · **Etapa:** Laboratório

- [ ] Documentar VM, patches, driver, instalação, boot, remoção e falhas
- [ ] Anexar resultados verificáveis e snapshots da arquitetura x86

### REA-011 — Validar Windows 7 SP1 x64 em VM isolada

**Status:** blocked · **Etapa:** Laboratório

- [ ] Documentar VM, patches, driver, instalação, boot, remoção e falhas
- [ ] Anexar resultados verificáveis e snapshots da arquitetura x64

### REA-012 — Construir contratos e testes de equivalência observável

**Status:** todo · **Etapa:** Semântica

- [ ] Descrever entradas, saídas, buffers e efeitos por rotina sem inventar lacunas
- [ ] Criar casos positivos, negativos e limites de confiança

### REA-013 — Certificar o escopo validado e registrar limites Windows 7

**Status:** todo · **Etapa:** Entrega

- [ ] Exigir evidências independentes x86 e x64
- [ ] Publicar aprovação/reprovação ou não verificado por contrato, com rastreabilidade

## Engenharia de loop: protocolo de conclusão

1. **Descoberta:** escolher a próxima tarefa pronta e identificar lacunas.
2. **Reconstrução:** produzir evidências com hash, RVA, condições e incertezas.
3. **Teste:** escrever fixtures sintéticas, executar CI Python 3.8/3.12.
4. **Revisão:** abrir PR, registrar resultados e revisar critérios.
5. **Checkpoint:** atualizar tasks.json e regenerar este documento.
6. **Nova iteração:** selecionar a próxima tarefa pronta; não fechar bloqueios sem teste.

**Importante:** estes controles validam evidências documentais e testes de código próprio, não equivalência semântica, assinaturas ou Windows 7.
