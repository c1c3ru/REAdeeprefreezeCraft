# REAdeeprefreezeCraft

Laboratório de **engenharia reversa auditável** para análise de componentes de proteção e restauração de sistemas Windows. O projeto começa com a inspeção estática de um pacote do **Faronics Deep Freeze Standard 9.00.020.5760**.

> Este repositório **não** distribui binários ou código-fonte proprietário, não altera mecanismos de licenciamento e **não** disponibiliza uma implementação funcional do Deep Freeze. Os achados não equivalem a uma auditoria dinâmica nem à comprovação de compatibilidade com Windows 7.

## Primeira entrega

- [Relatório REA 9.00.020.5760](docs/analyses/DeepFreeze_9.00.020.5760.md) — identificação do binário, hashes, componentes, limitações e riscos.
- [Matriz de testes Windows 7](docs/WINDOWS7_LAB.md) — requisitos de laboratório e critérios de aceite.
- [Roadmap](docs/ROADMAP.md) — fases de inventário, análise estrutural e validação semântica.
- **[Cobertura integral de engenharia reversa](docs/coverage/STATUS.md)** e [manifesto de componentes](docs/coverage/scope.json): cobertura por byte de módulo medido, denominadores desconhecidos e gates de equivalência; sem percentual global inventado.
- `tools/rea_coverage.py`: validador/gerador da cobertura integral, integrado ao CI.
- `tools/rea_driver_evidence.py` — REA-009: identifica arquivos .sys **reais** versus strings, registra tabelas Authenticode e overlays não classificados sem validar criptograficamente a assinatura; [checkpoint](docs/coverage/REA009_DRIVER_PROVENANCE.md).
- `tools/rea_ioctl_contract.py` — REA-008: contrato estático das oito posições de `DeviceIoControl`, `CreateFileA`, buffers e status de retorno; [análise](docs/analyses/REA008_ARGUMENT_PROVENANCE.md).
- `tools/rea_transform_state.py` — REA-015/J: valida 74 instruções de flag, estado e byte XOR na amostra fixada por SHA-256, com simulações somente sintéticas; [relatório](docs/coverage/REA015_TRANSFORM_STATE_2026-10-29.md).
- `tools/rea_overlay_handle_flow.py` — REA-015/I: valida origem estática de handle (CreateFileA → contexto → ReadFile), leitura de buffer e caminho XOR condicional, com [checkpoint](docs/coverage/REA015_HANDLE_FLOW_2026-10-29.md).
- `tools/rea_overlay_reader_trace.py` — REA-015/H: confere 25 instruções x86 e um thunk para `KERNEL32.DLL!ReadFile` pinadas por SHA-256 e correlaciona leitura/validação do cabeçalho com os campos do overlay sem supor decoder; [evidência](docs/coverage/REA015_READER_TRACE_2026-10-29.md).
- `tools/rea_overlay_codec_probe.py` — REA-015/G: testa candidatos zlib/gzip com limites de entrada e saída, sem comprovar algoritmo ou cifragem.
- `tools/rea_overlay_inventory.py` — REA-015: valida offline o enquadramento do overlay (7,84 MB), hashes, marcadores e possíveis PEs sem executar/descompactar; [relatório](docs/coverage/REA015_OVERLAY_FRAME_2026-10-29.md).
- `tools/rea_upx_surface.py` — REA-015: valida entradas PE, hashes das seções UPX0/UPX1 e bytes compactados, sem supor código reconstruído; [relatório](docs/coverage/UPX_SURFACE_2026-10-28.md).
- `tools/rea_embedded_pe_candidates.py` — REA-015: verifica marcadores MZ em offsets não iniciais dos recursos e separa falsos positivos de candidatos PE válidos.
- `tools/rea_recursive_inventory.py` — REA-015: inventário recursivo de ZIP/PE/recursos com hashes, limites, marcadores UPX, classificação de recurso TsiLang por cabeçalho exato e separação de binários confirmados versus nomes de driver; [checkpoint](docs/coverage/REA015_RECURSIVE_DISCOVERY.md).
- **[Plano de ação, metas e portões](docs/PLANO_DE_ACAO.md)** e **[status atualizado/pendências](docs/STATUS_ATUAL.md)** — controle vivo de execução do REA.
- [Diagnóstico do CI e histórico de falhas resolvidas](docs/CI_DIAGNOSTICO.md) — como distinguir erros antigos, testes negativos esperados e workflows atuais.
- `tools/rea_progress.py` + [manifesto versionado](docs/progress/tasks.json) — verificação automática de evidências, dependências e estado no CI.
- `tools/rea_inventory.py` — inventário **sem extrair ou executar** entradas ZIP, SHA-256, cabeçalhos PE e referências de strings.
- `tests/` — testes automatizados com arquivos sintéticos; sem incluir executáveis comerciais.
- `tools/rea_structural.py` — importações PE, árvore de recursos, PE embutidos, strings de drivers e mapa de interfaces.
- [Evidências estruturais](docs/analyses/STRUCTURAL_2026-10-28.md) e [fronteiras usuário/kernel](docs/INTERFACES_USER_KERNEL.md).
- `tools/rea_loop.py`: loop estático automatizado **IAT → thunks → chamadas candidatas → literais de argumentos → ponto fixo**.
- [Descobertas do loop](docs/analyses/LOOP_DEVICEIO_2026-10-28.md) e [metodologia/limitações](docs/LOOP_METHODOLOGY.md).
- `tools/rea_cfg.py`: desmontagem offline com GNU objdump, confirmação localizada de chamadas, grafo de saltos locais e rastreamento simbólico conservador dos argumentos.
- [Evidências de desmontagem e CFG local](docs/analyses/CFG_LOCAL_2026-10-28.md).
- `tools/rea_function_cfg.py`: grafo de fluxo por função delimitada, alcançabilidade, blocos básicos, dominadores, desvios retroativos e dependências de parâmetros x86.
- [Etapa 5: duas funções e contratos estruturais](docs/analyses/FUNCTION_CFG_2026-10-28.md) e [contratos JSON](docs/contracts/cycle5_functions.json).
- `tools/rea_contract_trace.py` — ciclo 6: extrai uma tabela de oito dwords, valida importações via IAT, registra a cadeia entre chamador, auxiliar e DeviceIoControl e os caminhos de volume candidatos.
- [Relatório do ciclo 6](docs/analyses/CONTRACT_CHAIN_2026-10-28.md) e [checkpoint curado](docs/contracts/cycle6_findings.json).
- `tools/rea_path_coverage.py`: **REA-007** — enumeração limitada de desvios e saídas dos dois CFGs; separa retorno explícito, corte de laço e destino não resolvido.
- [Relatório REA-007](docs/analyses/REA_007_BRANCH_EXITS.md) e [evidência JSON](docs/contracts/rea007_exit_paths.json).

## Executar localmente

Requisito para inventário/loop: **Python 3.8+**, sem dependências Python de terceiros. Para `rea_cfg.py`, `rea_function_cfg.py` e `rea_contract_trace.py` é necessário **GNU binutils (objdump)**. O analisador pode rodar em Linux, sem execução do arquivo Windows.

```bash
python -m unittest discover -s tests -v
python -m tools.rea_progress --check
python -m tools.rea_progress --json
python -m tools.rea_coverage --check
python -m tools.rea_coverage --json
python -m tools.rea_transform_state --archive /caminho/para/userfreezer.zip --json rea015_transform_state.json
python -m tools.rea_overlay_handle_flow --archive /caminho/para/userfreezer.zip --json rea015_handle_flow.json
python -m tools.rea_overlay_reader_trace --archive /caminho/para/userfreezer.zip --json rea015_frame_reader.json
python -m tools.rea_overlay_inventory --archive /caminho/para/userfreezer.zip --json rea015_overlay.json
python -m tools.rea_driver_evidence --archive /caminho/para/userfreezer.zip --expect-sha256 f2e1a70e3becff235c886c6092d3d8a5928404bbe43f9c0c6360e428daa64671 --json rea009_driver_scan.json
python -m tools.rea_upx_surface --archive /caminho/para/userfreezer.zip \
  --json rea015_upx_surface.json
# Inventário recursivo da amostra original (sem executar nem escrever executáveis)
python -m tools.rea_recursive_inventory --archive /caminho/para/userfreezer.zip \
  --expect-sha256 f2e1a70e3becff235c886c6092d3d8a5928404bbe43f9c0c6360e428daa64671 \
  --json rea015_inventory.json --markdown rea015_inventory.md
python tools/rea_inventory.py /caminho/para/userfreezer.zip --output inventario.json
python -m tools.rea_structural --archive /caminho/para/userfreezer.zip --json estrutura.json --markdown interfaces.md
python -m tools.rea_loop --archive /caminho/para/userfreezer.zip --json rea_loop.json --markdown rea_loop.md
# Etapa 5: endereços virtuais do PE (VA), janela de função delimitada
python -m tools.rea_function_cfg --archive /caminho/para/userfreezer.zip \
  --entry 0x438b48 --stop 0x438c41 --json cfg_function_helper.json
# Etapa 6: SHA-256 obrigatório para evitar aplicar offsets a outra versão
python -m tools.rea_contract_trace --archive /caminho/para/userfreezer.zip \
  --json contract_cycle6.json
# Etapa 7: caminhos sintáticos, sem executar PE/driver
python -m tools.rea_path_coverage --archive /caminho/para/userfreezer.zip \
  --json rea007.json --markdown rea007.md
```

A análise `--archive` de CFG copia temporariamente apenas o membro PE selecionado para um diretório privado e apaga essa cópia ao concluir. Não faz commit nem instala o software. Os resultados JSON/Markdown são gerados apenas localmente; a documentacao versionada e curada manualmente. O arquivo `inventario.json` é gerado apenas localmente. **Não faça commit do ZIP, dos drivers originais, de chaves ou de dados pessoais.** O inventário rejeita arquivos grandes e caminhos suspeitos; o retorno `2` indica entradas ignoradas por segurança.

## Compatibilidade e escopo

A compatibilidade **Windows 7 SP1 x86/x64** é requisito do projeto; o analisador utiliza Python 3.8 para não exigir versões recentes do interpretador. O driver e qualquer futura implementação Windows precisam de testes independentes: executar o script não demonstra compatibilidade do produto comercial nem da proteção em modo kernel.

Toda hipótese precisa ser rotulada como **observada**, **inferida** ou **a validar**. Testes de sistema deverão ocorrer apenas em máquinas virtuais descartáveis com snapshots e backups.
