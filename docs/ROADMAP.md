# Roadmap REA — descoberta, reconstrução e validação

## Entregas desta mudança

- [x] Preservar relatório estático inicial e hashes de referência.
- [x] Disponibilizar inventário estático reexecutável e testes com dados sintéticos.
- [x] Definir matriz de laboratório com Windows 7 SP1 x86/x64.

## Etapa 2 — entregas

- [x] Varredura estática de importações e recursos PE, com testes sintéticos.
- [x] Identificar dois executáveis PE embutidos no instalador principal.
- [x] Catalogar evidências de serviços e interfaces Win32/dispositivo, separando hipóteses.
- [x] Automatizar exportação JSON/Markdown; CI validará o código sem binários de terceiros.
- [ ] Identificar binários de driver completos e respectivas assinaturas.
- [x] Identificar call sites **candidatos** para DeviceIoControl/SCM e literais x86.
- [ ] Validar fronteiras de instruções, callers, parâmetros dinâmicos e contratos DeviceIoControl.
- [ ] Verificar instalação, reboot e Frozen/Thawed em Windows 7 SP1 x86/x64.

## Etapa 3 — loop REA (2026-10-28)

- [x] Implementar loop estático reexecutável com checkpoints de etapas no JSON.
- [x] Identificar no DFStd.exe 9 imports selecionados, 9 thunks e 51 candidatos E8.
- [x] Documentar 13 call sites DeviceIoControl e 10 literais distintos candidatos.
- [x] Adicionar fixtures sintéticas ao CI Python 3.8/3.12.
- [ ] Desmontar e validar as fronteiras de instrução dos candidatos completos.
- [ ] Derivar parâmetros reais (não somente literais) e vincular chamadas a handles.
- [ ] Localizar drivers reais e construir contratos semânticos testáveis em VMs.

## Etapa 4 — desmontagem localizada e rastreamento conservador

- [x] Verificar por `objdump` as 51 chamadas candidatas nas três janelas de desmontagem (resultado local).
- [x] Automatizar a decodificação de chamadas x86 e extração de saltos locais (CFG parcial).
- [x] Acrescentar rastreamento local de empilhamentos/registradores e checkpoint JSON/Markdown.
- [x] Investigar o parâmetro dinâmico de `DeviceIoControl` em RVA `0x038C08`: origem imediata `[EBP+0x08]`.
- [ ] Obter CFG global validado a partir de entradas de funções e referências de salto.
- [ ] Confirmar origem e tipos reais de handles, valores IOCTL em runtime e contratos de buffers.
- [ ] Inventariar drivers instalados e suas assinaturas em Windows 7 SP1 x86/x64.

## Etapa 5 — CFG delimitado e contratos estruturais (2026-10-28)

- [x] Automatizar CFG por janela de função com limites conhecidos, análise de alcançabilidade, blocos básicos, dominadores e desvios retroativos.
- [x] Registrar dois candidatos de função contíguos em DFStd.exe, com proveniência e hashes.
- [x] Gerar contratos JSON preliminares (entradas observadas, chamadas, retornos e lacunas).
- [x] Adicionar testes sintéticos (compatibilidade Python 3.8+; GNU objdump para fixtures PE).
- [ ] Reconhecer entradas/saídas de funções automaticamente com evidências suficientes.
- [ ] Validar caminhos com saltos indiretos, chamadas dinâmicas e exceções.
- [ ] Rastrear nomes de objetos, buffers e resultados sem deduzir valores não observados.
- [ ] Verificar drivers e semântica em VMs isoladas Windows 7 SP1 x86/x64.

## Etapa 6 — contrato interprocedural estático (2026-10-28)

- [x] Ler tabela de oito dwords de `0x0094AF54` com limites de mapeamento PE.
- [x] Correlacionar cópia local, laço de oito itens, argumento do auxiliar e a posição do código em `DeviceIoControl`.
- [x] Resolver pela IAT as chamadas a `GetSystemDirectoryA`, `CreateFileA`, `DeviceIoControl` e `CloseHandle`.
- [x] Documentar caminhos candidatos de volume e checagens de handle/retorno, sem inferir resultados.
- [x] Exigir SHA-256 específico para prevenir extrapolação a outras versões.
- [x] Incluir testes com PE sintético no CI e checkpoint de evidência.
- [ ] Validar todos os caminhos e suas condições de parada sem execução de drivers.
- [ ] Identificar o significado de cada código de controle com evidência independente/autorizada.
- [ ] Executar teste de compatibilidade isolado Windows 7 SP1 x86/x64.

## Governança dos ciclos — plano executável

O backlog ativo, critérios de aceite e dependências passaram a ser mantidos em [tasks.json](progress/tasks.json), com quadro reprodutível [STATUS_ATUAL.md](STATUS_ATUAL.md) e [plano de ação](PLANO_DE_ACAO.md).

- [x] Definir portões técnicos G0–G6, prioridades P0/P1 e critérios para declarar entregas.
- [x] Criar issues REA-007 a REA-013.
- [x] Adicionar validador de status/evidências e testes sintéticos ao CI.
- [x] REA-007: saídas, nove desvios condicionais e dois laços das duas janelas candidatas; ver [análise](analyses/REA_007_BRANCH_EXITS.md).
- [x] REA-008: proveniência estática de handles/buffers/retornos nas duas funções, [relatório](analyses/REA008_ARGUMENT_PROVENANCE.md).
- [ ] REA-009: **bloqueada por ausência dos `.sys` reais e assinaturas verificadas**; auditoria dos três PEs e do overlay em [checkpoint](coverage/REA009_DRIVER_PROVENANCE.md).
- [ ] REA-010/011/012/013: laboratório Windows 7 e certificação contratual.

## Expansão para 100% de cobertura verificável

- [x] REA-014 — manifesto e medidor conservador: [STATUS de cobertura](coverage/STATUS.md).
- [ ] REA-015 — **em execução:** 23 entradas ZIP, 190 folhas de recursos nos 3 PEs, dois PEs UPX com pontos de entrada em UPX1 e 2.095.104 bytes compactados medidos, mas ainda não descompactados; SIB identificado como dados TsiLang (registros ainda não decodificados); overlay com enquadramento consistente (corpo ainda desconhecido), com 21 âncoras de leitor estático; corpo/driver/UPX não recuperados, handle e XOR condicional rastreados; flag e aritmética do byte XOR rastreadas estaticamente; inventário ainda não fechado ([checkpoint](coverage/REA015_RECURSIVE_DISCOVERY.md), [issue #17](https://github.com/c1c3ru/REAdeeprefreezeCraft/issues/17)).
- [ ] REA-016 — regiões executáveis completas, funções, CFG, exceções e chamadas indiretas ([issue #18](https://github.com/c1c3ru/REAdeeprefreezeCraft/issues/18)).
- [ ] REA-017 — semântica, contratos e equivalência com testes Windows 7 x86/x64 ([issue #19](https://github.com/c1c3ru/REAdeeprefreezeCraft/issues/19)).
- [ ] Manter desconhecidos como desconhecidos até a evidência; 100% de dois trechos não é 100% do produto.

## Fases futuras

1. **Inventário recursivo:** localizar PEs embutidos e drivers extraídos, obter metadados e assinaturas sem executar artefatos.
2. **Análise estrutural:** mapear serviços, importações, funções, referências e grafos de chamada, com evidências por offset/arquivo.
3. **Reconstrução semântica:** documentar parâmetros, retornos, estados, efeitos de memória e interação usuário/kernel, sem inferir mais que as evidências permitam.
4. **Implementação própria:** somente comportamentos compreendidos, com interfaces separadas por versões do Windows, sem copiar binários proprietários.
5. **Validação:** comparação de comportamentos observáveis em VMs Windows 7 x86/x64, com relatórios de cobertura e limites de confiança.
6. **CI:** testes do código próprio, revisão de dependências e rastreabilidade de artefatos; CI em Linux **não substitui** testes do driver no Windows 7.

## Política de evidências

Todo achado deverá incluir: ID, arquivo/hash, ferramenta/versão, observação, interpretação, nível de confiança, limitação e próximo teste. Guardar somente dados com permissão de redistribuição.
