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

## Fases futuras

1. **Inventário recursivo:** localizar PEs embutidos e drivers extraídos, obter metadados e assinaturas sem executar artefatos.
2. **Análise estrutural:** mapear serviços, importações, funções, referências e grafos de chamada, com evidências por offset/arquivo.
3. **Reconstrução semântica:** documentar parâmetros, retornos, estados, efeitos de memória e interação usuário/kernel, sem inferir mais que as evidências permitam.
4. **Implementação própria:** somente comportamentos compreendidos, com interfaces separadas por versões do Windows, sem copiar binários proprietários.
5. **Validação:** comparação de comportamentos observáveis em VMs Windows 7 x86/x64, com relatórios de cobertura e limites de confiança.
6. **CI:** testes do código próprio, revisão de dependências e rastreabilidade de artefatos; CI em Linux **não substitui** testes do driver no Windows 7.

## Política de evidências

Todo achado deverá incluir: ID, arquivo/hash, ferramenta/versão, observação, interpretação, nível de confiança, limitação e próximo teste. Guardar somente dados com permissão de redistribuição.
