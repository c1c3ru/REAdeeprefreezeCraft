# Roadmap REA — descoberta, reconstrução e validação

## Entregas desta mudança

- [x] Preservar relatório estático inicial e hashes de referência.
- [x] Disponibilizar inventário estático reexecutável e testes com dados sintéticos.
- [x] Definir matriz de laboratório com Windows 7 SP1 x86/x64.

## Fases futuras

1. **Inventário recursivo:** localizar PEs embutidos e drivers extraídos, obter metadados e assinaturas sem executar artefatos.
2. **Análise estrutural:** mapear serviços, importações, funções, referências e grafos de chamada, com evidências por offset/arquivo.
3. **Reconstrução semântica:** documentar parâmetros, retornos, estados, efeitos de memória e interação usuário/kernel, sem inferir mais que as evidências permitam.
4. **Implementação própria:** somente comportamentos compreendidos, com interfaces separadas por versões do Windows, sem copiar binários proprietários.
5. **Validação:** comparação de comportamentos observáveis em VMs Windows 7 x86/x64, com relatórios de cobertura e limites de confiança.
6. **CI:** testes do código próprio, revisão de dependências e rastreabilidade de artefatos; CI em Linux **não substitui** testes do driver no Windows 7.

## Política de evidências

Todo achado deverá incluir: ID, arquivo/hash, ferramenta/versão, observação, interpretação, nível de confiança, limitação e próximo teste. Guardar somente dados com permissão de redistribuição.
