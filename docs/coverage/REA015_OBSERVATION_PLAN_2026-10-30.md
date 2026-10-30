# REA-015/Q — Planejamento de observações e contratos (30/10/2026)

**Estado:** REA-015 aberta, 9/17 marcos concluídos, 0/8 recibos, zero capturas Win7.

## Ferramenta offline

`tools/rea_observation_planner.py` recebe **apenas** o relatório JSON sanitizado produzido pelo correlator REA-015/P; não executa o instalador, não lê bytes binários do produto, não cria leituras do processo e não certifica resultados.

```bash
python -m tools.rea_runtime_file_correlation --archive /privado/userfreezer.zip \
  --trace /privado/observacao_win7_sanitizada.json --json /privado/correlacao.json
python -m tools.rea_observation_planner --correlation /privado/correlacao.json \
  --max-targets 12 --window-bytes 65536 --json /privado/plano.json
```

Para evitar prioridades baseadas em relatórios malformados, a ferramenta exige referência aos hashes fixados, exige estado *não certificado*, verifica aritmética de cobertura, rejeita intervalos incorretos, sobrepostos ou não ordenados e limita o tamanho das janelas. O plano sugere alvos de contexto para cabeçalho e trailer e janelas em lacunas no corpo, com início, centro e fim como primeira prioridade. Os offsets são declarados tanto no referencial do PE embutido quanto no overlay isolado. Esses alvos permitem **filtrar e orientar observações voluntárias em laboratório**, mas não fazem o instalador ler esses intervalos e não provam que qualquer leitura tenha ocorrido.

## Matriz de classificação

| Componente | Estado sustentado | Bloqueio |
|---|---|---|
| Recurso `CLOUD_INSTALLER` | PE embutido identificado por hash estático | Correspondência dinâmica com caminho e handle não demonstrada |
| Overlay 7.836.809 bytes | Intervalo e hash estáticos conhecidos | Identidade em execução não demonstrada |
| Cabeçalho 96 bytes / trailer 8 bytes | Delimitação provisória | Interpretação real ainda não comprovada |
| Corpo 7.836.705 bytes | **Opaco e não classificado** | Algoritmo, conteúdo decodificado e módulos internos desconhecidos |
| Dois módulos com marcadores UPX | Superfície comprimida identificada | Código descompactado e CFG não recuperados |
| Drivers | Apenas referências nominais | `.sys` e assinaturas não recuperados |

## Contratos semânticos priorizados

1. **FILE:** origem do pathname, `CreateFileA`, PID, handle e hash completo do arquivo, com evidência externa autenticável.
2. **READ:** `ReadFile`, offset absoluto, bytes retornados e hash do buffer *antes* de transformação.
3. **TRANSFORM:** condição `[owner+0x60] & 1`, proveniência da chave (inclusive origem temporal) e pares de buffers pré/pós-XOR; sem presumir o ramo executado.
4. **FORMAT:** estrutura do corpo após decodificação observada, módulos recuperados e hashes de seus bytes, sem publicar binários proprietários.
5. **EQUIVALENCE:** vetores originais, reimplementação independente e validação em Win7 SP1 x86/x64, com drivers verificados.

Os contratos são **requisitos de evidência**, não contratos já certificados. A classificação do corpo não pode ser encerrada com testes sintéticos ou somente hashes de leitura. A REA-015 fica aberta e a contagem de entregas permanece 9/17.

## Validação e custo

CI: testes Python 3.8 e 3.12, `rea_progress --check`, `rea_coverage --check`, `rea_certification --check`. A ferramenta roda offline e sem emulador. Coletar observações reais somente em VM isolada e autorizada, preservar brutos e cadeia de custódia fora do Git, e diferenciar consistência de hashes de equivalência comportamental. Nenhum resultado produzido por este planejador constitui um recibo de certificação.
