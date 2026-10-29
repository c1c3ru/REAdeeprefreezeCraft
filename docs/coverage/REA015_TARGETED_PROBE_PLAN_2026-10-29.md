# REA-015/O — Plano orientado de sondagens, sem alegação de captura

**Estado:** proposta de instrumentação offline, sem evidência nova de execução Win7.

## Motivação

O correlator REA-015/N fornece os checks de leituras observadas. O planejador
`tools/rea_runtime_probe_plan.py` usa esse JSON para sugerir regiões de interesse
e evitar repetir intervalos do corpo já correlacionados.

As duas hipóteses são **candidatas independentes**:
1. arquivo aberto = recurso PE completo (offset do overlay somado);
2. arquivo aberto = overlay isolado (offset relativo a zero).

Nunca converter sugestão em observação: apenas o fluxo real do programa
determina quais offsets serão lidos. Caso nenhuma hipótese corresponda ao arquivo
real, todas as sugestões serão apenas orientações de investigação.

## Uso

```bash
python -m tools.rea_runtime_file_correlation \
  --archive /privado/userfreezer.zip \
  --trace /privado/observacao_win7_sanitizada.json \
  --json /privado/correlacao.json

python -m tools.rea_runtime_probe_plan \
  --correlation /privado/correlacao.json \
  --window 4096 --limit 12 \
  --json /privado/plano-sondagens.json

python -m unittest tests.test_rea_runtime_probe_plan -v
python -m unittest discover -s tests -v
python -m tools.rea_progress --check
python -m tools.rea_coverage --check
python -m tools.rea_certification --check
```

O JSON gerado inclui exclusivamente offset absoluto no arquivo hipotético,
comprimento e motivo. O plano não captura bytes, não controla `ReadFile`,
não verifica a cadeia de custódia, não decodifica XOR e não cria recibos.
Os metadados de origem precisam ser validados independentemente.

## Estratégia de aceleração

- **Pista A (estática):** localizar callee de transformação, registrar pré/pós-condições e buffers.
- **Pista B (dinâmica):** coletar I/O da VM isolada e associar PID/handle, arquivo integral, offsets e hashes de buffers após `ReadFile`.
- **Pista C (diferenças):** quando houver observações genuínas, executar o correlator e gerar novo plano; registrar divergência por classe, sem presumir correspondência.
- **Pista D (equivalência):** usar vetores independentes para confrontar reimplementação e original, somente após obter contratos observados.

A captura está pendente; o checklist REA-015, a certificação (0/8)
e a contagem de 9/17 entregas não são modificados por este PR.
