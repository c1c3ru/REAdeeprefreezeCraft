# REA-015/S — Auditoria de prontidão (não certificadora)

O verificador `tools/rea_capture_readiness.py` examina exclusivamente metadados
produzidos pelos correlatores N/O/P/Q. Seu objetivo é detectar omissões
e inconsistências locais e **não** provar execução em Windows 7.

```bash
python -m tools.rea_capture_readiness \
  --correlation /privado/correlacao.json \
  --probes /privado/sondagens.json \
  --differences /privado/diferencas.json \
  --lineage /privado/lineage_resultado.json \
  --json /privado/prontidao.json

python -m unittest tests.test_rea_capture_readiness -v
```

Dois estados possíveis: `INCOMPLETE` ou
`CONSISTENT_REPORT_SET_UNAUTHENTICATED`. Nenhum é certificação.
A ferramenta identifica ausência de hash de arquivo conhecido,
leituras sem correspondência, inexistência de pares de buffers,
falta de encadeamento direto e divergência do identificador de captura
entre correlator e planejador.

**Duas limitações estruturais importantes:** o schema P não atrela pares
a IDs de transformações do Q, e o Q não atrela as leituras ao ID de
captura nem aos eventos individuais do N. Portanto, mesmo quatro relatórios
consistentes NÃO demonstram que pertencem à mesma execução. A próxima
evolução deve estabelecer identificadores estáveis e evidência externa da VM.

Nenhuma captura real nova; certificação 0/8; REA-015 ainda aberta.
