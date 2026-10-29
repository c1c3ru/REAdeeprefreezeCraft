# REA-015/P — Perfil diferencial offline de buffers (proposta)

A ferramenta `tools/rea_runtime_buffer_diff.py` compara amostras de bytes antes
e depois de uma transformação presumida. É deliberadamente **offline**, sem
instrumentar o instalador e sem exportar amostras para o Git.

## Condição de uso

Obter pares de bytes por observação autorizada em VM isolada, associando
externamente cada amostra ao mesmo PID, handle, offset, sequência e ponteiros
de leitura/transformação. **Apenas os SHA-256 produzidos pelo correlator
REA-015/N não permitem inferir XOR nem recuperar os bytes.**

O formato abaixo usa dados **inventados**:

```json
{
  "schema": "rea-015-local-buffer-pairs-v1",
  "pairs": [
    {
      "offset": 0,
      "before_hex": "00112233",
      "after_hex": "aabb8899"
    }
  ]
}
```

Execute localmente:

```bash
python -m tools.rea_runtime_buffer_diff --pairs /privado/pares.json \
  --json /privado/perfil.json
python -m unittest tests.test_rea_runtime_buffer_diff -v
```

A ferramenta limita a 128 pares e 4096 bytes por par, valida comprimentos e
detecta apenas compatibilidade com máscara XOR constante por par.
Isso **não demonstra que o código usa XOR**: também são possíveis outras
transformações com os mesmos resultados para as amostras. O relatório
publica hashes e estatísticas; nunca publica os bytes brutos ou uma máscara.

## Evidências ainda ausentes

- Captura de Win7 real, com origem auditável e cadeia de custódia.
- Vinculação da chamada `CreateFileA` ao arquivo completo por SHA-256.
- Prova de que o buffer pós-`ReadFile` é o mesmo consumido pela transformação.
- Teste diferencial com dados representativos e fluxos de erro.
- Demonstração de transformação do corpo completo e recibos independentes.

Sem mudanças na cobertura certificada, no progresso 9/17 ou nos 0/8 recibos.
