# REA-015/Q — Encadeamento de buffers, evidência não autenticada

O validador offline `tools/rea_runtime_buffer_lineage.py` verifica coerência
de um manifesto local de eventos `open`, `read`, `transform` e `close`.
A associação usa PID, handle, identificador único da leitura, comprimento,
endereço virtual e SHA-256 do buffer antes/depois.

Uso:

```bash
python -m tools.rea_runtime_buffer_lineage \
  --trace /privado/lineage_win7.json \
  --json /privado/lineage_relatorio.json
python -m unittest tests.test_rea_runtime_buffer_lineage -v
```

Amostra **sintética e não observada** (todos os valores inventados):

```json
{
 "schema":"rea-015-buffer-lineage-v1",
 "events":[
  {"seq":1,"pid":42,"kind":"open","handle":"0x40"},
  {"seq":2,"pid":42,"kind":"read","handle":"0x40","read_id":"r1",
   "buffer_pointer":"0x1000","length":4,
   "buffer_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
  {"seq":3,"pid":42,"kind":"transform","read_id":"r1",
   "input_pointer":"0x1000","length":4,
   "before_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
   "after_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
  {"seq":4,"pid":42,"kind":"close","handle":"0x40"}
 ]
}
```

**Limites críticos:** coincidência de ponteiro, comprimento e SHA-256 é somente
consistência de dados auto-relatados. Não prova que o buffer permaneceu intacto
entre as chamadas, exclui substituição de conteúdo por escrita concorrente,
demonstra transferência por cópia ou certifica que o binário original executou.
Hash igual sem endereço igual não prova cópia. Eventos também devem ser
vinculados a um arquivo real por SHA-256 independente e evidência de VM auditável.

## Captura real Win7 SP1 — procedimento de aceite

1. VM isolada, snapshot identificado, Windows/arquitetura e hash do executável.
2. Instrumentação autorizada do processo para registrar PID, thread, tempo
   monotônico, handle e abertura real; guardar pathname bruto fora do Git.
3. Ao retorno bem-sucedido de `ReadFile`, registrar número efetivo de bytes,
   offset efetivo no arquivo, endereço do buffer e SHA-256 do conteúdo.
4. Antes e depois da rotina candidata de transformação, registrar endereço,
   comprimento, SHA-256 e ligação de ordem/identidade com a leitura.
5. Preservar logs originais privados, seus hashes e revisão independente.
6. Rodar correlator N, planejador O, perfil diferencial P e validador Q.
7. Só elevar o estado semântico com revisão da cadeia de custódia e evidência
   do código realmente executado, considerando interferência entre eventos.

**Estado:** nenhuma captura Win7 original obtida neste ciclo, 0/8 recibos,
REA-015 aberta. Sem alegação de XOR validado em todo o corpo.
