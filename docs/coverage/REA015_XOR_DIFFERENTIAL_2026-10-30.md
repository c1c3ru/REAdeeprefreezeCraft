# REA-015/R — Correlação offline dos buffers antes/depois do XOR

**Data:** 2026-10-30 · **Estado:** validador de consistência preparado; nenhuma execução do instalador Windows 7 demonstrada. REA-015 permanece aberta, 9/17 entregas e **0/8 recibos**.

## Evidência estática atualmente disponível

A análise delimitada `tools/rea_transform_state.py` verifica âncoras de instruções x86 no executável original. A rotina de leitura consulta `[owner+0x60] & 1`; a escolha da chave ativa considera quatro DWORDs em `[owner+0xBC..0xC8]` (grupo secundário) e, se zerados, os de `[owner+0xAC..0xB8]` (alternativo). Existe cadeia estática relacionada a `GetLocalTime`, mas não sabemos a string concreta, seus quatro DWORDs no runtime ou se a leitura é a do overlay `CLOUD_INSTALLER`.

A fórmula candidata para cada byte foi reconstruída de instruções originais, mas **o modelo ainda só foi testado com bytes sintéticos**. Identificar operações locais não significa validar a transformação integral ou a reversão do formato proprietário.

## Novo verificador

`tools/rea_xor_differential.py` recebe uma captura de `CreateFileA/ReadFile` (formato REA-015/N), o ZIP original sob hash fixado e um manifesto **privado** de pequenos pares de amostras pré/pós-transformação. O arquivo de pares contém bytes em hexadecimal e **nunca deve ser commitado**; o JSON de saída só inclui tamanhos, offsets, hashes e flags de consistência.

```bash
python -m tools.rea_xor_differential \
  --archive /privado/userfreezer.zip \
  --trace /privado/observacao_win7_sanitizada.json \
  --pairs /privado/pares_pre_pos_privados.json \
  --json /privado/resultado_diferencial.json
```

**Formato do segundo manifesto (exemplo exclusivamente ilustrativo, NÃO real):**

```json
{
  "schema": "rea-015-xor-paired-observation-v1",
  "capture_id": "SYNTHETIC-NOT-VM",
  "samples": [{
    "sample_id": "sample-1",
    "read_seq": 3,
    "pid": 123,
    "handle": "0x30",
    "offset_in_read": 0,
    "byte_index_in_transform_block": 0,
    "pre_hex": "4142434445464748",
    "post_hex": "4142434445464748",
    "owner_flag_0x60": 0,
    "primary_words": [1, 2, 3, 4],
    "secondary_words": [0, 0, 0, 0],
    "active_words": [1, 2, 3, 4],
    "state_kind": 1,
    "branch_observed": false,
    "reported_key_source": "unknown"
  }]
}
```

O exemplo demonstra o caso de **transformação desabilitada**; o byte de saída é igual ao de entrada. As sequências `read_seq`, PID e handle devem corresponder ao `ReadFile` capturado no primeiro manifesto. O índice `byte_index_in_transform_block` é uma posição medida na rotina de transformação, **não** o offset absoluto do arquivo; ambos não devem ser confundidos. Uma leitura pode ser grande, mas cada par possui no máximo 4.096 bytes e deve estar totalmente dentro do corpo opaco e do intervalo efetivamente lido.

### Verificações e significado

1. **Origem local dos bytes de entrada:** hash da leitura completa comparado à referência fixada e amostra pré-transformação comparada aos bytes originais do mesmo intervalo. Isso apenas verifica consistência dos registros fornecidos.
2. **Chave ativa:** grupo secundário não nulo deve prevalecer; se os quatro DWORDs secundários forem zero, a seleção cai para o grupo primário. A ferramenta confronta os DWORDs ativos declarados com a regra estática.
3. **Flag e ramo:** aplica o modelo candidato para `owner_flag_0x60 & 1`, quatro DWORDs não nulos e `state_kind == 1` e compara com o ramo declarado.
4. **Resultado:** calcula o XOR esperado para o índice de bloco observado e compara bytes pós-transformação declarados. Relata hashes das duas saídas e não revela chaves ou payloads.
5. **Contabilização:** soma os bytes distintos do corpo em amostras *internamente consistentes*, com união de intervalos; não os contabiliza como bytes de execução comprovada.

**Limitação decisiva:** o manifesto é escrito pelo observador; não existe autenticação criptográfica da captura neste instrumento. Mesmo com todas as comparações positivas, `key_origin_verified`, `original_executable_run_verified`, `cloud_installer_transformation_proven`, `whole_body_decoded`, `output_format_classified` e `certification_receipt_created` continuam falsos.

A procedência da string/chave e de `GetLocalTime` não é provada pelo rótulo `reported_key_source`, mesmo quando a seleção matemática bate. A integridade e cadeia de custódia devem ser estabelecidas fora do JSON autodeclarado.

## Próximas provas necessárias

- Em VM Windows 7 SP1 x86 e x64 isolada/autorizada, registrar com observação independente `CreateFileA`, PID, handle, arquivo e hash original.
- Capturar `ReadFile` e buffer de saída antes de XOR; registrar os mesmos bytes antes/depois no ponto de transformação, a flag, os quatro DWORDs, a escolha da chave e o índice relativo ao bloco. Associar rigorosamente os eventos, preservando logs brutos em armazenamento privado.
- Demonstrar procedência do fallback temporal, incluindo o valor transformado por `GetLocalTime` e a string intermediária, sem adivinhar argumentos a partir de um horário de log.
- Verificar, com vetores originais rastreáveis, se a saída revela formato reconhecível e artefatos extraíveis, cada um por tamanho, limites e SHA-256. Enquanto isso, os 7.836.705 bytes permanecem opacos.
- Recuperar os módulos UPX e drivers legítimos e avançar na reimplementação independente/validação de equivalência (REA-009, REA-012, REA-016 e REA-017).

## Regressão e economia

Testes unitários sintéticos Python 3.8 e 3.12 cobrem caminho habilitado/inibido, subintervalos de `ReadFile`, seleção de chave, divergências de flag/bytes, adulterações, sobreposição e falsos positivos. Manter `rea_progress --check`, `rea_coverage --check` e `rea_certification --check`. Nenhum runner CI precisa executar instalador, driver ou VM.

## Triagem delimitada da estrutura de saída

O relatório identifica apenas **candidatos de cabeçalho** no início do bloco de saída declarado: MZ, PE parcial com assinatura e campos mínimos, ZIP (local header), gzip e 7z. A classificação é explicitamente provisória, não extrai arquivos nem trata bytes de amostra como módulos comprovados. Para posições fora do início do bloco, informa que a triagem não se aplica. `output_format_verified=false` e `output_format_classified=false` permanecem invariáveis mesmo com uma assinatura candidata. Os testes verificam os prefixos falsos e uma estrutura PE sintética mínima.
