# REA-015/N — Contrato de observação Win7 e correlator offline de leituras

**Data:** 29/10/2026 · [Issue REA-015 #17](https://github.com/c1c3ru/REAdeeprefreezeCraft/issues/17) · **Estado:** instrumento de validação criado; **nenhuma captura real disponível**.

## Por que este checkpoint é necessário

A análise REA-015/M rastreou a origem *estática* do ponteiro usado por \`CreateFileA\` e encontrou a rotina \`ReadFile\`, mas não comprovou a identidade do arquivo aberto durante a instalação. Este ciclo disponibiliza um verificador para uma observação controlada em **VM Windows 7 SP1 x86/x64**, mantendo separados:

1. **Hash do arquivo efetivamente aberto:** serve para comparar com o SHA-256 do PE embutido \`BINARY/CLOUD_INSTALLER/4105\` ou com o próprio overlay; não revela como o arquivo chegou ao disco.
2. **Evento de abertura:** PID, handle e caminho redigido, vinculados a \`CreateFileA\` com sucesso.
3. **Eventos de leitura do mesmo handle:** offsets *absolutos no arquivo aberto*, número real de bytes retornados e SHA-256 do buffer **logo após ReadFile**, antes de qualquer XOR/cópia posterior.
4. **Correspondência por intervalo:** o verificador extrai **somente em memória** o PE e o overlay da amostra original e confronta o digest de cada intervalo do evento com os bytes originais.
5. **Autenticidade:** um arquivo JSON escrito pelo observador não é uma prova criptográfica de execução. É preciso preservar evidências da VM e obter revisão/assinatura externa, em uma etapa distinta.

O projeto já fixou os seguintes identificadores: SHA-256 do recurso \`145c6b8461132fd077a42cee775aca318c2b697b5720283749e04fc6aa5b4772\`, SHA-256 do overlay \`9453669c5ae280cb8718761159895da425168ccbba1e4e56d376b5165554b9e2\` e início do overlay no recurso em offset \`0x1E4800\` (1.984.512 bytes). A hipótese de cabeçalho tem **96 bytes**, corpo de **7.836.705** e trailer de **8**, totalizando **7.836.809 bytes**.

## Observação que ainda precisa ser realizada

Em **VM isolada e autorizada**, registrar de modo sincronizado e com origem auditável:

- Hash do executável original carregado, versão do Windows e arquitetura, identificador da VM/snapshot, horário e método.
- A abertura \`CreateFileA\`, com **PID, handle retornado e caminho original preservado somente fora do Git**; publicar apenas etiqueta \`path_redacted\` e hash do arquivo aberto.
- Cada leitura \`ReadFile\` correlacionada pelo mesmo **PID e handle**, offset de leitura no momento do evento, número de bytes retornados e SHA-256 do buffer de saída, tomado *antes* de a rotina de transformação modificar o buffer.
- Encerramento com \`CloseHandle\`, quando observado.
- Logs brutos da VM preservados em armazenamento apropriado, sanitizados, com hashes e revisão independente antes de compor qualquer recibo de certificação.

**Limite de ferramentas:** um CSV simples do Process Monitor pode ajudar a identificar pathname e offsets, mas não comprova por si só o valor do handle nem o conteúdo exato do buffer de \`ReadFile\`. Para a verificação byte a byte será necessária instrumentação autorizada que observe a saída da chamada; não inventar essas informações a partir de um CSV. Evitar executar instaladores comerciais fora de uma VM de teste e não anexar dumps ou dados de terceiros ao repositório.

## Formato local do manifesto

Exemplo **ilustrativo, incompleto e não utilizável como observação real**, mostrando apenas os campos (não commitá-lo como captura):


{
  "schema": "rea-015-file-io-observation-v1",
  "capture": {
    "platform": "windows7-sp1-x86",
    "original_pe_sha256": "2d7c171d4037660843a7e02c055679c5a26904af84d48fc8c557a67023f55c8b",
    "capture_id": "VM-EXAMPLE-NOT-OBSERVED",
    "method": "illustrative_only",
    "observed_at": "2026-10-29T16:00:00Z",
    "independently_signed": false
  },
  "events": [
    {
      "seq": 1,
      "kind": "open",
      "api": "CreateFileA",
      "pid": 1234,
      "handle": "0x80",
      "result": "success",
      "path_redacted": "VM_PATH_LABEL_1",
      "file_sha256": "REPLACE_WITH_OBSERVED_FULL_SHA256",
      "file_size": 0
    },
    {
      "seq": 2,
      "kind": "read",
      "api": "ReadFile",
      "pid": 1234,
      "handle": "0x80",
      "result": "success",
      "file_offset": 0,
      "bytes_returned": 96,
      "buffer_sha256": "REPLACE_WITH_SHA256_OF_RETURNED_96_BYTES"
    }
  ]
}


Campos como \`file_sha256\`, \`file_size\` e \`buffer_sha256\` **precisam de valores reais** para passar no verificador. A etiqueta de pathname deve ser sanitizada antes de compartilhar relatórios. O validador rejeita evento órfão, leitura sem abertura prévia, handle com PID diferente, comprimento impossível, offset fora do arquivo, ordem temporal inválida e declaração unilateral de assinatura.

Se o arquivo aberto for o PE embutido completo, a leitura do cabeçalho do overlay começará em **offset 1.984.512** nesse arquivo. Se o arquivo aberto for uma cópia do overlay isolado, começará em **offset 0**. O programa compara ambas as hipóteses **somente quando o hash do arquivo inteiro corresponde à referência**; não escolhe a hipótese a partir de marcadores parciais.

## Utilização

\`\`\`bash
python -m tools.rea_runtime_file_correlation \
  --archive /caminho/para/userfreezer.zip \
  --trace /caminho/privado/observacao_win7_sanitizada.json \
  --json /caminho/privado/rea015_comparacao.json

python -m unittest discover -s tests -v
python -m tools.rea_progress --check
python -m tools.rea_coverage --check
python -m tools.rea_certification --check
\`\`\`

A saída contém apenas metadados: quantidade de leituras, correspondências dos hashes, regiões (cabeçalho/corpo/trailer) e **cobertura única de intervalos de corpo**. Leituras repetidas ou sobrepostas não elevam o total de bytes distintos; um resultado positivo permanece marcado como \`LOCAL_HASH_CONSISTENCY_ONLY_NOT_RUNTIME_PROOF\`.

### Situação deste ciclo

- Ferramenta offline de correlação: **implementada**; suíte sintética **18 casos**.
- Captura Windows 7 SP1 x86: **não realizada**.
- Captura Windows 7 SP1 x64: **não realizada**.
- ReadFile/handle do original confirmado dinamicamente: **não**.
- Decodificação comprovada dos 7.836.705 bytes: **não**.
- Issue REA-015: **aberta**. Certificação: **NÃO CERTIFICADA**, 0/8 recibos.

## Próxima evidência necessária

Obter uma captura real de VM para um arquivo com hash correspondente à referência, correlacionar PID/handle/offset e comparar leituras do cabeçalho, corpo e trailer, documentando divergências. Só então tentar demonstrar que o recurso embutido foi extraído/aberto pelo fluxo observado, com cadeia de custódia da evidência. O algoritmo XOR e a proveniência de chave/clock são **análises semânticas separadas** e não devem ser confundidos com a origem do arquivo.
