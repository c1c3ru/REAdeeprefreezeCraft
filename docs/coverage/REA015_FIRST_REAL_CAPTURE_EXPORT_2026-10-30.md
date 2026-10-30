# REA-015/T — Primeira captura real, importação privada e evidência diferencial

**30/10/2026 — ciclo de preparação técnica, NÃO captura comprovada.**

A REA-015 permanece aberta e com **9/17 entregas** concluídas. Ainda não existe captura autenticada Windows 7 SP1 x86/x64 neste repositório; não declarar sucesso na execução do original, correspondência com `CLOUD_INSTALLER` ou equivalência sem registros reais.

## 1. Caminho crítico — aquisição na VM controlada

Usar duas VMs **isoladas e autorizadas** Win7 SP1, uma x86 e outra x64, com snapshots distintos, rede desconectada e dados/credenciais de laboratório. Salvar logs de depurador e dumps em diretório privado da VM e realizar análise offline fora de produção.

No WinDbg x86 (símbolos/carregamentos confirmados antes de operar), os comandos manuais abaixo são auxiliares de depuração, **não executam captura automatizada**:

```text
bu kernel32!CreateFileA
bu kernel32!ReadFile
bu kernel32!CloseHandle
g
```

- **CreateFileA na entrada (x86/stdcall):** inspecionar argumentos em `esp+4` (pathname), `esp+8` etc.; documentar PID/TID, pathname completo apenas no log privado e snapshot do arquivo de fato aberto. Com `gu`, verificar retorno `EAX` e confirmar sucesso e handle antes de registrar evento `open`.
- **ReadFile na entrada (x86/stdcall):** anotar `[esp+4]` (handle), `[esp+8]` (ponteiro `lpBuffer`), `[esp+0xc]` (pedido), `[esp+0x10]` (ponteiro da contagem retornada), `[esp+0x14]` (ponteiro `OVERLAPPED`). Conferir e registrar o offset absoluto pelo estado real do handle, não calculá-lo a partir de número de chamada. Prosseguir até o retorno via `gu`, conferir sucesso e contagem retornada; **somente então** gravar exatamente os bytes `lpBuffer[0:bytesRead]` em arquivo privado com `.writemem`. Para leitura assíncrona, aguardar a conclusão efetiva — retorno pendente não é leitura concluída.
- **XOR:** colocar breakpoint somente no ponto de transformação efetivamente demonstrado no fluxo original; congelar a mesma thread, preservar o buffer antes e depois, registrar o índice no bloco, flag, 4 DWORDs e origem observada da string/chave. Os bytes precisam existir no processo observado; não fabricar buffers com o modelo sintético.
- **x64:** usar convenção ABI x64, não interpretar `esp` como x86; `RCX`, `RDX`, `R8` e `R9` carregam os primeiros argumentos, com argumentos adicionais na pilha. Confirmar módulos e caminhos reais. O binário principal identificado é x86; execução em SO x64 pode passar por WoW64.
- **Aviso:** a presença de entradas API/caminhos ou a execução de `gu` não prova a identidade do arquivo. Preservar `.logopen` e arquivos externos de captura; Process Monitor não expõe o conteúdo completo dos buffers retornados.

Sintaxe WinDbg de referência: [bp/bu](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bp--bu--bm--set-breakpoint-), [gu](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/gu--go-up-) e [.writemem](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-writemem--write-memory-to-file-). Verificar endereços/parâmetros antes do ensaio. Não deixar a VM conectada à rede externa e não anexar dumps ao Git.

## 2. Novo importador offline REA-015/T

`tools/rea_private_capture_export.py` converte um índice de arquivos brutos em documentos reconhecidos pelos validadores N e R. **Não coleta nem instrumenta** Windows. Exige arquivos pré-existentes e externos contendo: (a) snapshot íntegro do arquivo realmente aberto; (b) dump dos bytes retornados pelo `ReadFile`; (c) opcionalmente buffers pequenos, pré/pós-XOR da mesma leitura. O importador calcula SHA-256 dos arquivos, verifica os tamanhos e confere que os bytes pré-XOR são exatamente o segmento selecionado do dump de `ReadFile`, antes de emitir os JSONs.

Todos os caminhos são relativos a um diretório privado; rejeita travessia `..`, symlinks, arquivos ausentes, offsets fora da leitura, PIDs/handles incongruentes, chave/flags malformadas e duplicação de amostras. A saída contém um JSON com apenas hashes e metadados de I/O e outro **PRIVADO com os bytes pré/pós em hexadecimal** necessários ao validador R. Não são recibos de certificação.

### Exemplo de índice — estrutura somente, não é evidência

```json
{
  "schema": "rea-015-t-private-export-v1",
  "capture": {
    "capture_id": "SYNTHETIC-NOT-VM",
    "platform": "windows7-sp1-x86",
    "original_pe_sha256": "2d7c171d4037660843a7e02c055679c5a26904af84d48fc8c557a67023f55c8b",
    "method": "laboratory-debugger-export",
    "observed_at": "2026-10-30T16:00:00Z",
    "independently_signed": false
  },
  "events": [
    {"seq": 1, "kind": "open", "pid": 123, "handle": "0x30", "path_redacted": "FILE_1", "opened_file_snapshot": "opened.bin"},
    {"seq": 2, "kind": "read", "pid": 123, "handle": "0x30", "file_offset": 0, "bytes_returned": 96, "returned_buffer_dump": "read-2.bin"},
    {"seq": 3, "kind": "close", "pid": 123, "handle": "0x30"}
  ],
  "pairs": []
}
```

O índice só funciona se os arquivos `opened.bin` e `read-2.bin` de 96 bytes existirem **sob diretório privado**. No exemplo, captura, PID e handle são fictícios. Nenhuma identidade é inferida a partir dos valores mostrados.

### Processar os dados recolhidos

```bash
python -m tools.rea_private_capture_export \
  --private-root /privado/win7-x86 \
  --manifest /privado/win7-x86/raw_index.json \
  --trace-json /privado/win7-x86/trace.json \
  --pairs-json /privado/win7-x86/pairs.PRIVADO.json

python -m tools.rea_runtime_file_correlation \
  --archive /privado/userfreezer.zip \
  --trace /privado/win7-x86/trace.json \
  --json /privado/win7-x86/correlacao.json

python -m tools.rea_xor_differential \
  --archive /privado/userfreezer.zip \
  --trace /privado/win7-x86/trace.json \
  --pairs /privado/win7-x86/pairs.PRIVADO.json \
  --json /privado/win7-x86/diferencial.json
```

A última etapa **exige pares não vazios**; se houver apenas I/O, usar somente o correlator. Arquivos de saída não são sobrescritos por segurança. As permissões de criação são restritas quando suportadas pelo sistema. **Não publicar** `pairs.PRIVADO.json` nem os dumps em repositórios públicos.

## 3. Encadeamento para os próximos ciclos

A primeira entrega comprovável será o arquivo realmente aberto com `SHA256` correspondente à referência, acompanhado do log do depurador com PID/handle/offset e dump do buffer. Só com esse conjunto podem ser executadas as checagens de origem de arquivo e comparação de bytes. A seguinte precisa demonstrar a seleção efetiva da chave, o teste `[owner+0x60] & 1` e saída pré/pós-XOR. Somente **após** uma saída reconstruída e comprovadamente íntegra deve haver classificação de possíveis módulos ocultos e reimplementação independente para validação diferencial Win7 x86/x64.

A ausência de observação autêntica mantém: `CLOUD_INSTALLER` não associado em execução, corpo opaco de 7.836.705 bytes não classificado, UPX não recuperado, drivers desconhecidos, 0/8 recibos e REA-015 aberta.

CI testa unicamente fixtures sintéticas com Python 3.8/3.12; nenhum runner executa Win7, driver ou produto proprietário.
