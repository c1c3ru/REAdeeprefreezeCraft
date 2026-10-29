# REA-015/H — Correlação estática entre cabeçalho do overlay e rotinas x86

**Data:** 29/10/2026 · **Issue:** [REA-015 #17](https://github.com/c1c3ru/REAdeeprefreezeCraft/issues/17) · **Status:** evidência parcial, sem fechamento de escopo.

## Avanço confirmado

A inspeção com GNU objdump do `DFStd.exe` (SHA-256 `2d7c171d4037660843a7e02c055679c5a26904af84d48fc8c557a67023f55c8b`) identificou **25 âncoras de instruções** no intervalo `0x0074FB45..0x00750613`, verificadas por endereço virtual e bytes reais do arquivo, exclusivamente na seção `.text`. Três âncoras manipulam explicitamente o DWORD `0x69ABCD69` que também aparece no cabeçalho e no final do overlay do CLOUD_INSTALLER (SHA-256 `9453669c5ae280cb8718761159895da425168ccbba1e4e56d376b5165554b9e2`).

### Leitura, validação e inicialização

| Função observada | VA | Instrução ou efeito verificável |
|---|---|---|
| Preparar destino de leitura | `0x0074FB45` | `lea edi,[ebx+0x10]` |
| Solicitar leitura de 96 bytes | `0x0074FB49` / `0x0074FB50` | `push 0x60; call 0x752670` |
| Validar o cabeçalho após a leitura | `0x0074FB59` | `call 0x75018C` |
| Comparar marcador do cabeçalho | `0x0075019E` | `cmp dword [ebx+0x1C],0x69ABCD69` |
| Inicializar cabeçalho (96) | `0x00750591` | `mov dword [ebx+0x10],0x60` |
| Inicializar campo 769 | `0x007505A5` | `mov dword [ebx+0x18],0x301` |
| Inicializar marcador | `0x007505AC` | `mov dword [ebx+0x1C],0x69ABCD69` |
| Inicializar comprimento duplicado | `0x00750607` | `mov dword [ebx+0x54],0x60` |
| Gravar dois campos sucessivos com mesmo registrador | `0x00750610` / `0x00750613` | `mov [ebx+0x58],eax; mov [ebx+0x5C],eax` |
| Preparar leitura de oito bytes no trecho final | `0x007502FD` / `0x00750300` / `0x00750307` | destino `[ebx+0x70]`, tamanho 8 e chamada `0x752670` |
| Comparar marcador após essa leitura | `0x00750317` | `cmp dword [ebx+0x70],0x69ABCD69` |

A base aparente do cabeçalho é **`EBX+0x10`**. Isso faz os campos `[ebx+0x18]`, `[ebx+0x1c]`, `[ebx+0x54]`, `[ebx+0x58]` e `[ebx+0x5c]` corresponderem aos deslocamentos **+0x08, +0x0C, +0x44, +0x48 e +0x4C**, exatamente onde foram observados, no overlay, o valor 769, o marcador `0x69ABCD69`, o comprimento repetido 96 e dois campos iguais a 8.928.

### Chegada à API Win32 ReadFile

A chamada de leitura no helper `0x00752670` usa `0x007526A9` (`push edi`, buffer), `0x007526AD` (`push ecx`, handle) e `0x007526AE` (`call 0x009010C2`). O thunk em `0x009010C2` contém `jmp dword [0x00A16998]`. A tabela de importações PE32 mapeia **`0x00A16998` para `KERNEL32.DLL!ReadFile`**. Esses quatro pontos também são verificados por bytes exatos no novo analisador.

Isso confirma que o helper faz uma chamada a **ReadFile**; não identifica qual arquivo ou recurso é aberto em execução, nem o transformador dos bytes após a leitura.

### O que essa evidência demonstra

A sequência `0x0074FB45 → 0x0074FB50 → 0x0074FB59 → 0x0075019E` fornece **um candidato estático forte a leitor e validador de cabeçalho de 96 bytes**. A sequência `0x00750591..0x00750613` inicializa uma estrutura com valores que coincidem com o cabeçalho; `0x00750307 → 0x00750317` verifica o mesmo marcador após uma solicitação de leitura de oito bytes.

**Limite essencial:** o binário principal contém essas rotinas e também o recurso CLOUD_INSTALLER, mas ainda **não foi demonstrada uma cadeia dinâmica ou uma referência de handle** que prove que essas funções consomem especificamente o overlay desse recurso. A correspondência indica provável uso de um formato comum. Não foi localizado o algoritmo responsável por transformar o corpo opaco de **7.836.705 bytes** e nenhum driver foi recuperado.

## Verificação automatizada e segurança

`tools/rea_overlay_reader_trace.py` verifica SHA-256 do ZIP, PE principal, CLOUD_INSTALLER e overlay; mapeia 25 endereços virtuais para offsets físicos pelo cabeçalho PE, compara os bytes de instruções e confirma sua presença na seção `.text`. Em seguida confronta campos e marcador final do overlay. O script **não executa o produto nem publica qualquer código binário proprietário**.

`tests/test_rea_overlay_reader_trace.py` exercita as validações com PEs e overlays sintéticos, corrupção de marcadores, offsets e comprimentos, erros de checksum e determinismo.

```bash
python -m tools.rea_overlay_reader_trace --archive /caminho/para/userfreezer.zip --json rea015_reader_local.json
python -m unittest discover -s tests -v
python -m tools.rea_progress --check
python -m tools.rea_coverage --check
```

## Próximos passos

1. Rastrear a origem do handle entregue às chamadas `0x752670` e a cadeia de chamadas que chega ao leitor do cabeçalho.
2. Identificar os argumentos e efeitos das rotinas que recebem as regiões seguintes do arquivo, distinguindo leitura, cópia e transformação.
3. Validar a relação direta com o recurso CLOUD_INSTALLER e produzir evidência positiva do processamento do corpo, sem presumir algoritmo.
4. Manter **REA-015 aberta** e as lacunas do inventário/UPX/drivers como desconhecidas; nenhuma equivalência Windows 7 SP1 x86/x64 foi validada.
