# REA-008 — Proveniência estática de handles, buffers e retornos

**Checkpoint:** 2026-10-28 · **Issue:** [#10](https://github.com/c1c3ru/REAdeeprefreezeCraft/issues/10) · **Tipo de evidência:** desmontagem offline do `DFStd.exe` fixado por SHA-256.

## Resultado verificável

A cadeia `tabela de oito DWORDs → chamadora (0x00438AC0) → auxiliar (0x00438B48) → CreateFileA / DeviceIoControl / CloseHandle` foi rastreada até o nível de **oito posições de argumentos da API**, dos buffers locais e das condições de retorno. O analisador `tools/rea_ioctl_contract.py` recusa a amostra quando o SHA-256, a tabela ou as instruções âncora não correspondem aos valores do binário observado.

### Contrato da chamada DeviceIoControl em 0x00438C08

| Slot | Parâmetro Win32 | Origem demonstrada na janela x86 | Evidência |
|---|---|---|---|
| 1 | `hDevice` | `EBX = CreateFileA return EAX after invalid-handle check` | `0x00438BE5`, `0x00438BEA`, `0x00438BEC`, `0x00438C07` |
| 2 | `dwIoControlCode` | `helper arg1 [EBP+0x8] from table [EDI]` | `0x00438B07`, `0x00438B09`, `0x00438C03`, `0x00438C06` |
| 3 | `lpInBuffer` | `literal NULL` | `0x00438C01` |
| 4 | `nInBufferSize` | `literal 0` | `0x00438BFF` |
| 5 | `lpOutBuffer` | `helper arg2 [EBP+0xC], caller local DWORD [EBP-0x4C]` | `0x00438B01`, `0x00438B06`, `0x00438BFB`, `0x00438BFE` |
| 6 | `nOutBufferSize` | `helper arg3 [EBP+0x10], literal caller 4` | `0x00438B04`, `0x00438BF7`, `0x00438BFA` |
| 7 | `lpBytesReturned` | `helper arg4 [EBP+0x14], caller local DWORD [EBP-0x48]` | `0x00438AFD`, `0x00438B00`, `0x00438BF3`, `0x00438BF6` |
| 8 | `lpOverlapped` | `literal NULL` | `0x00438BF1` |

**A chamada observada passa `lpInBuffer=NULL` e `nInBufferSize=0`.** O buffer de saída é o `DWORD` da chamadora em `[EBP-0x4C]`, com tamanho literal **4**, e a quantidade de bytes retornados vai para `[EBP-0x48]`. Os campos são encaminhados ao helper pelos argumentos `[EBP+0xC]`, `[EBP+0x10]` e `[EBP+0x14]`.

### Contratos auxiliares

`GetSystemDirectoryA` recebe buffer local `[EBP-0x13C]` e capacidade `0x104`; quando o retorno é zero, o helper salta ao epílogo sem tentar abrir a interface.

`CreateFileA` recebe, na ordem da ABI: `lpFileName` da lista local de dois caminhos; acesso desejado **0**; compartilhamento **0**; atributos de segurança **NULL**; disposição **OPEN_EXISTING (3)**; atributos **0x80**; arquivo modelo **NULL**. Seu retorno (EAX) é copiado para EBX em `0x00438BEA`, comparado com `INVALID_HANDLE_VALUE = 0xFFFFFFFF` em `0x00438BEC`. Caminhos de handle inválido não entram em `DeviceIoControl`.

Depois de uma tentativa de IOCTL com handle válido, `CloseHandle(EBX)` ocorre em `0x00438C19`, independentemente do retorno de `DeviceIoControl`. O helper retorna 1 apenas quando o resultado EAX de alguma chamada de IOCTL é não zero. No máximo **dois caminhos** locais são considerados nesse laço.

A chamadora utiliza a tabela de códigos iniciada em `0x0094AF54`, copia oito DWORDs por `rep movs` e pode examinar até **oito códigos**. Um retorno **1** do helper faz a chamadora encerrar a tentativa de códigos imediatamente; ela só retorna 1 quando `bytesReturned == 4` e o `DWORD` lido como não assinado é positivo. Caso o IOCTL tenha retornado sucesso mas seu conteúdo não cumpra os critérios, a função retorna 0 **sem tentar os códigos seguintes**.

### Evidência: códigos candidatos

1. `0x00071c08`
2. `0x0007200c`
3. `0x00071fc4`
4. `0x00071fc0`
5. `0x00071fbc`
6. `0x00071ff4`
7. `0x00071ff0`
8. `0x00071fec`

Estes são **candidatos a `dwIoControlCode` observados no executável**, não funções do kernel comprovadas. Nada nesta etapa identifica o driver que responde aos códigos nem valida seus efeitos em Windows.

## Testes sem envio de IOCTL

O módulo inclui modelos puros `hypothetical_helper` e `hypothetical_caller`, usados exclusivamente com resultados sintéticos. São testados: falha de `GetSystemDirectoryA`; handle inválido; sucesso/falha de IOCTL na primeira ou segunda tentativa; fechamento após handle válido; parada no primeiro helper bem-sucedido; saída com 4 bytes e DWORD positivo; rejeição de comprimento inválido e ausência de sucesso nos oito candidatos.

```bash
python -m tools.rea_ioctl_contract --archive /caminho/para/userfreezer.zip --json rea008_contract.json
python -m unittest discover -s tests -v
python -m tools.rea_progress --check
```

## Critério de conclusão da REA-008

A **proveniência estática das APIs, buffers e retornos dessas duas janelas** está documentada e com validação das âncoras e testes sintéticos. Isso fecha a tarefa de rastreamento estático delimitado; **não** constitui equivalência comportamental, descrição comprovada do protocolo de driver, nem reconstrução integral. Esses aspectos continuam em REA-009, REA-016 e REA-017, além do laboratório Windows 7 SP1 x86/x64.

**Limites:** nenhum arquivo proprietário versionado, nenhum driver executado, nenhum `DeviceIoControl` real enviado.
