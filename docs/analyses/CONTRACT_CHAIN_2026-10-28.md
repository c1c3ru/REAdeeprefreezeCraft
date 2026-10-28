# REA — Ciclo 6: tabela de controle e fluxo interprocedural

**Data:** 2026-10-28. **Arquivo:** `Faronics_DFS/DFStd.exe`, SHA-256 `2d7c171d4037660843a7e02c055679c5a26904af84d48fc8c557a67023f55c8b`. **Origem:** `userfreezer.zip`, SHA-256 `f2e1a70e3becff235c886c6092d3d8a5928404bbe43f9c0c6360e428daa64671`.

## Evidências observadas

A função candidata em VA `0x00438AC0` copia oito dwords little-endian de `0x0094AF54` (mov esi + mov ecx,8 + rep movs). Um laço carrega o elemento de `[EDI]`, passa-o à função auxiliar em `0x00438B48` e verifica o índice `ESI` contra 8. Na auxiliar, `[EBP+0x08]` é colocado na posição do segundo argumento da chamada à API `DeviceIoControl`.

| Índice | Dword encontrado |
|---:|---|
| 0 | `0x00071C08` |
| 1 | `0x0007200C` |
| 2 | `0x00071FC4` |
| 3 | `0x00071FC0` |
| 4 | `0x00071FBC` |
| 5 | `0x00071FF4` |
| 6 | `0x00071FF0` |
| 7 | `0x00071FEC` |

São **valores candidatos de `dwIoControlCode` no lado usuário**. Não há comprovação de que todos sejam enviados, aceitos ou manipulados por algum driver; há saídas condicionais no loop.

## Cadeia de chamadas verificada por thunks FF25 e tabela IAT

| Site (VA) | API importada | Thunk (VA) |
|---|---|---|
| `0x00438B81` | `GetSystemDirectoryA` | `0x00900F2A` |
| `0x00438BE5` | `CreateFileA` | `0x00900D44` |
| `0x00438C08` | `DeviceIoControl` | `0x00900D6E` |
| `0x00438C19` | `CloseHandle` | `0x00900D20` |

A região `0x0094B078` contém o modelo `\\\\.\\C:`; o ponteiro em `0x0094B084` referencia outro literal com o mesmo formato em `0x00953E57`. A auxiliar coleta o diretório de sistema, modifica a letra de unidade do primeiro modelo, carrega o caminho candidato em `EAX` a partir de `[ESI]`, chama `CreateFileA`, copia o retorno para `EBX` e compara-o com `0xFFFFFFFF`.

No caminho que alcança `DeviceIoControl`, há teste de retorno `test eax,eax`; uma saída considerada bem-sucedida pelos bytes observados atualiza um indicador local `[EBP-0x28]`. A função também chama `CloseHandle` com `EBX`. Esses são fatos de fluxo local, **não provas de acesso real a qualquer dispositivo ou driver**.

## Limites e requisitos

- O resultado depende do SHA-256 fixado no analisador e de instruções esperadas nos endereços documentados. Se algum sinal divergir, o relatório marca a relação como não confirmada.
- O CFG das duas funções é delimitado e não resolve chamadas indiretas/exceções.
- O significado das operações, a semântica dos códigos, resultados de I/O, estados de disco e identidade do driver permanecem desconhecidos.
- Windows 7 SP1 x86/x64 permanece requisito, ainda sem validação experimental.

## Reproduzir e validar

```bash
python -m unittest discover -s tests -v
python -m tools.rea_contract_trace --archive userfreezer.zip --json contract_cycle6.json
```

A ferramenta faz **análise offline** com Python 3.8+ e GNU binutils, sem instalar ou executar binários. O ZIP não é enviado ao CI e não deve ser versionado. A análise é registrável em JSON e seus testes usam apenas dados sintéticos.
