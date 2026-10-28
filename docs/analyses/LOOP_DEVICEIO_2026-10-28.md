# Loop de engenharia reversa — evidências estáticas (2026-10-28)

**Entrada:** `userfreezer.zip` (SHA-256 `f2e1a70e3becff235c886c6092d3d8a5928404bbe43f9c0c6360e428daa64671`). **Fonte analisada:** `Faronics_DFS/DFStd.exe` (SHA-256 `2d7c171d4037660843a7e02c055679c5a26904af84d48fc8c557a67023f55c8b`). Análise em modo somente leitura e conferência pontual com `objdump`.

## Resultados observados

- PE32 x86, ImageBase `0x00400000`. Nove entradas IAT selecionadas e nove thunks candidatos `FF 25`.
- **51 correspondências candidatas** `E8 rel32` apontando para thunks: 13 `DeviceIoControl`; 12 `CreateFileW`; 12 `CreateFileA`; 7 `OpenServiceW`; 3 `OpenSCManagerW`; 1 `CreateServiceW`; 1 `StartServiceW`; 1 `ControlService`; 1 `RegLoadKeyW`.
- Thunk candidato `DeviceIoControl`: RVA `0x500D6E`, `FF 25 78 67 A1 00`, apontando para IAT VA `0x00A16778`. Exemplos verificados visualmente com `objdump`, sem validação de fluxo completo.
- Os dois recursos PE embutidos (`CLOUD_INSTALLER`, `RSC_WU_CMD_LINE`) não apresentaram as importações selecionadas. Ambos têm seções UPX; a ausência de importação **não** estabelece ausência de comportamento.

## Chamadas `DeviceIoControl`: RVA e possível argumento na pilha

| RVA | Constante candidata (hex) | Evidência |
|---|---|---|
| `0x0359CF` | `0x002D1400` | `push imm32; push reg; call` |
| `0x038C08` | Indeterminada/dinâmica | Parâmetro em registrador |
| `0x053F05` | `0x0009006F` | `push imm32; mov; push reg; call` |
| `0x054445` | `0x00090073` | Mesmo padrão |
| `0x0550A5` | `0x00090074` | Mesmo padrão |
| `0x05510F` | `0x00090074` | Mesmo padrão |
| `0x069770` | `0x00071C08` | `push imm32; push reg; call` |
| `0x0697FA` | `0x00071C08` | Mesmo padrão |
| `0x06A0B0` | `0x00072144` | Mesmo padrão |
| `0x06A0D9` | `0x00072154` | Mesmo padrão |
| `0x06D714` | `0x00560000` | Mesmo padrão |
| `0x06EB30` | `0x0009003C` | Mesmo padrão |
| `0x06EBA4` | `0x0009C040` | Mesmo padrão |

**Consolidação:** 13 chamadas candidatas, 12 literais inferidos, 10 valores distintos. Os padrões são compatíveis com a posição de `dwIoControlCode` em uma convenção de chamada x86, mas **não** confirmam o contrato IOCTL, o handle, tamanho de buffers, resultado ou aplicação dos comandos.

## Reconstrução parcial de contexto

- Em RVA `0x0359CF`, `objdump` mostra oito empilhamentos plausíveis e `call 0x00900D6E`, com teste de retorno de `eax` logo após.
- Em RVA `0x06D714`, uma preparação de buffer com `rep movs` precede `call 0x00900D6E`, e o retorno em `eax` é copiado para `esi`.
- O call site de `CreateServiceW` em `0x06A63B` guarda `eax` em memória; isso demonstra fluxo local de retorno, não comprova criação bem-sucedida de serviço.

## Próximo loop: critérios para elevar confiança

1. Validar as fronteiras de instrução e os caminhos de execução por disassembler/CFG, com correspondências por hash e RVA.
2. Associar cada handle a sua origem (`CreateFile*`), string de dispositivo, permissões e serviços instalados.
3. Reconstruir o argumento dinâmico em RVA `0x038C08` e validar tamanhos de buffers, retornos e efeitos.
4. Localizar e verificar assinatura dos drivers realmente presentes/carregados, x86 e x64 separadamente.
5. Executar ensaios em VMs isoladas Windows 7 SP1 (x86/x64), mantendo snapshots; não declarar equivalência antes da validação.

## Reproduzir sem executar o instalador

```bash
python -m unittest discover -s tests -v
python -m tools.rea_loop --archive /caminho/userfreezer.zip --json loop.json --markdown loop.md
# Exemplo opcional de conferência offline de instruções x86 (sem executar PE)
objdump -M intel -d --start-address=0x0046D6F7 --stop-address=0x0046D72C DFStd.exe
```

Não armazenar binários proprietários nem logs com informações sensíveis no repositório. O CI testa somente fixtures sintéticas.
