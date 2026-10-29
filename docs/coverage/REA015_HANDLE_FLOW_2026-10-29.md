# REA-015/I — Origem do handle, buffer após cabeçalho e transformação condicional

**29/10/2026** · [Issue #17](https://github.com/c1c3ru/REAdeeprefreezeCraft/issues/17) · **Estado: análise parcial comprovada, inventário NÃO fechado.**

## Resumo verificável

Rastreio **estático** do `DFStd.exe`, SHA-256 `2d7c171d4037660843a7e02c055679c5a26904af84d48fc8c557a67023f55c8b`. A ferramenta `tools/rea_overlay_handle_flow.py` compara **41 âncoras de instruções** do PE32 x86 por VA/bytes de máquina em `.text`, valida **13 arestas de CALL direto rel32** e resolve na tabela de importações as APIs **CreateFileA** e **ReadFile**. Não executa o programa, não interage com driver e não extrai executáveis.

### 1. Origem do handle ReadFile

| VA x86 | Evidência |
|---|---|
| `0x00750B92..0x00750B9A` | caminho recebido da chamadora é encaminhado a um helper com buffer de destino `[owner+0xDC]`; a origem anterior da string ainda não foi identificada |
| `0x00750BB4` | `[owner+0x0C]` contém ponteiro para contexto de arquivo |
| `0x00750BB8` | chama a rotina `0x0075256C` para abertura |
| `0x0075258A` | encaminha ao helper de abertura `0x00752234` |
| `0x007522CC` | chama importação `KERNEL32.DLL!CreateFileA`, via `0x00900D44` e IAT `0x00A1675C` |
| `0x007522D1` | grava o `HANDLE` retornado por `CreateFileA` em `[contexto+0x04]` |
| `0x007522D4` | testa `[contexto+0x04]` contra `INVALID_HANDLE_VALUE` |
| `0x0074FB4C` | encaminha `[owner+0x0C]` ao wrapper de leitura |
| `0x007526AA` | carrega `[contexto+0x04]` para argumento de `ReadFile` |
| `0x007526AE` | chama importação `KERNEL32.DLL!ReadFile` via `0x009010C2` / IAT `0x00A16998` |

**Conclusão restrita:** o handle tem origem imediata no retorno de `CreateFileA` e é preservado no contexto até `ReadFile`. A string de caminho é fornecida à rotina de inicialização por uma chamadora **ainda não rastreada**. Não há prova de que esse handle seja sempre associado ao overlay embutido `CLOUD_INSTALLER`.

### 2. Fluxo dos bytes depois do cabeçalho

| VA | Operação |
|---|---|
| `0x0074FE61` | chama a leitora de cabeçalho `0x0074FB20` |
| `0x0074FE91` | chama, após a etapa anterior, `0x0074FD34` |
| `0x0074FD58` | obtém tamanho solicitado de `[owner+0x58]` |
| `0x0074FD5C` | obtém destino do buffer de `[owner+0x80]` |
| `0x0074FD63` | obtém contexto de arquivo de `[owner+0x0C]` |
| `0x0074FD67` | lê dados pelo mesmo wrapper `0x00752670` / `ReadFile` |
| `0x0074FD71` | testa `[owner+0x60] & 1` |
| `0x0074FD75` | se a flag é zero, pula a etapa de transformação |
| `0x0074FD9B` | se habilitada, despacha buffer/tamanho/estado para `0x007500F8` |

Essa evidência demonstra **leitura para um buffer e processamento condicional após a leitura de cabeçalho** no fluxo estático. Não implica processamento integral dos 7.836.705 bytes do corpo opaco, nem prova o caminho de arquivo específico em execução.

### 3. Rotina que modifica os bytes

A sequência verificada é:

```text
0x0074FD9B  -> 0x007500F8  (dispatcher condicional)
0x007500F8  -> 0x0074F7AC  (verifica conjunto de quatro DWORDs)
0x0075012F  -> 0x0074F728  (processador de estado)
0x0074F78B  -> 0x0074F87C  (rotina de transformação)
0x0074F893  -> 0x0074F8AC  (calcula um byte em AL)
0x0074F89B     xor byte ptr [esi], al
0x0074F89E     inc esi
```

A instrução `xor byte [esi],al` em `0x0074F89B` **prova uma operação XOR in-place sobre um byte do buffer**, iterada por um laço dependente do tamanho. A transformação não é incondicional: depende da flag `[owner+0x60]`, do conjunto de DWORDs e de uma verificação de estado no processador. Identificar essa operação **não comprova** o algoritmo do instalador como um todo, sua semântica de cifragem, nem descompactação do overlay original.

## Reprodutibilidade e limites

```bash
python -m tools.rea_overlay_handle_flow --archive /caminho/para/userfreezer.zip --json rea015_handle_flow.json
python -m unittest discover -s tests -v
python -m tools.rea_progress --check
python -m tools.rea_coverage --check
```

O verificador recusa qualquer amostra com hash diferente do ZIP/PE fixados, instruções não correspondentes, chamadas para outros endereços ou imports API alterados. A suíte CI usa **fixtures sintéticas**, sem dados do instalador comercial.

### Próxima atividade para finalizar o inventário

1. Rastrear a chamadora que fornece o caminho para `CreateFileA` e demonstrar a identidade do arquivo quando a leitura é executada.
2. Rastrear o valor de `[owner+0x60]` e os quatro DWORDs do estado para determinar quando o XOR é aplicado.
3. Analisar a função calculadora `0x0074F8AC` e validar seu efeito com vetores sintéticos ou observações autorizadas, sem supor que o corpo todo foi decodificado.
4. Reconciliar artefatos efetivamente recuperados com REA-009/015/016/017. **REA-015 permanece aberta**, a cobertura global não foi medida e não houve teste Windows 7 SP1 x86/x64.
