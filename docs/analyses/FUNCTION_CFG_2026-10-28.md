# REA — Ciclo 5: CFG delimitado e contratos estruturais

**Data:** 2026-10-28 · **Artefato:** `Faronics_DFS/DFStd.exe` · **SHA-256:** `2d7c171d4037660843a7e02c055679c5a26904af84d48fc8c557a67023f55c8b` · **ZIP:** `f2e1a70e3becff235c886c6092d3d8a5928404bbe43f9c0c6360e428daa64671`.

Método: `objdump -D -M intel`, decodificação a partir de **entradas candidatas** identificadas por prólogo x86 e retorno, busca de caminhos por worklist, blocos básicos, dominadores e arestas retroativas. Nada foi executado; nenhuma chamada kernel foi reproduzida. O CFG é delimitado a cada janela e não é um CFG global.

## Observações verificadas

| Critério | Rotina chamadora | Rotina auxiliar |
|---|---|---|
| VA inicial (candidata) | `0x00438AC0` | `0x00438B48` |
| Fim exclusivo | `0x00438B48` | `0x00438C41` |
| Instruções decodificadas | 55 | 82 |
| Instruções alcançáveis a partir da entrada proposta | 55 | 82 |
| Blocos básicos | 8 | 10 |
| Arestas retroativas | 1 | 1 |
| Saltos não resolvidos dentro da janela | 0 | 0 |
| Chamadas importadas de interesse | nenhuma | `CreateFileA`, `DeviceIoControl` |

**Chamador:** salto condicional retroativo `0x00438B33 → 0x00438AF3`, com índice `ESI` comparado a `8`; existe chamada direta à rotina auxiliar em `0x00438B0A → 0x00438B48`. A intenção do laço permanece desconhecida.

**Auxiliar:** salto retroativo `0x00438C2B → 0x00438BD3` após comparação de `EDI` com `2`. Sua aresta retroativa **não é um back-edge natural segundo a relação de dominância calculada**: esta distinção evita uma afirmação estrutural incorreta. Dentro do corpo, observa-se `CreateFileA` em `0x00438BE5` e `DeviceIoControl` em `0x00438C08`, com desvio de controle em `0x00438BEF` que pode saltar a chamada de controle na iteração corrente.

### Fluxo de dados preliminar

A função auxiliar lê quatro argumentos da pilha: `[EBP+0x08]`, `[EBP+0x0C]`, `[EBP+0x10]` e `[EBP+0x14]`. O primeiro aparece na posição de parâmetro de `DeviceIoControl` compatível com `dwIoControlCode`. Os demais participam da preparação de argumentos relativos a buffers de saída. Há um indicador local `[EBP-0x28]` devolvido em `EAX` ao final.

O handle em `EBX` é abastecido pelo retorno de `CreateFileA` e comparado a `0xFFFFFFFF` antes da chamada seguinte. A correspondência `CreateFileA` → handle → `DeviceIoControl` é um **fluxo local de instruções observadas**, não comprovação de um driver ou dispositivo específico.

## Limites de confiança

- O prólogo e `ret` tornam os limites plausíveis, **não demonstram** que sejam os limites completos.
- O caminho analisado usa somente saltos diretos dentro da janela. Não avalia exceções, concorrência, código auto-modificável ou contexto dinâmico.
- A presença de `DeviceIoControl` não prova comunicação com `DeepFrz.sys` ou `FarSpace.sys`.
- Os códigos de controle, o caminho de dispositivo, o conteúdo dos buffers e o significado do retorno **não foram validados**.
- O produto comercial e a compatibilidade Windows 7 SP1 x86/x64 continuam **sem validação dinâmica**.

## Reproduzir

```bash
python -m unittest discover -s tests -v
python -m tools.rea_function_cfg --archive userfreezer.zip --entry 0x438ac0 --stop 0x438b48 --json cfg_function_caller.json
python -m tools.rea_function_cfg --archive userfreezer.zip --entry 0x438b48 --stop 0x438c41 --json cfg_function_helper.json
```

A automação gera JSON apenas com metadados de fluxo e provê limites de tempo/tamanho. A saída não contém os bytes do executável. O CI executa exclusivamente fixtures sintéticas.

**Próximo ciclo:** confirmação independente dos limites de função e rastreamento de dependências no grafo, seguido da verificação autorizada de drivers e assinaturas em VMs isoladas, mantendo Windows 7 como requisito.
