# REA-015 — descoberta recursiva e classificação do pacote

**Checkpoint:** 2026-10-28 · **Issue:** [#17](https://github.com/c1c3ru/REAdeeprefreezeCraft/issues/17)

**Amostra original:** `userfreezer.zip` SHA-256 `f2e1a70e3becff235c886c6092d3d8a5928404bbe43f9c0c6360e428daa64671`. Executável `Faronics_DFS/DFStd.exe` SHA-256 `2d7c171d4037660843a7e02c055679c5a26904af84d48fc8c557a67023f55c8b`.

## Resultado do primeiro subciclo

O ZIP possui **23 entradas**, das quais **15 são arquivos** e **8 são diretórios**. Os arquivos são 1 EXE, 13 atalhos `.url` e 1 `.txt` (a extensão é apenas indicativa; o scanner valida o conteúdo).

| Local | Recursos PE observados | PE embutidos diretamente observados | Estado |
|---|---:|---:|---|
| `DFStd.exe` | **106** | **2** | Estrutura PE explorada, porém payload interno possivelmente compactado |
| `BINARY/CLOUD_INSTALLER/4105` | **72** | **0** | PE32 x86, seções `UPX0`/`UPX1`; conteúdo original não descompactado |
| `BINARY/RSC_WU_CMD_LINE/4105` | **12** | **0** | PE32 x86, seções `UPX0`/`UPX1`; conteúdo original não descompactado |
| **Total de folhas nos 3 diretórios PE** | **190** | **2** | Apenas inventário **visível** de recursos PE |

### Outras evidências relevantes

- Recurso `BINARY/STD_INSTALL_SIB/4105`: **152.243 bytes**, SHA-256 `791d980f9f329d37...` (prefixo exibido para conferência), assinatura de dados `SIB file`. Seu formato e possível conteúdo aninhado continuam **não verificados**.
- `CLOUD_INSTALLER`: 9.821.321 bytes, SHA-256 `145c6b8461132fd077a42cee775aca318c2b697b5720283749e04fc6aa5b4772`; PE32 x86, 3 seções incluindo `UPX0`, `UPX1`, `.rsrc`.
- `RSC_WU_CMD_LINE`: 584.056 bytes, SHA-256 `454a1a6a576cce0b69acbf320fbeebb4909891ee7592f20afd9df992db6a1351`; PE32 x86, 3 seções incluindo `UPX0`, `UPX1`, `.rsrc`.
- Nomes `DeepFrz.sys`, `DeepFrzx64.sys`, `FarSpace.sys`, `FarSpaceX64.sys` foram encontrados em referências textuais anteriores; **nenhum driver PE completo foi confirmado no inventário atual**.
- Nenhum novo PE diretamente embutido foi identificado nas 84 folhas dos diretórios de recursos dos dois executáveis aninhados. Isso **não exclui** executáveis dentro de dados compactados ou de outros formatos.

## Nova ferramenta: inventário recursivo

`tools/rea_recursive_inventory.py` percorre ZIP → PE → folha de recurso → PE/ZIP embutido, sem gravar os bytes recuperados em disco. Classifica arquivos por assinatura (não apenas extensão), atribui hash SHA-256 por folha, inspeciona arquitetura, seções executáveis e marcadores UPX, distingue referências a nomes de drivers de binários `.sys` efetivos e registra formatos desconhecidos. Os limites de profundidade, arquivos, bytes descompactados e número de nós impedem expansão ilimitada.

```bash
python -m unittest discover -s tests -v
python -m tools.rea_recursive_inventory --archive userfreezer.zip \
  --expect-sha256 f2e1a70e3becff235c886c6092d3d8a5928404bbe43f9c0c6360e428daa64671 \
  --json rea015_inventory.json --markdown rea015_inventory.md
python -m tools.rea_progress --check
python -m tools.rea_coverage --check
```

**Reprodutibilidade:** os números deste documento são um checkpoint local de inspeção estática do pacote original. O CI exercita a ferramenta sobre **fixtures sintéticas**, não inclui a amostra comercial. Regenerar o inventário antes de declarar o escopo fechado.

## O que permanece para concluir REA-015

1. Determinar o significado estrutural do formato `SIB file`, sem executar o instalador.
2. Investigar a superfície compactada UPX de ambos os PEs e distinguir dados/recursos de código original ainda não recuperado.
3. Conferir módulos externos, drivers e dependências de instalação autorizadas; encadear ao REA-009.
4. Reconciliar todos os módulos com `docs/coverage/scope.json` e só alterar `discovery_closed` depois de resolver os desconhecidos relevantes.

**Status:** **REA-015 aberta / em execução por ciclos**, não concluída. Este relatório certifica apenas a contagem de folhas dos diretórios PE que já estão visíveis. Não certifica 100% de códigos, funções, interfaces, semântica ou Windows 7 SP1.
