# REA-015/L — Chamadas diretas ao inicializador e formato da string temporal

**29/10/2026** · [Issue REA-015 #17](https://github.com/c1c3ru/REAdeeprefreezeCraft/issues/17) · **Estado:** parcial, não certificado.

## Origem e método

O módulo `tools/rea_constructor_xrefs.py` verifica a amostra original `DFStd.exe` SHA-256 `2d7c171d4037660843a7e02c055679c5a26904af84d48fc8c557a67023f55c8b`, fixa o hash ZIP e varre os bytes físicos da seção executável `.text` por candidatos `E8 rel32` cujo destino coincide com quatro funções. Cada ocorrência encontrada é confrontada com uma posição de instrução verificada separadamente na desmontagem GNU objdump e com o opcode no binário, evitando que um `E8` inesperado seja aceito como chamadora comprovada.

**Escopo explícito:** esse é um inventário de **chamadas diretas na seção examinada**. Não inclui chamadas indiretas, virtuais, computadas, PEs internos compactados ou qualquer caminho que dependa de decodificação não realizada. Não significa inventário global de todos os chamadores possíveis.

## 1. Chamadas diretas ao construtor 0x00750F1C

Foram encontradas **11** referências diretas, com `push 0` comprovado para o argumento de string principal em todas. O argumento do caminho vem da função chamadora ou de outra rotina que devolve um ponteiro; nenhum pathname constante foi identificado nesses locais.

| CALL VA | `push 0` VA | Proveniência imediata do caminho |
|---|---|---|
| `0x004170CE` | `0x004170C4` | `[ebp+0x08]` |
| `0x0041734F` | `0x00417345` | `[ebp+0x08]` |
| `0x00437241` | `0x0043722E` | retorno de `0x00407334`, passado por EAX |
| `0x00465C0A` | `0x00465C00` | `[ebp+0x08]` |
| `0x00465EAB` | `0x00465EA1` | `[ebp+0x08]` |
| `0x00467D45` | `0x00467D3E` | `[ebp+0x0C]` |
| `0x00467EC1` | `0x00467EB7` | `[ebp+0x0C]` |
| `0x00468029` | `0x0046801F` | `[ebp+0x0C]` |
| `0x0046821B` | `0x00468211` | `[ebp+0x0C]` |
| `0x004683DF` | `0x004683D5` | `[ebp+0x0C]` |
| `0x0046854F` | `0x00468545` | `[ebp+0x0C]` |

A existência de **11 chamadas diretas com NULL não prova** que outros fluxos tenham parâmetro nulo, nem explica o pathname concretamente usado no instalador.

## 2. Chamadas a geradores auxiliares

| Função | Chamadas diretas na `.text` | Observações |
|---|---:|---|
| `0x00750C60` (preparação alternativa) | **7** | `0x467D83`, `0x467DFB`, `0x468256`, `0x4682D8`, `0x46858A`, `0x46860C`, `0x46DE60` |
| `0x0074F804` (quatro DWORDs) | **4** | duas chamadas relacionadas ao estado de objeto (`0x750B43`, `0x750C84`) e duas chamadas adicionais (`0x47B77B`, `0x47B827`) em outro fluxo |
| `0x0074F914` (inicializador base) | **2** | `0x750F41`, `0x46DD67`; esta última também recebe valores nulos, mas não foi contabilizada entre as 11 chamadas ao construtor |

As chamadas independentes a `0x74F804` passam o ponteiro originado em `[ebp-0x28]` para gerar quatro DWORDs locais em `[ebp-0x38]`. O conteúdo da string não foi observado e a **relação desses pontos com o leitor do CLOUD_INSTALLER não está provada**.

## 3. Constante real de formatação no fluxo temporal

O código em `0x0076AE5A` carrega o endereço `0x009D71B4` como ponteiro para uma string C terminada em NUL, que é fornecida a uma rotina de formatação em `0x0076AE9D`. A constante, **de 32 bytes**, é:

```text
%.3s %.3s%3d %.2d:%.2d:%.2d %d%s
```

SHA-256 da constante: `e3705d782a9125c2d2a14f06bb997c0a763d7f35fc24acd0c671b95b5d000755`.

Isso esclarece **um template de formatação observável** na cadeia `GetLocalTime → transformação de calendário → representação textual`; não é o valor da string efetivamente produzida. Esse resultado também não resolve o restante do algoritmo de construção dos quatro DWORDs em execução real.

## 4. Reprodutibilidade e limitações

```bash
python -m tools.rea_constructor_xrefs --archive /caminho/para/userfreezer.zip --json rea015_xrefs_local.json
python -m unittest discover -s tests -v
python -m tools.rea_progress --check
python -m tools.rea_coverage --check
python -m tools.rea_certification --check
```

O scanner só lê o arquivo original com hashes fixados e reporta metadados, sem extrair novos módulos, executar código proprietário ou manipular a instalação. O CI usa **13 testes sintéticos** de descoberta de destinos rel32, casos negativos, falsa inferência de CALL indireto, hashes, limites e determinismo.

**Pendências:** determinar caminho real recebido no `CreateFileA`, provar qual arquivo ou recurso está associado ao handle, rastrear chamadas indiretas, testar em laboratório autorizado e recuperar drivers/UPX. Não foi comprovada a transformação integral dos 7.836.705 bytes do overlay. Portanto a REA-015 e os oito recibos de certificação continuam pendentes.
