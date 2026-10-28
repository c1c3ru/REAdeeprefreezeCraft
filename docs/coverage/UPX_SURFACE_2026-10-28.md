# REA-015/D — Superfície UPX e pontos de entrada verificados

**Referência:** 2026-10-28 · **Issue:** [#17](https://github.com/c1c3ru/REAdeeprefreezeCraft/issues/17) · **Status:** parcial / inventário não fechado

**Amostra de origem:** `userfreezer.zip` SHA-256 `f2e1a70e3becff235c886c6092d3d8a5928404bbe43f9c0c6360e428daa64671`; executável `DFStd.exe` SHA-256 `2d7c171d4037660843a7e02c055679c5a26904af84d48fc8c557a67023f55c8b`.

## Objetivo da iteração

Medir e autenticar a superfície UPX **fisicamente presente no arquivo**, mapear o ponto de entrada PE para um offset em `UPX1` e registrar de modo verificável **o que falta para recuperar o código original**. Este checkpoint **não executa nem descompacta** o instalador.

## Resultados

| Módulo | Entry RVA | Entry no arquivo | UPX0 raw / virtual | UPX1 raw / virtual |
|---|---|---|---:|---:|
| CLOUD_INSTALLER | `0x73EDD0` | `0x1DE1D0` | 0 / 5.636.096 | 1.958.400 / 1.961.984 |
| RSC_WU_CMD_LINE | `0x0C41B0` | `0x0215B0` | 0 / 663.552 | 136.704 / 139.264 |

Ambas as entradas pertencem à seção `UPX1`, cujos bytes estão presentes fisicamente. O marcador `UPX!` foi encontrado no offset **`0x3E0`** do cabeçalho PE de ambos. O conteúdo inicial dos pontos de entrada foi hasheado, sem incluir bytes do loader no repositório.

| Componente | SHA-256 do conteúdo físico de `UPX1` |
|---|---|
| CLOUD_INSTALLER | `cc1a67e0060bb4fb13f8ef0b08c963c3cafd880a70b839b72cdd55eb6fbb5e1b` |
| RSC_WU_CMD_LINE | `2b346ea50e275436952384a345caee6baeea1b94ea223626fcdb3a730f887406` |

**Total de bytes de seções executáveis empacotadas fisicamente presentes:** 2.095.104, medida separada dos 5.246.976 bytes de seção executável já medidos no DFStd principal. Esses 2.095.104 bytes são de **payload compactado + loader**, não de código reconstruído. Seu valor não altera o numerador de instruções analisadas nem implica equivalência semântica.

## Como reproduzir

```bash
python -m tools.rea_upx_surface --archive /caminho/para/userfreezer.zip --json rea015_upx_surface.json
python -m unittest discover -s tests -v
python -m tools.rea_coverage --check
python -m tools.rea_progress --check
```

O script valida os hashes fixados do ZIP, do executável principal e dos PEs embarcados, confirma permissões e intervalos das seções, mapeia o RVA de entrada para bytes em disco e produz um JSON sem distribuir componentes comerciais. A suíte do CI usa **PEs sintéticos** e não requer a amostra original.

## Próxima iteração — ainda necessária para o objetivo 100%

1. **REA-015:** obter uma imagem desempacotada verificável desses dois PEs em ambiente de análise isolado, registrar tamanho/hash/denominador de código e **sem executar drivers**, se a ferramenta/ambiente estiver disponível.
2. **REA-009:** localizar e identificar binários de driver reais e assinaturas; referências textuais não satisfazem o aceite.
3. **REA-016:** classificar regiões virtuais como código, dados ou desconhecidas, reconstruindo funções/CFG e caminhos indiretos.
4. **REA-008/017:** ampliar contratos de buffers/retornos e validar comportamentos em laboratório Windows 7 SP1 x86/x64.

**Limites:** sem descompactação confirmada, o código original contido em `UPX0` permanece desconhecido. Não declarar `discovery_closed` nem cobertura global 100%.
