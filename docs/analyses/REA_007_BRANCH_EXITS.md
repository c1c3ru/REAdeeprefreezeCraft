# REA-007 — Desvios condicionais, saídas e limites dos dois laços

**Data:** 2026-10-28  
**Issue:** [#9](https://github.com/c1c3ru/REAdeeprefreezeCraft/issues/9)  
**Amostra:** `Faronics_DFS/DFStd.exe`, SHA-256 `2d7c171d4037660843a7e02c055679c5a26904af84d48fc8c557a67023f55c8b`.

## Objetivo e critério de aceite

Inventariar os desvios condicionais das **duas funções delimitadas no ciclo 5**, suas saídas locais, destinos, ramos alternativos e situações não resolvidas; automatizar a enumeração com travas de exploração e testes sintéticos. O objetivo **não é** afirmar completude global de CFG ou viabilidade de execução.

## Achados confirmados por desmontagem offline

| Função candidata | Janela VA | Condicionais | Retorno local | Retrocessos | Alvos diretos pendentes na janela |
|---|---|---:|---|---:|---:|
| Chamadora | `0x00438AC0..0x00438B48` (fim exclusivo) | 4 | `0x00438B47` | 1 | 0 |
| Auxiliar | `0x00438B48..0x00438C41` (fim exclusivo) | 5 | `0x00438C40` | 1 | 0 |

### Chamadora (4 pontos de decisão)

| VA do desvio | Instrução | Destino se tomado | Continuação (não tomado) | Evidência de condição |
|---|---|---|---|---|
| `0x00438B13` | `jne` | `0x00438B2C` | `0x00438B15` | produtor de flags não confirmado nesta janela curta |
| `0x00438B19` | `jne` | `0x00438B21` | `0x00438B1B` | `cmp [ebp-0x48],4` em `0x00438B15` |
| `0x00438B1F` | `ja` | `0x00438B25` | `0x00438B21` | `cmp [ebp-0x4c],0` em `0x00438B1B` |
| `0x00438B33` | `jb` | `0x00438AF3` | `0x00438B35` | `cmp esi,8` em `0x00438B30` |

O salto para `0x00438AF3` forma uma aresta retroativa, classificada no ciclo 5 como candidata a *back-edge natural*; o fluxo contém instrução `ret` em `0x00438B47`.

### Auxiliar (5 pontos de decisão)

| VA do desvio | Instrução | Destino se tomado | Continuação (não tomado) | Evidência de condição |
|---|---|---|---|---|
| `0x00438B88` | `je` | `0x00438C2D` | `0x00438B8E` | `test eax,eax` após `GetSystemDirectoryA` |
| `0x00438BEF` | `je` | `0x00438C1E` | `0x00438BF1` | `cmp ebx,0xffffffff` após `CreateFileA` |
| `0x00438C0F` | `je` | `0x00438C18` | `0x00438C11` | `test eax,eax` após `DeviceIoControl` |
| `0x00438C26` | `jne` | `0x00438C2D` | `0x00438C28` | `cmp [ebp-0x28],0` |
| `0x00438C2B` | `jb` | `0x00438BD3` | `0x00438C2D` | `cmp edi,2` |

A aresta `0x00438C2B → 0x00438BD3` é retroativa, mas **não** satisfaz a condição de dominância para ser chamada de *back-edge natural* no CFG delimitado. O caminho `0x00438BEF → 0x00438C1E` evita a chamada de controle naquela passagem; a semântica do desvio continua condicionada ao estado em execução.

## Automação implementada

`tools/rea_path_coverage.py`:
- Desmonta offline as duas janelas com `objdump`, após verificar **SHA-256 exato** do PE.
- Enumera ramos `taken`/`not_taken` e evidência de `cmp`/`test` próxima, distinguindo fontes não confirmadas.
- Classifica retorno explícito, salto indireto/não resolvido, saída da janela, limite de profundidade e corte de repetição de laço **separadamente**.
- Usa limites de estados, caminhos, profundidade e visitas; fornece JSON e Markdown determinísticos.
- Em chamadas externas, assume continuação apenas para a modelagem sintática. **Não prova que o alvo retorna**.
- Executa somente sobre binário local; o CI utiliza **fixtures sintéticas**, sem o instalador proprietário.

```bash
python -m unittest discover -s tests -v
python -m tools.rea_path_coverage --archive userfreezer.zip \
  --json rea007.json --markdown rea007.md
python -m tools.rea_progress --check
```

### Conclusão e limites do aceite

**Concluído somente para as duas janelas candidatas:** levantamento dos 9 desvios, 18 resultados sintáticos, dois retornos, dois retrocessos e ausência de destinos diretos pendentes nessas janelas. Não extrapolar estes resultados à totalidade do programa. A análise é estrutural e não valida viabilidade das decisões, efeitos dos códigos de controle, identidade do driver, assinatura ou compatibilidade Windows 7 SP1 x86/x64.

**Próximo loop:** [REA-008 — proveniência de handles, buffers e retornos](https://github.com/c1c3ru/REAdeeprefreezeCraft/issues/10) e [REA-009 — identificação de drivers reais](https://github.com/c1c3ru/REAdeeprefreezeCraft/issues/11).
