# REA-015/F — Delimitação e inventário estático do overlay

**Data:** 29/10/2026 · **Questão:** [REA-015 #17](https://github.com/c1c3ru/REAdeeprefreezeCraft/issues/17) · **Estado:** em execução, ainda não concluída.

## Proveniência da amostra

- Arquivo `userfreezer.zip`: SHA-256 `f2e1a70e3becff235c886c6092d3d8a5928404bbe43f9c0c6360e428daa64671`.
- Instalador `Faronics_DFS/DFStd.exe`: SHA-256 `2d7c171d4037660843a7e02c055679c5a26904af84d48fc8c557a67023f55c8b`.
- Recurso PE `BINARY/CLOUD_INSTALLER/4105`: SHA-256 `145c6b8461132fd077a42cee775aca318c2b697b5720283749e04fc6aa5b4772`.
- Dados após o fim da última seção física desse PE: offset `0x1E4800`, tamanho **7.836.809 bytes**, SHA-256 `9453669c5ae280cb8718761159895da425168ccbba1e4e56d376b5165554b9e2`.

## Estrutura observada, sem atribuir formato não comprovado

A leitura offline identificou um **candidato a enquadramento por campos e sentinelas**, não um formato de instalador comprovado:

| Campo / região do overlay | Evidência |
|---|---|
| DWORD em `+0x00` | **96** (`0x60`), compatível com início de uma região de cabeçalho de 96 bytes |
| DWORD em `+0x04` | **86** (`0x56`); significado desconhecido |
| DWORD em `+0x08` | **769** (`0x301`); não atribuir versão formal sem documentação |
| DWORD em `+0x0C` | `0x69ABCD69` |
| DWORD em `+0x24` | **7.836.809**, exatamente o comprimento da região |
| Posição `+0x779481` | repetição do marcador `0x69ABCD69` oito bytes antes do fim |
| Últimos 4 bytes | `77 6B 88 FF`; significado desconhecido |

A hipótese de divisão em **96 bytes de cabeçalho + 7.836.705 bytes de corpo + 8 bytes finais** é estruturalmente consistente na amostra. Não foi identificada uma especificação de formato e essa divisão permanece uma hipótese, não um parser de registros validado.

- Candidato a cabeçalho (96 bytes), SHA-256 `c5d1764ad06d1a58a856093556328bac6277420abd702d44608a656e17f1dd43`.
- Candidato a corpo (7.836.705 bytes), SHA-256 `0debdf907e9b12b3c10012b473c97ebcd5022542d2584e29e8120f51c8ec7e28`.
- Região final (8 bytes), SHA-256 `a1f7b045c4cda0f59e5c2c5c4c38a86d6dd8c33a48dbfa75e5ea6bd650edb6f8`.

## Assinaturas e validação de falsos positivos

O scanner encontrou **116 marcadores `MZ`**, mas **nenhum validou** como PE x86/x64 com cabeçalho `PE\0\0`, tabela de seções e limites consistentes. Não foram localizadas as assinaturas fortes pesquisadas para cabeçalhos ZIP, 7z, CAB, RAR, XZ ou ELF.

Isso não prova ausência de arquivos executáveis ocultos: o corpo pode conter dados transformados, compactados, cifrados ou encapsulados em estrutura ainda não compreendida.

### Entropia local em amostras de 64 KiB do possível corpo

| Região amostrada | Entropia Shannon (bits/byte) |
|---|---:|
| Início | **7,99686** |
| Meio | **7,99717** |
| Final | **7,64961** |

Entropia elevada **não permite distinguir**, isoladamente, compressão de cifragem ou dados de outra natureza. Nenhum algoritmo ou chave foi identificado.

## Código e testes

`tools/rea_overlay_inventory.py` realiza leitura somente de amostras fixadas por SHA-256, valida limites e duplicidades, mapeia a região além das seções PE, calcula hashes do conjunto e de regiões, procura marcadores conhecidos, verifica se sequências `MZ` têm estrutura PE e mede a entropia em janelas limitadas. **Não extrai ou executa conteúdo proprietário, não tenta descompactação forçada e não prova ausência de drivers.**

`tests/test_rea_overlay_inventory.py` contém 11 testes **sintéticos** para integridade dos campos, diferenças entre marcador e executável, limites de recursos, resultados determinísticos e recusa de amostra com hash incorreto.

```bash
python -m tools.rea_overlay_inventory --archive /caminho/para/userfreezer.zip --json rea015_overlay_local.json
python -m unittest discover -s tests -v
python -m tools.rea_progress --check
python -m tools.rea_coverage --check
```

A saída local de referência, sem bytes proprietários, está em [rea015_overlay_checkpoint.json](rea015_overlay_checkpoint.json). O CI utiliza somente dados sintéticos.

## Nova evidência da leitura do cabeçalho — subciclo H

Foram identificadas no código x86 do DFStd.exe rotinas com leitura de 96 bytes, verificação de `0x69ABCD69` e inicialização dos campos correspondentes a este cabeçalho, em 21 instruções âncora (ver [análise estática REA-015/H](REA015_READER_TRACE_2026-10-29.md)). Ainda falta demonstrar a cadeia de uso do recurso CLOUD_INSTALLER e a transformação efetiva do corpo.

## Pendências para a meta 100%

**REA-015 permanece aberta**. Ainda é necessário determinar o formato/transformação do corpo do overlay, identificar componentes eventualmente encapsulados, comprovar o inventário dos módulos descompactados dos dois PEs UPX, identificar drivers completos e verificar dependências externas. Isso bloqueia os denominadores globais da engenharia reversa. Os testes de equivalência e Windows 7 SP1 x86/x64 não foram realizados.
