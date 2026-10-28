# Etapa 2 — inventário e fronteiras estruturais (2026-10-28)

**Origem:** userfreezer.zip (SHA-256 f2e1a70e3becff235c886c6092d3d8a5928404bbe43f9c0c6360e428daa64671). Inspeção estática offline, sem executar ou publicar os arquivos proprietários.

## Binário principal

- Faronics_DFS/DFStd.exe: 18.356.600 bytes, SHA-256 2d7c171d4037660843a7e02c055679c5a26904af84d48fc8c557a67023f55c8b, PE32, machine 0x014c.
- 26 descritores de DLL importada (há DLL repetida). 106 recursos enumerados na árvore PE.
- Importações confirmadas: DeviceIoControl, CreateFileW, CreateServiceW, StartServiceW, ControlService, WinHttp*, RegLoadKeyW, InitiateSystemShutdownExW.
- Referências textuais aos drivers: DeepFrz.sys, DeepFrzx64.sys, FarSpace.sys, FarSpaceX64.sys. Os arquivos .sys **não foram extraídos ou identificados como binários**.

## PEs embutidos com cabeçalhos válidos

| Caminho no recurso do DFStd.exe | Bytes | SHA-256 | Formato | DLLs importadas |
|---|---:|---|---|---:|
| BINARY/CLOUD_INSTALLER/4105 | 9.821.321 | 145c6b8461132fd077a42cee775aca318c2b697b5720283749e04fc6aa5b4772 | PE32, seções UPX0/UPX1 | 25 |
| BINARY/RSC_WU_CMD_LINE/4105 | 584.056 | 454a1a6a576cce0b69acbf320fbeebb4909891ee7592f20afd9df992db6a1351 | PE32, seções UPX0/UPX1 | 5 |

**Achado aninhado:** CLOUD_INSTALLER contém outro recurso BINARY/RSC_WU_CMD_LINE/4105 (584.056 bytes), SHA-256 e6e7f150ff9a40f7c8ee4c14d32d702f49564219a6c9c44c362a6ffbb345644f. O conteúdo inicia sem assinatura MZ, portanto **não** foi identificado como PE. Não presumir equivalência com o executável homônimo do PE principal.

## Automação REA

```bash
python -m unittest discover -s tests -v
python -m tools.rea_structural --archive /caminho/userfreezer.zip --json estrutura.json --markdown interfaces.md
python -m tools.rea_structural --pe /caminho/binario.exe --json pe.json --markdown pe.md
```

O analisador produz somente metadados, hashes, importações, referências estáticas e recursos, com limites de leitura e sem extração dos binários. O GitHub Actions usa fixtures sintéticas (Python 3.8 e 3.12) e **não recebe o ZIP original**.

## Lacunas

- Não foram identificados contratos IOCTL, objetos Device, dispatch IRP nem os drivers reais.
- UPX ainda não foi descompactado. Importações dos PEs compactados podem não representar o conjunto completo do comportamento.
- O fluxo de boot e a operação Frozen/Thawed exigem VM Windows 7 SP1 x86/x64 e evidência independente de assinatura.
- Próxima entrega: mapear funções/call sites, localizar artefatos de drivers e criar testes de equivalência semântica.
