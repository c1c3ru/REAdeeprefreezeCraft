# Análise estática inicial — Faronics Deep Freeze Standard 9.00.020.5760

**Data:** 2026-10-28. **Entrada:** `userfreezer.zip`. **Método:** inspeção estática offline. **Estado:** parcial; os componentes não foram executados nem tiveram equivalência semântica validada.

## Proveniência verificada

| Artefato | Tamanho | SHA-256 |
|---|---:|---|
| `userfreezer.zip` | 12.651.811 bytes | `f2e1a70e3becff235c886c6092d3d8a5928404bbe43f9c0c6360e428daa64671` |
| `Faronics_DFS/DFStd.exe` | 18.356.600 bytes | `2d7c171d4037660843a7e02c055679c5a26904af84d48fc8c557a67023f55c8b` |

O pacote original tem **23 entradas ZIP** (incluindo diretórios) e **15 arquivos regulares**. Não contém o código-fonte do produto. O executável principal é **PE32 x86**, versão declarada **9.00.020.5760**, compilado em Delphi/VCL conforme símbolos observados. A data de compilação do cabeçalho PE é apenas metadado, não prova da origem.

## Observações estáticas (não implicam execução)

- Strings encontradas: `DeepFrz.sys`, `DeepFrzx64.sys`, `FarSpace.sys`, `FarSpaceX64.sys`, `DeviceIoControl`, `CreateServiceW`, `StartServiceW`, `ControlService`, `RegLoadKeyW`, `WinHttpSendRequest`.
- Módulos referenciados: `Dfstdinstallhelper`, `Dinstallfiles`, `Dflicense`, `Authenticateuser`, `Thawspacehelper`.
- O analisador local confirma que o PE principal apresenta `DllCharacteristics=0x0000`. Isso é um **sinal de hardening reduzido**, não demonstra exploração.
- Recursos PE embutidos `BINARY/CLOUD_INSTALLER` (9.821.321 bytes) e `BINARY/RSC_WU_CMD_LINE` (584.056 bytes) foram identificados em inspeção de recursos prévia. Ainda não foram reconstruídos semanticamente; as referências a drivers não significam que seus arquivos tenham sido isolados.
- Foi identificada estrutura de assinatura Authenticode no executável, mas **não houve validação criptográfica integral** ou da cadeia de confiança no Windows.

## Achados e backlog

| ID | Prioridade | Ação |
|---|---|---|
| REA-01 | Alta | Inspecionar drivers e serviços efetivamente instalados **somente** em VMs descartáveis. |
| REA-02 | Alta | Localizar, inventariar e hashear os binários x86/x64 extraídos sem execução. |
| REA-03 | Alta | Modelar e testar estados Frozen/Thawed, reinicialização e persistência observável. |
| REA-04 | Média | Auditar mitigadores PE e analisar compatibilidade com Windows 7 antes de qualquer hardening. |
| REA-05 | Média | Identificar/descompactar recursos UPX offline com preservação das evidências. |
| REA-06 | Média | Verificar Authenticode e assinaturas dos drivers com ferramentas Windows confiáveis. |
| REA-07 | Baixa | Atualizar referências documentais legadas para HTTPS quando possível. |

## Compatibilidade com Windows 7

**Não validada experimentalmente.** Existem referências de manifesto e mensagens internas genéricas potencialmente contraditórias. A presença de GUID Windows 7 no manifesto não prova instalação ou funcionamento em todas as edições; é indispensável uma matriz de testes x86/x64. Consultar [WINDOWS7_LAB.md](../WINDOWS7_LAB.md).

## Limites e fontes

A inspeção estática não recupera por si só o comportamento interno dos drivers. O comportamento público de restauração após reboot é descrito em [Faronics — Deep Freeze](https://www.faronics.com/products/deep-freeze/standard); histórico da versão em [Faronics — feature history](https://www.faronics.com/document-library/document/deep-freeze-standard-feature-history). Para assinatura Windows, ver [Microsoft — Driver signing](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing).

**Política:** não versionar executáveis comerciais, chaves, artefatos extraídos proprietários ou técnicas de contorno de licença. Registrar hipóteses e separar achados observados de inferências.
