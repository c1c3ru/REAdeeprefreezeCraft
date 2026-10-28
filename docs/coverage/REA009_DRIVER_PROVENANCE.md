# REA-009 — Evidência de drivers, certificados e dados adicionais

**Status:** bloqueada por falta de artefatos completos de driver · **Issue:** [#11](https://github.com/c1c3ru/REAdeeprefreezeCraft/issues/11) · **Checkpoint:** 2026-10-28.

A origem observada foi o arquivo `userfreezer.zip` com SHA-256 `f2e1a70e3becff235c886c6092d3d8a5928404bbe43f9c0c6360e428daa64671`. Esta análise é **somente leitura**, sem instalação, execução, desativação ou modificação do produto.

## O que foi comprovado

- O ZIP possui **15 entradas de arquivo**, sendo um executável principal; **nenhuma entrada `.sys` diretamente**.
- Os três PEs identificados nas árvores de recursos visíveis incluem dois embutidos. **Nenhum driver PE recuperado** nesse escopo de busca. Isso não exclui drivers em dados compactados, no instalador após execução ou em dependências externas.
- `DFStd.exe` contém apenas referências textuais aos nomes de drivers conhecidos: `DeepFrz.sys` (3), `DeepFrzx64.sys` (2), `FarSpace.sys` (9) e `FarSpaceX64.sys` (4). Os dois PEs embutidos não contêm esses quatro nomes nessa inspeção literal.
- Os contadores de referência **não** representam instâncias de drivers, carregamentos, objetos DeviceIoControl ou funcionalidades provadas.

## Superfície de certificados Authenticode

| Componente | `WIN_CERTIFICATE` (bytes) | Certificado do PE | Criptografia/cadeia validada |
|---|---:|---|---|
| `DFStd.exe` | 10.616 | presente, PKCS#7 | **não** |
| `CLOUD_INSTALLER` | 0 | ausente na tabela PE | **não** |
| `RSC_WU_CMD_LINE` | 10.616 | presente, PKCS#7 | **não** |

O cabeçalho `WIN_CERTIFICATE` dos dois componentes com certificados tem revisão `0x0200` e tipo `0x0002`. O OpenSSL local interpretou os certificados X.509 do blob PKCS#7, com sujeito **Faronics Corporation** e emissor de assinatura **DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1**, sem ter feito a verificação Authenticode do digest do executável, do carimbo temporal, da cadeia de confiança ou da política de driver em Windows. Os hashes SHA-256 das estruturas PKCS#7 e os offsets estão registrados em [rea009_checkpoint.json](rea009_checkpoint.json).

**Presença de certificado não prova assinatura válida**. Ademais, esses certificados pertencem a executáveis identificados, e **não** a algum `.sys` recuperado.

## Nova região que exige inspeção: overlay no CLOUD_INSTALLER

A seção física final do `CLOUD_INSTALLER` termina no offset `0x1E4800`. A partir desse ponto há **7.836.809 bytes de dados adicionais**, SHA-256 `9453669c5ae280cb8718761159895da425168ccbba1e4e56d376b5165554b9e2`.

Essa região **não tem formato confirmado**; pode conter dados do instalador, mas não há base para afirmar que contém um driver. Ela será tratada como `overlay_unknown` na fila de análise de componentes da REA-015. Não é parte das seções executáveis medidas nem da cobertura de código reconstruído.

## Automação de evidência

`tools/rea_driver_evidence.py`:
- valida SHA-256 opcional do ZIP, percorre PE principal/recursos PE visíveis até limite de profundidade, conta referências ASCII/UTF-16 e só registra `.sys` como binário confirmado quando possui cabeçalho PE parseável;
- diferencia tabela de certificados PE (offset físico) de prova de assinatura criptográfica;
- mede/hasheia bytes adicionados após seções e eventual tabela de certificados, incluindo overlays desconhecidos;
- deixa explícito `cryptographically_verified_signatures: 0`, `scope_closed: false`, sem executáveis/arquivos proprietários no repositório.

```bash
python -m tools.rea_driver_evidence --archive /caminho/para/userfreezer.zip \
  --expect-sha256 f2e1a70e3becff235c886c6092d3d8a5928404bbe43f9c0c6360e428daa64671 \
  --json rea009_local_result.json
python -m unittest discover -s tests -v
python -m tools.rea_progress --check
python -m tools.rea_coverage --check
```

O CI usa somente fixtures sintéticas. Nenhum teste de driver real ou de Windows 7 foi executado.

## Desbloqueio para completar a REA-009

1. Obter **binários `.sys` reais de uma instalação/autorização legítima**, associados à versão e ao hash da amostra; registrar nome, origem, arquitetura PE32/PE32+, versão, SHA-256 e catalog `.cat` se houver.
2. Em máquinas virtuais isoladas **Windows 7 SP1 x86 e x64**, verificar cadeia, carimbo temporal, política de assinatura e condições de carregamento sem interferir em produção. Exemplos administrativos de verificação: `Get-AuthenticodeSignature` e, com o WDK, `signtool verify /kp /v driver.sys`, usando `/c driver.cat` quando houver assinatura de catálogo. Não confundir certificado presente com driver carregável.
3. Registrar pré-requisitos de SHA-2 apropriados à instalação (consultar boletim oficial <https://learn.microsoft.com/pt-br/security-updates/securityadvisories/2015/3033929> e <https://support.microsoft.com/pt-br/servicing/os/windows/2020/09/2019-sha-2-code-signing-support-requirement-for-windows-and-wsus>).
4. Reconciliar drivers e overlay com [o inventário de cobertura integral](scope.json).

**Condição de encerramento:** arquivos reais de driver e evidência de assinatura verificável por arquitetura, não apenas strings ou a presença de certificados nos três PEs já conhecidos.
