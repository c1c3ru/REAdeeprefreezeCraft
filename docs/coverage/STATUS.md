# REA — cobertura integral verificável

**Referência:** 2026-10-28
**Produto:** Deep Freeze Standard 9.00.020.5760

**Objetivo:** Reconstruir e verificar 100% dos componentes e comportamentos identificáveis do produto, com denominadores rastreáveis e sem confundir cobertura estrutural com equivalência.

## Linha de base

- PEs identificados: **3**.
- Recursos não-PE com formato identificado: **1**.
- Referências a nomes de driver sem binário: **4**.
- PEs com denominador executivo desconhecido: **2**.
- Bytes executáveis medidos: **5246976**.
- Bytes físicos UPX1 (compactados, NÃO decodificados): **2095104**.
- Módulos UPX com código original não recuperado: **2**.
- Bytes de janelas estruturalmente desmontadas: **385**.
- Fração das janelas sobre o denominador conhecido: **0.00733756%**.
- Denominador global do produto fechado: **não**.
- Engenharia reversa integral certificada: **não**.

> Decoded bytes are a bounded structural sample, not semantic or behavioral coverage.

A fração local não é cobertura do produto completo; portanto o percentual global permanece **indeterminado**, até fechamento de escopo e testes.

## Artefatos analisados

| Componente | Bytes executáveis conhecidos | Bytes de janelas | Percentual local | Semântica |
|---|---:|---:|---:|---|
| DFSTD_MAIN | 5246976 | 385 | 0.00733756% | partial |
| CLOUD_INSTALLER | desconhecido | 0 | — | unmeasured |
| RSC_WU_CMD_LINE | desconhecido | 0 | — | unmeasured |

## Recursos de dados identificados

| Identificador | Formato | Bytes | Registros internos verificados |
|---|---|---:|---|
| TSILANG_STD_INSTALL | tsilang_translation_data | 152243 | não |

## Desconhecidos que impedem 100%

- Recursive resource/archive discovery is not closed
- Unknown executable section sizes for two embedded PEs
- Four driver filename references are not recovered driver binaries
- Only two candidate functions of the main PE have bounded structural decoding
- No global function or instruction coverage; no semantic equivalence established
- Windows 7 SP1 x86/x64 dynamic validation is absent
- TsiLang SIB translation records are not parsed beyond exact format header
- CLOUD_INSTALLER appended 7,836,809-byte overlay remains unclassified; no driver binaries verified from it

## Engenharia de loop — próximos alvos

- **REA-008:** Flow of handles, buffers and returns ([issue](https://github.com/c1c3ru/REAdeeprefreezeCraft/issues/10)).
- **REA-009:** Driver artifact identification and signatures ([issue](https://github.com/c1c3ru/REAdeeprefreezeCraft/issues/11)).
- **REA-015:** Recursive inventory and package denominator closure ([issue](https://github.com/c1c3ru/REAdeeprefreezeCraft/issues/17)).
- **REA-016:** Executable byte and function/CFG classification ([issue](https://github.com/c1c3ru/REAdeeprefreezeCraft/issues/18)).
- **REA-017:** Behavioral contracts and equivalence evidence ([issue](https://github.com/c1c3ru/REAdeeprefreezeCraft/issues/19)).

## Regra de conclusão

Nunca declarar 100% global com artefatos/denominadores desconhecidos, drivers não recuperados, bytes não classificados ou testes de equivalência e Windows 7 SP1 x86/x64 ausentes.

Regenerar: python -m tools.rea_coverage --write
Validar: python -m tools.rea_coverage --check
