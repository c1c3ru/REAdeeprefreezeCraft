# Política para certificar a engenharia reversa completa

**Situação em 29/10/2026:** NÃO CERTIFICADA. O objetivo de 100% depende de um universo de componentes fechado, de uma medição com denominadores e de equivalência em duas arquiteturas. O resultado não é certificado de fabricante nem acreditação de laboratório independente.

## Três conceitos diferentes

1. **CI estático aprovado:** os testes Python, parsing e consistência de documentação passaram. Não implica comportamento real de Windows/driver.
2. **Componente ou comportamento validado:** hash da amostra e um contrato delimitado, casos positivos, negativos e de fronteira com saída original/reimplementada comparadas, com cobertura e limitações explícitas. Pode ser validado isoladamente sem dar 100% ao produto.
3. **Certificação interna do escopo integral:** todos os componentes necessários foram identificados, cada denominador está fechado, assemântica foi verificada, Win7 SP1 x86 e x64 passaram e existem recibos independentes assinados e comprováveis. Não é uma garantia universal sobre todos os ambientes possíveis.

## Oito portões obrigatórios

| ID | Critério de aceitação | Evidência por hash |
|---|---|---|
| inventory | Arquivo principal, recursos, overlays, dependências, todos os PEs, drivers, dados; sem desconhecidos | Inventário com hashes, extrações autorizadas, registros de origem e reconciliação |
| structural | Cada seção executável com intervalo fechado; código/dados mapeados, instruções, funções, CFG, saltos indiretos e exceções | Mapa sem lacunas, testes de intervalos e auditoria |
| semantics | Contratos para cada função e interface necessária; entradas/saídas, estados, memória, erro e efeitos | Casos comportamentais rastreados até RVA e hashes |
| equivalence | Comparação diferencial original vs. reconstrução com mesmas condições e expectativa; limites e caminhos de falha | Vetores identificados, entradas e saídas autenticadas, divergências resolvidas |
| drivers | .sys reais com hash, arquitetura, assinatura Authenticode/catalog e condições de carregamento | SignTool/relatórios de cadeia, drivers/versões documentados, sem confundir strings com arquivo |
| windows7_x86 | Windows 7 SP1 x86 isolado, snapshots pré/pós, instalação, Frozen/Thawed, reinicialização, rollback, falhas e remoção | Logs de VM, observações e hashes; **não** dados reais sensíveis |
| windows7_x64 | Mesma matriz, independentemente, em Windows 7 SP1 x64 | Outro conjunto distinto de logs/snapshots; não copiar o relatório x86 |
| independent_review | Revisor independente, diferente dos executores das evidências acima | Auditoria dos hashes, casos e políticas; assinatura criptográfica independente |

Os cinco indicadores do arquivo docs/coverage/scope.json têm de ser verdadeiros **e** existir evidência independente, não apenas valores Booleanos. O gate também exige que todas as tarefas do docs/progress/tasks.json estejam concluídas.

## Recibos assinados: formato e vínculo

Para cada portão versionar um arquivo JSON sob docs/certification/receipts/ com campos:

    {
      "schema": "rea-signed-receipt-v1",
      "claim_id": "windows7_x86",
      "scope_sha256": "<SHA256 EXATO do docs/coverage/scope.json>",
      "source_archive_sha256": "<SHA256 da amostra original>",
      "result": "pass",
      "run_id": "<identificador único de execução>",
      "method": "<ferramentas, comandos e versões>",
      "reviewed_at": "<timestamp ISO 8601>",
      "platform": "windows7-sp1-x86",
      "test_cases": ["boot", "frozen", "thawed", "rollback", "failure", "uninstall"],
      "artifacts": [
        {"path": "docs/certification/proofs/x86_sanitized_log.txt", "sha256": "<HASH>"}
      ]
    }

A propriedade platform é obrigatória nos dois portões Windows 7. O recibo deve referenciar evidência **real e sanitizada** (sem binários proprietários, dados pessoais ou segredos), com SHA-256 exato e casos observáveis. Os arquivos da matriz de VMs devem ser distintos.

O revisor/autor assina os bytes exatos do JSON. Exemplo com chave privada **fora do Git**, utilizando OpenSSL no ambiente de assinatura:

    openssl dgst -sha256 -sign /outside/ExecutorA.key -out docs/certification/receipts/windows7_x86.sig docs/certification/receipts/windows7_x86.json

Registre em docs/certification/claims.json a referência ao recibo, seu SHA-256, assinatura e o ID do revisor. Chaves públicas de confiança devem ser obtidas e autenticadas **fora do repositório**, em diretório como /outside/trusted/ExecutorA.pem. Nunca admitir chave pública adicionada pelo mesmo PR como raiz autossuficiente de confiança. Nunca versionar chaves privadas.

A validação criptográfica utiliza openssl dgst -sha256 -verify contra a chave externa. Modificação de recibo, de documento citado ou do scope.json invalida a evidência. Os critérios de assinatura também exigem revisor independente diferente dos executores.

## Comandos reproduzíveis

    python -m tools.rea_coverage --check
    python -m tools.rea_progress --check
    python -m tools.rea_certification --check

O comando de CI acima aprova somente **consistência** de estado, mesmo se o status for NÃO CERTIFICADO. A emissão real exige explicitamente:

    python -m tools.rea_certification --require-certified --trusted-keys /outside/trusted

Esse comando deve retornar código não zero enquanto qualquer portão estiver pendente, faltar evidência/assinatura, ou o escopo global continuar desconhecido. A presença de 213 ou 226 testes sintéticos verdes nunca substitui a prova dinâmica.

Para avançar no produto sob análise: concluir REA-015 (incluindo UPX e corpo opaco), REA-009 (driver real), REA-016 (código/CFG), REA-010/011 (VMs), REA-012/017 (equivalência) e REA-013 (revisão e emissão). Certificações parciais podem ser feitas por função/módulo, mas não alteram o veredito integral antes do fechamento de todos os critérios.

**Limite epistemológico:** nenhum processo finito prova todas as possibilidades de comportamento de um programa arbitrário. A expressão "100%" aqui significa cobertura integral do **escopo fechado, mensurado e publicado**, e equivalência para a matriz de ambientes/casos definida e revisada, não onisciência ou garantia de ausência absoluta de bugs.
