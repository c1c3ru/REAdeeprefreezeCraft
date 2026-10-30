# REA-015/S — Plano de evidência real e triagem do resultado (2026-10-30)

**Estado:** subciclo de ferramentas; REA-015 segue aberta. A linha de base é **9/17 entregas**, **0 capturas Win7 reais** e **0/8 recibos certificados**.

## Objeto e limites

O recurso BINARY/CLOUD_INSTALLER/4105 é um PE embutido conhecido. Seu overlay físico mede 7.836.809 bytes, com enquadramento provisório de 96 bytes de cabeçalho, 7.836.705 bytes opacos e 8 bytes finais. A REA-015/R dispõe de um comparador local de amostras pré/pós-XOR, mas não de dados originais coletados em execução. Os dois módulos UPX e os drivers permanecem sem recuperação certificada. Nenhuma ferramenta desta etapa decodifica o corpo nem executa o produto.

## Aquisição mínima de evidências reais — laboratório externo

Em VMs Windows 7 SP1 **x86 e x64 separadas**, isoladas, com snapshots descartáveis e instalação legalmente autorizada:

1. Registrar SHA-256 do ZIP/PE originais, configuração da VM e snapshot antes da execução, mantendo os arquivos privados fora do Git.
2. Observar CreateFileA (pathname em armazenamento privado, PID, handle, arquivo aberto, digest completo). CSV do Process Monitor ajuda, mas não comprova sozinho os bytes lidos ou o valor de retorno do handle.
3. Observar ReadFile no retorno da API: mesmo PID/handle, offset absoluto, bytes efetivamente retornados e SHA-256 do buffer antes do XOR.
4. Somente se o ramo de transformação for alcançado, capturar flag [owner+0x60], seleção dos quatro DWORDs, índice no bloco, proveniência da string/chave e pares pré/pós de até 4.096 bytes. Não deduzir valores reais de um horário de log.
5. Preservar os brutos de instrumentação, ambiente, método e eventual arquivo de saída recuperado; registrar seu tamanho e SHA-256 de forma independente. Revisão externa e autenticidade são verificações separadas.
6. Não executar instaladores ou drivers nos runners GitHub Actions nem em máquina de produção. Suspender execução com drivers não verificados.

## Ferramenta 1 — Conferência de integridade do conjunto de evidências

Ferramenta: tools/rea_capture_evidence_intake.py.

Recebe manifesto privado com quatro papéis obrigatórios: file_io_trace (JSON REA-015/N), xor_pairs (JSON REA-015/R), observer_log e vm_environment. Verifica SHA-256, tamanhos, conteúdo das etiquetas de captura, referência fixa do PE e caminhos confinados ao diretório privado. Rejeita duplicação de papéis ou reaproveitamento do mesmo arquivo para papéis diferentes.

Exemplo de estrutura do manifesto (ILUSTRATIVO, não observado):

    {
      "schema": "rea-015-win7-evidence-bundle-v1",
      "capture_id": "SYNTHETIC-NOT-VM",
      "platform": "windows7-sp1-x86",
      "snapshot_id": "VM-SNAPSHOT-EXAMPLE",
      "instrumentation_method": "manual-observation",
      "original_pe_sha256": "2d7c171d4037660843a7e02c055679c5a26904af84d48fc8c557a67023f55c8b",
      "independently_reviewed": false,
      "network_isolated": true,
      "artifacts": [
        {"role": "file_io_trace", "relative_path": "trace.json", "size_bytes": 123, "sha256": "DIGEST_REAL"},
        {"role": "xor_pairs", "relative_path": "pairs.json", "size_bytes": 123, "sha256": "DIGEST_REAL"},
        {"role": "observer_log", "relative_path": "observer.log", "size_bytes": 123, "sha256": "DIGEST_REAL"},
        {"role": "vm_environment", "relative_path": "vm_environment.txt", "size_bytes": 123, "sha256": "DIGEST_REAL"}
      ]
    }

Os campos de tamanho e digest precisam de valores efetivamente medidos; o exemplo **não é executável** como evidência. A marca network_isolated é uma declaração do manifesto, não uma autenticação externa.

Comando local:

    python -m tools.rea_capture_evidence_intake --manifest /privado/win7/manifest.json --evidence-dir /privado/win7 --json /privado/win7/intake.json

Em seguida, validar o contrato de transformação quando houver buffers reais:

    python -m tools.rea_xor_differential --archive /privado/userfreezer.zip --trace /privado/win7/trace.json --pairs /privado/win7/pairs.json --json /privado/win7/diferencial.json

O relatório de intake omite caminhos e conteúdos privados e permanece em estado LOCAL_DIGEST_INTEGRITY_ONLY_REVIEW_REQUIRED; nunca afirma execução autenticada nem emite recibo.

## Ferramenta 2 — Triagem de arquivo já observado no laboratório

Ferramenta: tools/rea_output_structure.py.

Recebe um **arquivo local produzido de fato** pela instrumentação, limitado a 32 MiB, com digest SHA-256 registrado separadamente e identificador sanitizado. Sem executar/descompactar/extrair bytes, identifica candidatos de cabeçalho PE32/PE32+ x86/x64 com limites físicos de seções, contagem de marcadores MZ e prefixos ZIP/gzip/7z.

    python -m tools.rea_output_structure --artifact /privado/win7/saida_observada.bin --expected-sha256 SHA256_REGISTRADO_EXTERNAMENTE --capture-id WIN7-X86-OBS-001 --json /privado/win7/triagem.json

A ausência de assinatura conhecida **não prova** ausência de módulos. Uma assinatura PE plausível **não prova** que o arquivo é um módulo recuperado, válido em execução ou devidamente atribuído ao CLOUD_INSTALLER. Os resultados são metadados de candidatos e SHA do trecho delimitado, nunca o payload extraído.

## Matriz de contratos pendentes

| Contrato | Evidência exigida | Estado |
|---|---|---|
| S-FILE | CreateFileA: origem do pathname, PID, handle e hash do arquivo | Pendente |
| S-READ | ReadFile original: offsets, buffers pré-XOR, hashes | Pendente |
| S-XOR | Buffers pareados reais, flag, quatro DWORDs, índice no bloco, derivação da chave | Pendente |
| S-OUTPUT | Saída observada, tamanho, SHA, interpretação estrutural verificada | Pendente |
| S-MODULES | Binários recuperados, limites íntegros, hashes e arquitetura | Pendente |
| S-DRIVERS | Arquivos .sys e catálogos legítimos verificados | Bloqueado (REA-009) |
| S-EQUIVALENCE | Reimplementação independente e vetores originais Win7 x86/x64 | Pendente |

**Próximo loop de engenharia reversa:** coletar amostras em VM autorizada, comparar origem/transformação, classificar a saída, recuperar módulos quando observados e somente então tentar equivalência. A certidão 0/8 não muda por testes sintéticos. REA-015/016/017 continuam abertas.

## Gates da entrega

Testes Python 3.8 e 3.12 com fixtures sintéticas (cabeçalho PE, marcadores falsos, limites, hash, adulteração de logs, proveniência e caminhos), mais os validadores rea_progress, rea_coverage e rea_certification. Nenhuma execução de Windows 7 no CI; nenhum binário proprietário enviado ao Git.
