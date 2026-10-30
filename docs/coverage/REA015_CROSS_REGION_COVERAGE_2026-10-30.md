# REA-015/O — Cobertura correta em leituras que atravessam regiões

Checkpoint: 2026-10-30. Escopo: **correlator offline**, sem novas observações de VM.

## Problema e correção

O correlator de REA-015/N reconhecia uma leitura com hash válido, mas só incluía bytes na cobertura do corpo se a leitura estivesse *inteiramente* dentro do corpo. Uma leitura válida abrangendo cabeçalho e corpo (ou corpo e trailer) recebia a classe `crosses_regions` e seus bytes internos ao corpo eram ignorados.

Agora cada leitura com hash verificado contribui com a interseção entre o intervalo lido `[pos, pos + bytes_returned)` e o corpo `[96, len(overlay) - 8)`. A união dos intervalos evita contar bytes sobrepostos novamente. A etiqueta `overlay_region` continua `crosses_regions` para manter o diagnóstico fiel.

**Invariante:** nenhum byte de leitura com digest divergente entra na cobertura. Uma leitura fora do overlay contribui zero. A cobertura nunca inclui cabeçalho nem trailer.

## Validação

Foram adicionados cenários unitários inteiramente sintéticos para (1) leitura do overlay inteiro cruzando três regiões e (2) sobreposição com leitura existente e digest deliberadamente falsificado. São testes propostos no PR; a aprovação depende do CI e dos validadores.

## Limites de inferência

Mesmo que `matched_body_unique_bytes == opaque_body_total_bytes`, isso só demonstra consistência de hashes em um manifesto de observação autodeclarado. **Não** demonstra execução original, origem do handle, XOR, equivalência Windows 7 nem certificação. Preservar `LOCAL_HASH_CONSISTENCY_ONLY_NOT_RUNTIME_PROOF` e 0/8 recibos até evidência autêntica independente.

## Próximo ciclo operacional e economia

1. Executar o batch offline já disponível via `python -m tools.rea_parallel_batch` em máquina local com amostra legítima e SHA fixado; reutilizar checkpoint por hash.
2. Capturar `CreateFileA` e `ReadFile` em VM Win7 isolada, com PID, handle, offset, tamanho real e hash do buffer *antes* da transformação; preservar logs e cadeia de custódia.
3. Validar o JSON sanitizado via `python -m tools.rea_runtime_file_correlation` e analisar divergências por intervalo, incluindo leituras cruzando fronteiras.
4. Investigar transformação XOR em contrato separado, com vetores reais de entrada/saída e controle de chave/clock. Recuperar drivers assinados para desbloquear REA-009/010/011.
5. Continuar com testes rápidos no CI padrão e reservar execuções de VM para laboratório controlado; não alegar aceleração percentual sem benchmark.
