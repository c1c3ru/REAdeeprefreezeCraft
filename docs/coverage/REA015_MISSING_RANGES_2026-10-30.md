# REA-015/P — diagnóstico das lacunas de leitura do corpo

**Data:** 2026-10-30. **Estado:** implementação proposta; nenhuma captura real Win7 apresentada.

## Alteração incremental

O correlator offline agora inclui no JSON de saída os campos `missing_body_unique_bytes` e `missing_body_ranges_overlay_relative`. Cada intervalo é semiaberto `[início, fim)`, em **bytes relativos ao início do overlay**, não ao início do PE embutido. A ferramenta subtrai do corpo `[96, len(overlay)-8)` a união dos intervalos que passaram por SHA-256. Leituras repetidas ou sobrepostas não reduzem a lacuna mais de uma vez; leituras com hash divergente não reduzem lacunas. Nenhum conteúdo binário é escrito.

Esses valores permitem orientar uma captura manual futura sem repetir intervalos já correlacionados no manifesto. São **lacunas de consistência do manifesto**, não prova de que o programa executou ou não executou caminhos específicos. Não substituem cadeia de custódia, testemunho de instrumentação ou verificação independente.

## Critérios

- Python 3.8 e 3.12, testes sintéticos de corpo completo, sem corpo verificado, intervalos sobrepostos e erro de fronteira.
- Manter marcadores de ausência de certificação e zero recibos.
- Execução real Win7, origem do handle e transformação XOR permanecem desconhecidas.
- Sem execução de instalador, drivers, instrumentação ou arquivos proprietários no CI.

## Próxima ação externa

Captura autorizada na VM isolada, preservando PID, handle, offset e SHA-256 dos buffers anteriores à transformação, seguindo o protocolo REA-015/N. Cotejar o resultado no correlator e usar os intervalos ausentes para escolher a próxima observação. REA-009 ainda depende dos drivers legítimos e assinaturas para desbloquear experimentos em x86/x64.
