# REA — aceleração com engenharia de loop e trilhas paralelas

**29/10/2026** · Deep Freeze Standard 9.00.020.5760 · **NÃO CERTIFICADO.**

## Decisão operacional

Acelerar é **reduzir retrabalho**, executar análises independentes em paralelo e atacar primeiro os bloqueios críticos. Não significa transformar testes sintéticos em prova de equivalência. No momento o projeto possui **9/17 entregas concluídas** e **0/8 recibos assinados de certificação**.

Há **dois caminhos críticos P0** que devem avançar em paralelo: **REA-009** (drivers reais, atualmente bloqueada, habilita testes Win7 e contratos) e **REA-015** (reconstrução do recurso CLOUD_INSTALLER e origem do arquivo lido, habilita REA-016). As dependências REA-010/011/012/013/017 não devem ser marcadas como feitas antes de evidências reais.

## Quatro trilhas simultâneas

| Trilha | Trabalho | Critério de aceite |
|---|---|---|
| A — Estática | Inventário PE/UPX/drivers na amostra original, overlay, imports, xrefs, parâmetros | JSONs íntegros por hash; anomalias investigadas; **não** certifica código oculto |
| B — Laboratório | VMs isoladas e autorizadas Win7 SP1 x86 e x64; origem real do arquivo, buffers, drivers e assinaturas | Capturas de PID, handle, offset, hash; logs e origem verificável por plataforma |
| C — Semântica | Contratos de funções, reconstrução local e comparação diferencial | Resultados originais e reimplementados com casos positivos, negativos e limites |
| D — Evidências | CI, documentação central, hash dos resultados, revisão externa e certificados | Checkpoints auditáveis; assinatura autêntica, sem declarar conclusão antecipada |

Os analistas devem trabalhar em saídas separadas. Somente a integração revisada atualiza os documentos centrais, para evitar corrida de commits no mesmo arquivo. Até **3 subprocessos** por padrão para reduzir concorrência de memória/ZIP; no máximo 4 se o hardware comportar. Mais paralelismo pode piorar o desempenho por custo de I/O e memória.

## Automação efetivamente implementada

O comando de uso local abaixo utiliza ferramentas Python já existentes no repositório. A ferramenta de lote confere **antes de executar** o SHA-256 original do ZIP, aceita apenas uma lista explícita de módulos, executa processos isolados em paralelo e atualiza o checkpoint local **a cada job concluído**.

    python -m tools.rea_parallel_batch \
      --archive /caminho/privado/userfreezer.zip \
      --output-dir /caminho/privado/rea-batches/ciclo-o \
      --jobs 3

A repetição da mesma linha reaproveita tarefas válidas, desde que o SHA-256 do resultado JSON, o hash da amostra, a versão do Python e o hash de **todos os fontes tools/*.py** não tenham mudado. Saídas adulteradas ou faltantes são recalculadas. Falhas de um job não fazem outros desaparecerem; o lote termina com erro se houver falhas.

O arquivo STATUS_BATCH.json e os JSONs individuais ficam **fora do Git**, no diretório local de resultados. A ferramenta não executa o instalador Windows, não instala drivers, não descompacta automaticamente o corpo, não cria recibos e não fecha issues.

Para focar somente três hipóteses:

    python -m tools.rea_parallel_batch \
      --archive /caminho/privado/userfreezer.zip \
      --output-dir /caminho/privado/rea-batches/foco \
      --tasks rea_overlay_inventory rea_overlay_reader_trace rea_overlay_handle_flow \
      --jobs 2

### Verificar se realmente acelerou

Comparar lotes equivalentes com cache desativado, mesma máquina, mesma amostra e mesma versão de Python:

    python -m tools.rea_parallel_batch --archive /caminho/privado/userfreezer.zip \
      --output-dir /caminho/privado/rea-batches/serial --jobs 1 --no-resume

    python -m tools.rea_parallel_batch --archive /caminho/privado/userfreezer.zip \
      --output-dir /caminho/privado/rea-batches/paralelo --jobs 3 --no-resume

Verificar **tempo total e igualdade dos hashes das saídas de cada analisador**, não apenas os tempos. Não inventar fator de speed-up. O CI atual já testa centenas de casos Python rapidamente: adicionar fragmentação em muitos jobs não ajuda necessariamente e acarreta overhead. Por isso a aceleração foi aplicada à **análise do sample original em ambiente local**, não à divisão da suíte pequena de CI.

## Bloqueio principal: evidência original em Windows 7

Foi confirmado localmente que o ZIP original está disponível e seu SHA-256 é:

    f2e1a70e3becff235c886c6092d3d8a5928404bbe43f9c0c6360e428daa64671

O ambiente desta execução não contém QEMU, VirtualBox, Wine ou UPX, e o projeto **não dispõe de captura real de CreateFileA/ReadFile**. Portanto o ganho obtido neste ciclo é preparação/automação **estática**, não equivalência dinâmica.

**Atividade que desbloqueia mais etapas:** em VM Win7 SP1 isolada e autorizada, registrar o caminho aberto, PID, handle, SHA-256 do arquivo e hashes dos buffers retornados por ReadFile com seus offsets, preservando logs de origem. Verificar os dados com a ferramenta rea_runtime_file_correlation.py e, quando houver observação autenticada, relacionar o conteúdo realmente lido ao recurso CLOUD_INSTALLER. Em paralelo, recuperar de instalação legítima os drivers .sys e respectivos catálogos/assinaturas, sem versionar os binários proprietários. Executar os cenários x86 e x64 separadamente.

## Loop verificável por PR

1. Definir hipótese falsificável e denominador dos artefatos, com critério de aceite antes de executar.
2. Analisar arquivos originais somente de modo estático e independente onde isso é possível; guardar SHA e checkpoint dos resultados.
3. Investigar diferenças ou falhas; distinguir resultados sintéticos de observações originais.
4. Validar teste e documentação (Python 3.8/3.12, progresso, cobertura, certificação); não aceitar CI quebrado.
5. Integrar PR apenas depois de garantir **zero remoções** de evidências e que o documento central foi sincronizado.
6. Registrar issue e próximo bloqueio. Não preencher prova ausente com valores imaginados.
7. Só emitir certificado depois dos **oito portões assinados** e da verificação de chaves externas conforme docs/certification/CERTIFICATION_POLICY.md.

## Próximos ciclos priorizados

**P0 imediato:** executar batch real offline; se houver divergências entre analisadores, corrigir com testes e registrar. **P0 externo:** montar ambiente legítimo Win7/recuperar drivers REA-009 e criar captura para REA-015. **P0 estrutural:** recuperar módulos/código UPX e classificar CFG em REA-016. **P1 semântico:** gerar vetores originais e diferenciais de REA-012/017. **P1 auditoria:** preencher recibos por evidência real, jamais por mera conclusão administrativa.

**Critério atual:** NÃO CERTIFICADO; resultados de analisadores estáticos e CI verde não provam a execução do produto ou a cobertura integral do sistema.
