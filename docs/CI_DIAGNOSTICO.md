# Diagnóstico de CI — REAdeeprefreezeCraft

**Revisão:** 2026-10-28  
**Escopo:** workflow `.github/workflows/ci.yml`, GitHub Actions, Python 3.8 e 3.12.

## Qual execução é a referência?

Verificar **o SHA e a branch do check**: o resultado mais novo de `main` pode estar verde embora runs antigos ainda mostrem o ícone vermelho no histórico. Um PR já integrado não vira um PR aberto por causa do histórico de falha.

- Commit de referência anterior à manutenção: `80927639ec18605ce6efbc5d51db6bf61299f649`; [workflow em main aprovado](https://github.com/c1c3ru/REAdeeprefreezeCraft/actions/runs/40730980752).
- [PR #15 integrado](https://github.com/c1c3ru/REAdeeprefreezeCraft/pull/15); seu [workflow de PR](https://github.com/c1c3ru/REAdeeprefreezeCraft/actions/runs/40730896064) concluiu com sucesso.
- [Workflow vermelho antigo #40722288005](https://github.com/c1c3ru/REAdeeprefreezeCraft/actions/runs/40722288005) (PR #14): a árvore do PR deixou de incluir `tools/rea_contract_trace.py` e o teste de consistência relatou `Missing evidence`. Corrigido no commit posterior do mesmo PR; [run posterior aprovado](https://github.com/c1c3ru/REAdeeprefreezeCraft/actions/runs/40722487854).
- [Workflow vermelho antigo #40710961776](https://github.com/c1c3ru/REAdeeprefreezeCraft/actions/runs/40710961776) (PR #6): a suíte tentou importar `fixture_with_calls` em vez de `fixture_with_call`. Corrigido no mesmo PR; [run posterior aprovado](https://github.com/c1c3ru/REAdeeprefreezeCraft/actions/runs/40711259730).

## O falso erro visual em uma suíte aprovada

O teste `test_check_detects_stale_document` **fabrica deliberadamente** um documento de status inconsistente, verifica que o comando `--check` devolve código 1 e inspeciona a mensagem. Na implementação anterior, o erro esperado escapava ao `stderr`, fazendo o log de um job verde conter `REA progress ERROR: Status desatualizado`.

**Correção:** capturar `stdout`/`stderr` do teste esperado e confirmar o conteúdo dentro do próprio teste. Uma falha genuína do comando executado no passo `Validate REA action plan...` continua fazendo o job ficar vermelho.

## Manutenção preventiva do workflow

Substituir `actions/checkout@v4` e `actions/setup-python@v5` por versões que usam Node.js 24, reduzindo os avisos de depreciação no GitHub Actions. Continuar rodando a matriz **Python 3.8 e 3.12** com fixture PE sintética, sem binários de terceiros. Exigir runner moderno compatível com ações Node.js 24; os runners hospedados pelo GitHub passam por atualização pela plataforma.

O job gera resumo simples: testes do código próprio aprovados, checkpoint documental sincronizado e Windows 7 **não testado**. A atualização dos actions não é uma validação de driver.

## Reproduzir a verificação

```bash
python -m compileall -q tools tests
python -m unittest discover -s tests -v
python -m tools.rea_progress --check
```

Se houver um **novo workflow vermelho**, abrir o run e conferir o primeiro passo que falhou, o SHA e a branch exatos antes de corrigir. Não reinterpretar o histórico de falha de um commit antigo como falha da branch atual.
