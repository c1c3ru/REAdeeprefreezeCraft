# REAdeeprefreezeCraft

Laboratório de **engenharia reversa auditável** para análise de componentes de proteção e restauração de sistemas Windows. O projeto começa com a inspeção estática de um pacote do **Faronics Deep Freeze Standard 9.00.020.5760**.

> Este repositório **não** distribui binários ou código-fonte proprietário, não altera mecanismos de licenciamento e **não** disponibiliza uma implementação funcional do Deep Freeze. Os achados não equivalem a uma auditoria dinâmica nem à comprovação de compatibilidade com Windows 7.

## Primeira entrega

- [Relatório REA 9.00.020.5760](docs/analyses/DeepFreeze_9.00.020.5760.md) — identificação do binário, hashes, componentes, limitações e riscos.
- [Matriz de testes Windows 7](docs/WINDOWS7_LAB.md) — requisitos de laboratório e critérios de aceite.
- [Roadmap](docs/ROADMAP.md) — fases de inventário, análise estrutural e validação semântica.
- `tools/rea_inventory.py` — inventário **sem extrair ou executar** entradas ZIP, SHA-256, cabeçalhos PE e referências de strings.
- `tests/` — testes automatizados com arquivos sintéticos; sem incluir executáveis comerciais.
- `tools/rea_structural.py` — importações PE, árvore de recursos, PE embutidos, strings de drivers e mapa de interfaces.
- [Evidências estruturais](docs/analyses/STRUCTURAL_2026-10-28.md) e [fronteiras usuário/kernel](docs/INTERFACES_USER_KERNEL.md).

## Executar localmente

Requisito: **Python 3.8+**, sem dependências de terceiros (execução do analisador também em Linux).

```bash
python -m unittest discover -s tests -v
python tools/rea_inventory.py /caminho/para/userfreezer.zip --output inventario.json
python -m tools.rea_structural --archive /caminho/para/userfreezer.zip --json estrutura.json --markdown interfaces.md
```

O arquivo `inventario.json` é gerado apenas localmente. **Não faça commit do ZIP, dos drivers originais, de chaves ou de dados pessoais.** O inventário rejeita arquivos grandes e caminhos suspeitos; o retorno `2` indica entradas ignoradas por segurança.

## Compatibilidade e escopo

A compatibilidade **Windows 7 SP1 x86/x64** é requisito do projeto; o analisador utiliza Python 3.8 para não exigir versões recentes do interpretador. O driver e qualquer futura implementação Windows precisam de testes independentes: executar o script não demonstra compatibilidade do produto comercial nem da proteção em modo kernel.

Toda hipótese precisa ser rotulada como **observada**, **inferida** ou **a validar**. Testes de sistema deverão ocorrer apenas em máquinas virtuais descartáveis com snapshots e backups.
