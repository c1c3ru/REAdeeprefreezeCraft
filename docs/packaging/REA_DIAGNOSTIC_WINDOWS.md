# REA Inspector — empacotamento Windows sem instalar o produto

**Estado em 2026-10-31:** primeira versão do ponto de entrada e roteiro de compilação preparados. **O arquivo EXE ainda precisa ser gerado e testado em um ambiente Windows apropriado.** Este artefato é um utilitário de análise offline, NÃO um clone executável do Deep Freeze, não instala drivers, não ativa proteção do disco e não tem equivalência com o produto original demonstrada.

## O que pode rodar em máquina física

Em máquina física moderna, separada do laboratório de engenharia reversa, usar apenas o REA Inspector para verificar *arquivos locais*. O aplicativo tem comandos explícitos: `selfcheck`, `correlate`, `xor-check`, `inspect-output`, `intake`, `import-capture`. Eles não iniciam o instalador do Deep Freeze. Quando esses comandos recebem arquivos originais, manter ZIP, dumps, pares de buffers e chaves apenas em armazenamento privado.

**Não executar o instalador reconstruído, código UPX ainda não recuperado ou drivers desconhecidos em máquina física.** A proteção real de boot/disco é o tipo de operação que pode deixar o Windows inacessível ou os dados indisponíveis. Primeiro validar uma implementação própria de modo independente em VMs isoladas Windows 7 SP1 x86 e x64, com imagens descartáveis, backups, rastreabilidade dos contratos e drivers legítimos assinados.

## Compilar em Windows 10/11 (recomendado para o primeiro EXE)

O PyInstaller não produz executáveis Windows a partir de Linux: o build deve ocorrer **no Windows**. Instalar Python suportado e criar ambiente virtual, sem privilégios elevados desnecessários. Execute na raiz do clone:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install pyinstaller
.\packaging\build_windows.ps1 -Target win10plus
.\out\release\win10plus\REA-Inspector\REA-Inspector.exe selfcheck
```

O PowerShell pode exigir a política de execução apropriada para um script local confiável; não desabilite permanentemente os controles do sistema. O empacotador gera a pasta `out/release/win10plus/REA-Inspector/`. **Copie a pasta completa**, incluindo o executável e suas dependências. É modo `--onedir`, mais observável e simples para depuração do que um pacote `--onefile` que se extrai temporariamente.

**O comando `selfcheck` só testa inicialização e reporta o ambiente. Ele retorna explicitamente que Windows 7 e equivalência semântica NÃO foram verificados.**

## Build candidato ao Windows 7 (somente em laboratório)

Para compatibilidade Windows 7, a documentação oficial do Python aponta **Python 3.8**, já fora de suporte de segurança. A documentação do PyInstaller 5.13.2 informa que o Windows 7 *pode* funcionar, mas sem suporte oficial (Windows 8+ era o suportado). Portanto, o EXE deve ser construído em ambiente isolado e **testado efetivamente** em duas VMs Win7 SP1 x86 e x64, sem supor que um build em Windows 10/11 funcionará.

```powershell
py -3.8 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install pyinstaller==5.13.2
.\packaging\build_windows.ps1 -Target win7-x86
```

Na VM/build Windows x64, usar Python 3.8 x64 e `-Target win7-x64`. Para x86, usar Python 3.8 **de 32 bits**. O script rejeita arquitetura incorreta e verifica a versão do PyInstaller antes do build. Os runtimes Visual C++/UCRT necessários no destino precisam ser conferidos; não instalar redistribuíveis nem atualizar o sistema de produção sem aprovação explícita.

## Exemplo: primeira análise offline

```powershell
.\out\release\win10plus\REA-Inspector\REA-Inspector.exe --help

.\out\release\win10plus\REA-Inspector\REA-Inspector.exe correlate --archive C:\privado\userfreezer.zip --trace C:\privado\trace.json --json C:\privado\correlacao.json

.\out\release\win10plus\REA-Inspector\REA-Inspector.exe inspect-output --artifact C:\privado\saida.bin --expected-sha256 SHA256_CONFIRMADO --capture-id LAB-001 --json C:\privado\triagem.json
```

O `correlate` exige evidência de `ReadFile` coletada na VM; um arquivo de exemplo não comprova execução. O `xor-check` também exige pares pré/pós reais, sem publicar bytes em HEX. Não subir amostra original, drivers, chaves, traces privados nem arquivos de saída recuperados ao repositório público.

## Gates antes de considerar distribuível

1. Testar ponto de entrada e todos os comandos com dados sintéticos sem tocar no disco protegido.
2. Compilar localmente no Windows; registrar Python, PyInstaller, arquitetura, hash SHA-256 e dependências empacotadas.
3. Rodar `selfcheck`, `--help` e casos de uso read-only em Windows físico sem privilégios elevados; confirmar que não há instalação de drivers ou serviços.
4. Para Win7, validar **compatibilidade do utilitário** nas VMs x86/x64. Separadamente, recuperar módulos/driver, conduzir testes da reconstrução e avaliar equivalência antes de qualquer ensaio físico invasivo.
5. Publicar EXE somente após revisão de segurança e verificação de não inclusão de dados proprietários e privados.

Os status gerais permanecem **9/17 entregas e 0/8 recibos**. Empacotamento de ferramentas != implementação funcional != certificação do produto.

### Referências técnicas

- Python: https://docs.python.org/3/using/windows.html
- PyInstaller manual: https://pyinstaller.org/en/stable/
- Compatibilidade do PyInstaller 5.13.2: https://pypi.org/project/pyinstaller/5.13.2/
