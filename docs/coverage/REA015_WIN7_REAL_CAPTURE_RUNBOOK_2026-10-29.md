# REA-015/R — Runbook operacional de captura real Windows 7 SP1

**Estado:** procedimento preparado; **nenhuma captura real anexada ou atestada**.
**Escopo:** ambiente autorizado, VM desconectada de redes externas, snapshots e logs privados.

## 1. Pré-voo (máquina hospedeira e VM)

- [ ] Confirmar autorização sobre a amostra e a execução controlada.
- [ ] Verificar Windows 7 SP1 e arquitetura (x86/x64) e registrar hash da imagem/snapshot.
- [ ] Definir a ausência de rede externa, compartilhamentos, clipboard e pastas compartilhadas.
- [ ] Habilitar snapshots e isolamento; **não** usar a estação de trabalho de produção.
- [ ] Registrar SHA-256 do ZIP e do executável analisado (fora da VM ou sobre cópias preservadas).
- [ ] Guardar relógio UTC, versão dos depuradores e configuração de instrumentação.

PowerShell (Windows 7, disponível quando PowerShell estiver instalado):
```powershell
(Get-WmiObject Win32_OperatingSystem).Caption
(Get-WmiObject Win32_OperatingSystem).OSArchitecture
(Get-WmiObject Win32_OperatingSystem).ServicePackMajorVersion
# Hash local quando certutil oferecer o comando nesta instalação:
certutil -hashfile C:\caminho\arquivo.exe SHA256
```
**Não confiar em `certutil` sem testar sua disponibilidade na imagem específica.** Se indisponível, calcular o hash na hospedeira com ferramenta verificada.

## 2. Captura com duas fontes independentes

### Fonte A — identidade do arquivo e eventos I/O
Monitorar PID, TID, CreateFileA, ReadFile e CloseHandle. Registrar timestamp monotônico, status de retorno, handle efetivo, caminho privado, offset real e `lpNumberOfBytesRead` somente após sucesso.
Process Monitor pode corroborar abertura/caminho e posições, mas **não substitui** observação de handles e bytes retornados.

### Fonte B — buffers e transformação
Depurador ou instrumentação própria autorizada deve capturar **no retorno** de `ReadFile`:
PID, TID, contador de sequência, handle, endereço `lpBuffer`, offset efetivo, bytes lidos e SHA-256 exato dos bytes `[lpBuffer, lpBuffer+bytesRead)`.
Registrar separadamente a entrada/saída **confirmadas por análise de fluxo** da função transformadora: ponteiro de entrada, comprimento e hashes dos conteúdos imediatamente antes/depois. Não presumir que o ponteiro é o mesmo, nem que todas as chamadas aplicam XOR.

Em chamadas síncronas, determinar deslocamento efetivo com controle de posição do arquivo antes da chamada ou do `OVERLAPPED` quando aplicável. Leituras assíncronas e I/O pendente exigem captura no momento da conclusão, não no retorno inicial.

Evitar escrever conteúdo completo, chave, pathname privado ou bytes brutos no repositório. Preservar dados brutos apenas em repositório privado com acesso restrito.

## 3. Identidade, ordem, vínculos e integridade

- [ ] Cada sessão possui identificador de captura e hash de seus logs brutos.
- [ ] Cada evento contém PID/TID, sequência e, quando disponível, tempo monotônico.
- [ ] Confirmar reutilização e fechamento de handles, mapeamento de handle por processo e offset real.
- [ ] Identidade do arquivo aberto comprovada por SHA-256 do conteúdo integral no contexto da VM, além de metadados do arquivo.
- [ ] Registrar a origem do ponteiro e o encadeamento de chamadas, diferenciando alias, cópia e transformação in-place.
- [ ] Vincular o evento de transformação à leitura sem omitir chamadas intermediárias que possam alterar bytes.
- [ ] Registrar operações falhas, retornos zero, loops e caminhos alternativos em log separado.
- [ ] Garantir que timestamps e hash sejam coletados por ferramenta confiável, e que a revisão independente valide a proveniência. JSON auto-relatado não é recibo.

## 4. Correlacionar somente depois da coleta

```bash
python -m tools.rea_runtime_file_correlation \
  --archive /privado/userfreezer.zip \
  --trace /privado/observacao_win7_sanitizada.json \
  --json /privado/correlacao.json

python -m tools.rea_runtime_probe_plan \
  --correlation /privado/correlacao.json \
  --json /privado/sondagens.json

python -m tools.rea_runtime_buffer_diff \
  --pairs /privado/pares.json \
  --json /privado/diferencas.json

python -m tools.rea_runtime_buffer_lineage \
  --trace /privado/lineage.json \
  --json /privado/lineage_resultado.json

python -m unittest discover -s tests -v
python -m tools.rea_progress --check
python -m tools.rea_coverage --check
python -m tools.rea_certification --check
```

## 5. Critérios de aceite e contraprovas

- Abertura do arquivo real com hash igual ao PE `CLOUD_INSTALLER` ou ao overlay: **origem consistente**, exigindo vínculo causal independente para provar execução.
- ReadFile com PID/handle/offset/buffer coerentes: **leitura confirmada somente após auditoria das fontes**.
- Mesmo conteúdo antes/depois da transformação, com controle de mudanças intermediárias: **contrato de transformação candidato**.
- Corpo completo processado e equivalente ao original: exige cobertura de todos os intervalos relevantes e testes com caminhos alternativos; amostras não bastam.
- Divergência de hash, leituras de arquivos não correspondentes, handles ambíguos, offsets incorretos ou buffers modificados de forma não explicada: registrar **hipótese não confirmada**, sem forçar correspondência.

**Não fechar REA-015 com base apenas neste runbook.** Capturas reais = 0 (sem evidência adicional); certificação = 0/8. Não modificar progresso 9/17 por preparar documentação.
