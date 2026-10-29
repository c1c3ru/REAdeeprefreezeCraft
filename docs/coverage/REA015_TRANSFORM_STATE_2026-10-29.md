# REA-015/J — Origem da flag, seleção de quatro DWORDs e byte XOR

**29/10/2026** · [REA-015 #17](https://github.com/c1c3ru/REAdeeprefreezeCraft/issues/17) · **Conclusão:** subciclo de semântica *local*, não inventário global concluído.

## Evidências na amostra original

O executável `Faronics_DFS/DFStd.exe`, SHA-256 `2d7c171d4037660843a7e02c055679c5a26904af84d48fc8c557a67023f55c8b`, foi desmontado offline. Foram conferidas **74 instruções âncora x86 por endereço e bytes de máquina**, com **zero divergências**, e **sete destinos de chamadas relativas**. A ferramenta `tools/rea_transform_state.py` executa essas verificações contra a amostra fixada por hash. Não executa binário proprietário, drivers ou `ReadFile` real.

### 1. De onde vem a flag

| VA | Operação estática verificada |
|---|---|
| `0x00750B1A` | inicializa `[owner+0xA4] = 9` |
| `0x00750C19` | aceita configuração DWORD e a grava em `[owner+0xA4]` |
| `0x00750C2C..0x00750C56` | constrói `[owner+0xA4]` a partir de opções Booleanas nos bits 3 e 0 |
| `0x00750616` | lê `[owner+0xA4]` |
| `0x0075061C` | aplica máscara `0xFFFFFFF7`, apagando apenas o bit 3 |
| `0x0075061F` | grava o resultado em `[owner+0x60]` |
| `0x0074FD71` | testa o bit 0 de `[owner+0x60]` antes da transformação |

Assim, o valor de inicialização **9 torna-se 1** após a máscara e preserva o bit que habilita o caminho do XOR. Isso **não estabelece o valor que será usado em uma instalação real**: as outras rotinas podem alterar a configuração antes da leitura.

### 2. Proveniência e seleção dos quatro parâmetros

- Em `0x00750B38..0x00750B43`, a função recebe uma string por argumento de chamador, passa `[owner+0xBC]` como destino e chama `0x0074F804` para gerar quatro DWORDs. A rotina zera quatro palavras e mistura caracteres, deslocamentos e XOR.
- Em `0x00750C7D..0x00750C84`, uma rota alternativa chama a mesma função para produzir os quatro DWORDs em `[owner+0xAC..0xB8]`. A origem completa dessa segunda string não está certificada.
- Em `0x00750504..0x00750551`, se **todos** os quatro DWORDs de `[owner+0xBC..0xC8]` são zero, o código copia o conjunto alternativo de `[owner+0xAC..0xB8]`. Caso contrário, copia o primeiro conjunto. Ambos convergem para `[owner+0xCC..0xD8]`, repassado à transformação após `ReadFile`.

A análise **não contém os quatro DWORDs empregados na execução real** nem comprova que o conteúdo do overlay os utilize.

### 3. Modelo aritmético delimitado do byte aplicado por XOR

O fluxo `0x0074F728 → 0x0074F87C → 0x0074F8AC → 0x0074F8D4` revela operações suficientes para escrever um modelo **apenas de teste sintético**. Uma condição inicial verifica se os quatro DWORDs são todos zero; também há uma seleção pelo modo de estado igual a 1.

Quando o caminho alcança a rotina XOR, `0x0074F728` combina os quatro DWORDs por XOR e dobra esse resultado com um deslocamento aritmético de 16 bits. Para cada posição `i`, a rotina de byte utiliza a soma de 16 bits com o índice, uma divisão inteira **com sinal por 177**, uma cadeia de `LEA` equivalente a multiplicar o resto por **171**, depois um resultado aritmético multiplicado por **32.767**. Por último, XOR dos bytes baixo e alto da palavra resultante produz o byte em AL, que é aplicado por `xor byte [esi],al`.

Uma interpretação matematicamente reproduzível da sequência é:

```text
seed = XOR4(words) XOR (signed32(XOR4(words)) >> 16)
x = signed16((seed_low16 + position_low16) mod 65536)
q = trunc_toward_zero(x / 177)
r = x - q * 177
w = ((171 * r - 2 * q) * 32767) mod 65536
key_byte = low8(w) XOR high8(w)
```

Em um vetor de teste **artificial**, seed zero e posições 0, 1, 2 e 3 produzem os bytes `00 2A 54 82`. Isso valida a **implementação do modelo**, não uma comparação dinâmica com a rotina original em Windows.

## Ferramenta e regressão

```bash
python -m tools.rea_transform_state --archive /caminho/para/userfreezer.zip --json rea015_state_local.json
python -m unittest discover -s tests -v
python -m tools.rea_progress --check
python -m tools.rea_coverage --check
```

Os testes são exclusivamente sintéticos: valor padrão 9, setters Booleanos, escolha/fallback de DWORDs, sinal de `IDIV`, propagação de carry de 16 bits, vetores de posições e reversibilidade do XOR de bytes artificiais. A ferramenta **não recebe nem transforma o corpo original** como um argumento de decodificação.

## Bloqueios restantes

**REA-015 permanece aberta**. Falta comprovar a origem efetiva das strings/parâmetros em execução, associar inequivocamente o fluxo ao recurso CLOUD_INSTALLER e validar o corpo real de 7.836.705 bytes. Também faltam o código original dos módulos UPX, binários completos de driver, denominadores globais, equivalência semântica e validações Windows 7 SP1 x86/x64.

O próximo ciclo deve rastrear a origem das strings e estados na cadeia de inicialização e validar a interpretação aritmética em um laboratório controlado, antes de atribuir o protocolo ao overlay.
