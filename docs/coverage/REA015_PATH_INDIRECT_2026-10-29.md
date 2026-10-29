# REA-015/M — Proveniência do pathname e limites da busca de chamadas indiretas

**29/10/2026 · [Issue #17](https://github.com/c1c3ru/REAdeeprefreezeCraft/issues/17) · Estado: evidência estática parcial; inventário aberto.**

## Novo vínculo com as APIs Win32

No binário principal `DFStd.exe` SHA-256 `2d7c171d4037660843a7e02c055679c5a26904af84d48fc8c557a67023f55c8b`, a desmontagem permite ligar **o mesmo ponteiro de caminho** de uma função chamadora a verificações de atributos e à posterior abertura de arquivo:

| VA | Papel |
|---|---|
| `0x00467CB8..0x00467CC0` | encaminha `[EBP+0x0C]` para a função `0x00467CF8`, cujo argumento de pathname é o segundo parâmetro |
| `0x00467D06` | copia `[EBP+0x0C]` para `EDI`, preservando a origem do caminho |
| `0x00467D0E/0F` | passa `EDI` a `KERNEL32.DLL!GetFileAttributesA`, thunk `0x00900E6A`, IAT `0x00A16820` |
| `0x00467D1B..0x00467D21` | se a consulta retornar atributos válidos, passa o mesmo `EDI` a `SetFileAttributesA` com argumento `0x80` (atributos normais); thunk `0x0090110A`, IAT `0x00A169C8` |
| `0x00467D3E..0x00467D45` | encaminha novamente `EDI` ao construtor `0x00750F1C` e passa string-chave nula |
| `0x00750B92..0x00750BB8` | encaminha caminho ao buffer `[owner+0xDC]` e ao wrapper de abertura |
| `0x00752570..0x0075258A` | recusa ponteiro nulo ou string vazia e chama `0x00752234` para caminho válido |
| `0x007522C8..0x007522CC` | passa ponteiro `lpFileName` a `KERNEL32.DLL!CreateFileA` (IAT `0x00A1675C`), que retorna o handle rastreado na REA-015/I |

**Portanto:** o ponteiro utilizado para `GetFileAttributesA` e `SetFileAttributesA` é encaminhado à família de rotinas que alcança `CreateFileA`. **Isso não permite recuperar o conteúdo textual do pathname de execução.** Um caminho pode vir do chamador e depender de parâmetros de runtime; nenhum nome fixo é demonstrado aqui.

## Segunda fonte de pathname: campo de estrutura

A chamada em `0x00437241` encaminha um pathname obtido por `0x00407334`. O código prepara `[objeto+0x2C]`, e o helper lê o primeiro ponteiro dessa estrutura. Se ele estiver nulo, devolve o endereço `0x0090E06A`, correspondente a uma **string C vazia** no binário original. Se não estiver nulo, devolve o ponteiro armazenado. Esse ramo **não prova** qual string não nula é utilizada nem demonstra sua relação com o recurso `CLOUD_INSTALLER`.

## Chamadas indiretas: o que foi e não foi medido

A ferramenta `tools/rea_path_indirect_scope.py` fixa **39 âncoras de opcode** e **10 arestas CALL rel32**, além de resolver as quatro importações Win32 por IAT. Também inspeciona **oito janelas de instruções delimitadas** (somatório de **471 bytes**) na cadeia de pathname. Nessas janelas foram observados **zero padrões de bytes `FF /2` e `FF /4`** candidatos a CALL/JMP indiretos.

Essa observação é **estritamente local**. Um scanner de bytes `FF` não é um decodificador x86 completo; mais importante, não foram examinados exaustivamente callbacks, vtables, indireções de todos os módulos nem regiões compactadas. A existência de zero candidatos nas janelas **não significa ausência global de chamadas indiretas**.

## Evidência ainda necessária para fechar a identidade

O resultado atual identifica proveniência **estática** de ponteiros, não o arquivo efetivamente aberto. Para demonstrar a identidade do arquivo na execução original são necessárias observações em VM isolada do **mesmo evento CreateFileA/ReadFile**, correlacionando:

- hash e versão do PE carregado e a arquitetura da VM;
- endereço da chamada, caminho real sanitizado, hash do conteúdo do arquivo no momento da abertura e handle retornado;
- leituras e offsets observados para o mesmo handle, inclusive cabeçalho e dados após 96 bytes;
- comparação dos hashes dos bytes lidos com o overlay original conhecido, considerando offsets, sem inferir equivalência de payload por coincidência isolada de marcadores;
- logs sanitizados, hashes e recibos revisados/assinados conforme [política de certificação](../certification/CERTIFICATION_POLICY.md).

**Nada disso foi executado neste subciclo**. Não foi confirmado que o handle aponte ao CLOUD_INSTALLER ou que o XOR processe os 7.836.705 bytes do corpo. UPX, drivers e equivalência Windows 7 x86/x64 continuam pendentes; certificação **NÃO CERTIFICADA**.

## Reproduzir e testar

```bash
python -m tools.rea_path_indirect_scope --archive /caminho/para/userfreezer.zip --json rea015_m_local.json
python -m unittest discover -s tests -v
python -m tools.rea_progress --check
python -m tools.rea_coverage --check
python -m tools.rea_certification --check
```

Nenhum binário proprietário, arquivo de instalação ou conteúdo extraído foi versionado. A suíte CI utiliza somente testes sintéticos.
