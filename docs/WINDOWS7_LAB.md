# Matriz de compatibilidade — Windows 7 SP1

**Status:** planejamento; nenhum teste dinâmico foi realizado nesta etapa.

## Ambiente obrigatório

| Dimensão | Variante mínima | Evidência exigida |
|---|---|---|
| Sistema | Windows 7 SP1 x86 | Build, arquitetura, snapshot inicial |
| Sistema | Windows 7 SP1 x64 | Build, arquitetura, snapshot inicial |
| Assinatura | SHA-2, KB4474419 / KB4490628 quando aplicáveis | Registro de atualizações e verificação de assinatura |
| Disco | NTFS, VM sem dados reais | Geometria, modo de boot, snapshot |
| Estado | Frozen / Thawed | Registro dos estados antes/depois do reinício |
| Falha | Interrupção de alimentação simulada | Integridade da VM e plano de restauração |
| Remoção | Desinstalação e reboot | Inicialização sem componentes remanescentes |

## Critérios

1. Confirmar proveniência e assinatura **antes** de qualquer instalação.
2. Executar cenários em VMs descartáveis isoladas, nunca em estações produtivas.
3. Medir persistência de arquivos e chaves de registro em volumes protegidos e persistentes.
4. Capturar logs, versões e hashes dos drivers realmente carregados; não deduzir carregamento apenas de strings.
5. Validar transições de estado, falhas de boot e restauração por snapshots.
6. Não declarar compatibilidade aprovada sem evidência separada para x86 e x64.

## Resultados

- [ ] Windows 7 SP1 x86 validado
- [ ] Windows 7 SP1 x64 validado
- [ ] Assinaturas de drivers verificadas
- [ ] Estados Frozen/Thawed observados
- [ ] Integridade após reinicialização validada
- [ ] Desinstalação sem falhas validada
