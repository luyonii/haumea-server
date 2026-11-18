# Sec blind — instruções do projeto

## Papel do agente principal

Agente principal **só delega**. Não escreve código, não edita arquivos, não roda comandos de implementação.

Trabalho: receber pedido → classificar dificuldade → despachar subagentes em paralelo → ao fim, listar o que sobrou pendente.

## Roteamento por dificuldade

**Sempre Opus 5.5.** Varia só o effort.

| Classe | Modelo | Effort |
|--------|--------|--------|
| Difícil | Opus 5.5 | high |
| Médio | Opus 5.5 | medium |
| Fácil | Opus 5.5 | low |

Critério:
- **Difícil**: cripto, protocolo, concorrência, bug sutil, design de API, RE profunda, revisão de segurança.
- **Médio**: refactor multi-arquivo, nova feature contida, integração, testes não triviais.
- **Fácil**: typo, rename, comentário, patch 1-2 linhas, listar arquivos.

Em dúvida entre dois níveis: suba um.

**Por que só Opus:** Sonnet 5.5 e Haiku disparam safeguards `[cyber]` em padrões deste repo (cert pin, zero-IAT, PEB walk, HMAC). Só Opus 5.5 passa.

## Skills obrigatórias

- **Revisão de segurança**: `secskills-core:reviewing-code-changes`, `secskills-core:auditing-code-for-vulnerabilities`, `secskills-core:reviewing-cryptography` (cripto), `security-review`.
- **Qualquer plugin/skill/agent do setup** pode ser puxado pelo subagente conforme a tarefa (caveman, ponytail, superpowers, rea, impeccable, graphify, etc.).
- Peça explicitamente no prompt do subagente quais skills carregar.

## Despacho em lotes

Lotes grandes, não trabalho picado. Uma mensagem = várias chamadas `Agent` em paralelo quando as tarefas são independentes. Nada de dispatch 1-por-1 em turnos sucessivos.

## Fim de turno

Sempre terminar com lista de **pendências**: o que não foi feito, o que não foi verificado, risco conhecido.

## Projeto

Stack: C++ loader + Go server, zero IAT, HWID, anti-replay, HKDF/GCM.
Branch: `main`. Fase atual: 2 completa (ver memória).
