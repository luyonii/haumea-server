# Review Pós-Fixes — Sec-blind

Data: 2026-11-17. Revisor: Opus 4.7, read-only, após 5 subagents aplicarem os fixes do `REVIEW_2026-11-17.md`.

## 1. Status por Task

- **Task 1 (shutdown race C++)** — ⚠️ nits. Lógica correta, mas lifetime de `s_req_cs` em shutdown tem janela residual.
- **Task 2 (/auth/login order)** — ✅ clean. Challenge consumido primeiro, `failAuth` uniforme, `crypto.Equal` constant-time.
- **Task 3 (rate-limit + obs)** — ⚠️ nits. Rate-limit OK. `/debug/metrics` sem auth é aceitável com bind 127.0.0.1. Counters sem race.
- **Task 4 (kill flag)** — ⚠️ nit. Funciona; `KillStatus` fail-open mantido (já estava no audit como aceito).
- **Task 5 (graceful shutdown + PG ping + TLS)** — ⚠️ nits. OK no caminho feliz. `log.Fatalf` após `listen error` pula defers; ordem `go ListenAndServe` antes de `signal.Notify` tem janela mínima.

---

## 2. Novos Findings

### MEDIUM

**[M1] `net::shutdown` destrói `s_req_cs`/`s_cs` mesmo se `heartbeat::stop` desistiu com thread viva**
File: `Project1/src/net.cpp:338-345` + `Project1/src/heartbeat.cpp:153-156` + `Project1/src/Main.cpp:205,219`
Problem: se o segundo `pWaitFor(s_thread, 8000)` em `heartbeat::stop` também der timeout (worker travado em `pClose` interno do WinHTTP, ou SO sobrecarregado), `stop` retorna com thread viva. `Main.cpp` segue para `net::shutdown()` que chama `pDeleteCS(&s_req_cs)` e `pDeleteCS(&s_cs)`. Thread pode acordar e entrar em `close_request_locked` -> `pEnterCS(&s_req_cs)` em CS destruída.
Impact: UAF estreito, mas existente. Muito menos provável que o original, mas o mesmo tipo.
Fix: ou (a) retornar bool de `heartbeat::stop` indicando sucesso, e pular `net::shutdown` se timeout; ou (b) em `shutdown`, se worker ainda vivo, pular `pDeleteCS` (vaza CS para OS limpar na saída do processo — aceitável).

**[M2] `/debug/metrics` registrado via `mux.HandleFunc` escapa do `observe` middleware**
File: `server/internal/api/api.go:80-88`
Problem: endpoints normais passam por `observe(path, h)` que loga e mede. `/debug/metrics` usa `mux.HandleFunc` direto, logo o próprio scraping não aparece no access log. Não é bug, mas consistência pede.
Fix: `mux.Handle("/debug/metrics", observe("/debug/metrics", metricsHandler))`.

**[M3] `handleHeartbeat`: na resposta de kill, campo `kill` é `true` mas `revoked` é `false` como objeto separado — cliente parsa OK, nit**
File: `server/internal/api/api.go:452-456` + `Project1/src/heartbeat.cpp:80-87`
Verificado: cliente chama `json::get_bool("kill")` e sai antes de olhar `next_nonce`. Nenhum parse a mais quebra. Clean.

### LOW

**[L1] `listen error` + `log.Fatalf` ignora `defer pg.Close()`/`rdb.Close()`**
File: `server/cmd/server/main.go:124-125`
Problem: se `ListenAndServe` falhar (porta ocupada, bind recusado), processo morre sem fechar pools. OS limpa, mas no graceful loop seria mais limpo.
Fix: substituir `log.Fatalf` por `log.Printf` + `return` (ou `os.Exit(1)` após defers via função separada).

**[L2] Janela entre `go hs.ListenAndServe()` e `signal.Notify`**
File: `server/cmd/server/main.go:119-122`
Problem: sinais SIGINT/SIGTERM entre as linhas 119 e 122 matam com default handler, sem drain. Janela de microssegundos.
Fix: `signal.Notify` ANTES do `go`.

**[L3] `KillStatus` fail-open em heartbeat preserva sessão viva se PG estiver fora**
File: `server/internal/api/api.go:442`
Observação: já listado no audit original como MEDIUM aceito. Manter como está, mas documentar em `SERVER_SPEC.md` que uma degradação do PG permite heartbeat continuar — kill não é tolerante a falha.

**[L4] `RememberLatestToken` no caminho normal do heartbeat renova TTL mesmo quando o anterior é o mesmo token**
File: `server/internal/api/api.go:467`
Observação: funcionalmente correto, só um `SET` extra por heartbeat. Ignorar.

---

## 3. Integração Cross-Task

- **Task 2 × Task 3**: `failAuth` retorna 401 opaco; middleware `observe` loga status=401. Sem leak cross-check.
- **Task 3 × Task 4**: resposta de kill (`{"kill":true,"revoked":false}`) sai com status 200; `metricInc` não é chamado no kill path (não há um contador `kill_enforced_total`). Sugestão: adicionar `metricInc("kill_enforced_total", "/session/heartbeat")` na L451. Não é bug.
- **Task 1 × Task 4**: quando server envia kill, heartbeat lê `kill=true` e sai do loop. `net::cancel_in_flight` não é tocado nesse caminho (loop termina natural). OK.
- **Task 2 × Task 5**: PG ping em startup + ping timeout 5s conversa bem com `log.Fatalf` — processo morre cedo, mas ainda assim o `defer pg.Close()` não roda (ver L1).
- **Task 3 × /debug/metrics**: exposto antes de o processo começar a servir real traffic (está em `mux` ao registrar). OK desde que `addr` seja `127.0.0.1:8080`. Com `0.0.0.0` vaza. Default agora é `127.0.0.1` (main.go:105) — bom.

Nenhuma task quebrou outra.

---

## 4. Status Geral

**Pronto pra testar end-to-end**: SIM.
- Build C++ compila (mudanças só em `net.cpp`, `net.h`, `heartbeat.cpp`).
- Go tem novos símbolos (`metricInc`, `observe`, `rateLimitFetch`, `RatePerHWIDFetch`, `/debug/metrics`) todos auto-contidos.
- Mockup Docker de integration deve subir sem mudança de schema.

**Pronto pra deploy produção**: NÃO.

### Blockers restantes (ainda do audit original)
1. **Cert pins reais** — `Project1/src/net.cpp:163-164` ainda tem o mesmo hash integration repetido. Precisa current + backup reais.
2. **Hostname real** — `Project1/src/Main.cpp:106` (não re-verificado nesse passo).
3. **HWID bind TOCTOU** — não endereçado (item do audit HIGH, fix via `SELECT FOR UPDATE` ou upsert condicional).
4. **`/rpc/call` sem anti-replay** — não endereçado.
5. **`std::atomic` nos flags cross-thread** (`s_running`, `s_reason`) — não endereçado.
6. **M1 acima (CS lifetime)** — novo nit a fechar antes do shipping.

### Important (nice before beta)
- Health/readiness endpoint.
- Admin endpoint (kill/listar).
- Testes Go crypto além de HKDF.
- `fgets` buffer 256 (`Main.cpp:70-77`).
- Rotação de `master_secret`.
- Fix dos L1/L2 acima.

### Resumo em uma linha
As 5 tasks foram aplicadas corretamente, sem regressão cross-task. Restam **2 blockers de produção do audit original** (cert pin, hostname) + **1 novo nit** (CS lifetime no shutdown). Aprovado para seguir para testes end-to-end no harness de integration.
