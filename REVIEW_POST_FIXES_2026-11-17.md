# Post-Fix Review — Sec-blind

Date: 2026-11-17. Reviewer: Opus 4.7, read-only, after 5 subagents applied the fixes from `REVIEW_2026-11-17.md`.

## 1. Status per Task

- **Task 1 (C++ shutdown race)** — ⚠️ nits. Logic correct, but `s_req_cs` lifetime at shutdown has a residual window.
- **Task 2 (/auth/login order)** — ✅ clean. Nonce consumed first, uniform `failAuth`, `crypto.Equal` constant-time.
- **Task 3 (rate-limit + obs)** — ⚠️ nits. Rate-limit OK. `/debug/metrics` without auth is acceptable with 127.0.0.1 bind. Counters race-free.
- **Task 4 (kill flag)** — ⚠️ nit. Works; `KillStatus` kept fail-open (already in the audit as accepted).
- **Task 5 (graceful shutdown + PG ping + TLS)** — ⚠️ nits. OK on the happy path. `log.Fatalf` after `listen error` skips defers; `go ListenAndServe` before `signal.Notify` has a tiny window.

---

## 2. New Findings

### MEDIUM

**[M1] `net::shutdown` destroys `s_req_cs`/`s_cs` even if `heartbeat::stop` gave up with the thread alive**
File: `Project1/src/net.cpp:338-345` + `Project1/src/heartbeat.cpp:153-156` + `Project1/src/Main.cpp:205,219`
Problem: if the second `pWaitFor(s_thread, 8000)` in `heartbeat::stop` also times out (worker stuck in an internal WinHTTP `pClose`, or OS overloaded), `stop` returns with the thread alive. `Main.cpp` goes on to `net::shutdown()` which calls `pDeleteCS(&s_req_cs)` and `pDeleteCS(&s_cs)`. The thread can wake and enter `close_request_locked` -> `pEnterCS(&s_req_cs)` on a destroyed CS.
Impact: narrow UAF, but real. Much less likely than the original but the same kind.
Fix: either (a) return a bool from `heartbeat::stop` indicating success and skip `net::shutdown` on timeout; or (b) in `shutdown`, if the worker is still alive, skip `pDeleteCS` (leak the CS, OS cleans at process exit — acceptable).

**[M2] `/debug/metrics` registered via `mux.HandleFunc` escapes the `observe` middleware**
File: `server/internal/api/api.go:80-88`
Problem: normal endpoints go through `observe(path, h)` which logs and measures. `/debug/metrics` uses `mux.HandleFunc` directly, so scraping itself doesn't appear in the access log. Not a bug, but consistency asks for it.
Fix: `mux.Handle("/debug/metrics", observe("/debug/metrics", metricsHandler))`.

**[M3] `handleHeartbeat`: on the kill response, `kill` is `true` but `revoked` is `false` as a separate object — client parses OK, nit**
File: `server/internal/api/api.go:452-456` + `Project1/src/heartbeat.cpp:80-87`
Verified: the client calls `json::get_bool("kill")` and exits before looking at `next_nonce`. No extra parse breaks. Clean.

### LOW

**[L1] `listen error` + `log.Fatalf` ignores `defer pg.Close()`/`rdb.Close()`**
File: `server/cmd/server/main.go:124-125`
Problem: if `ListenAndServe` fails (port taken, bind refused), the process dies without closing pools. OS cleans up, but inside the graceful loop it would be cleaner.
Fix: replace `log.Fatalf` with `log.Printf` + `return` (or `os.Exit(1)` after defers via a separate function).

**[L2] Window between `go hs.ListenAndServe()` and `signal.Notify`**
File: `server/cmd/server/main.go:119-122`
Problem: SIGINT/SIGTERM between lines 119 and 122 kill with the default handler, no drain. Microsecond window.
Fix: `signal.Notify` BEFORE the `go`.

**[L3] `KillStatus` fail-open in heartbeat keeps the session alive if PG is down**
File: `server/internal/api/api.go:442`
Note: already listed in the original audit as accepted MEDIUM. Leave it, but document in `SERVER_SPEC.md` that a PG degradation lets heartbeat continue — kill is not fault-tolerant.

**[L4] `RememberLatestToken` in the normal heartbeat path refreshes TTL even when the previous is the same token**
File: `server/internal/api/api.go:467`
Note: functionally correct, just one extra `SET` per heartbeat. Ignore.

---

## 3. Cross-Task Integration

- **Task 2 × Task 3**: `failAuth` returns opaque 401; `observe` middleware logs status=401. No cross-check leak.
- **Task 3 × Task 4**: kill response (`{"kill":true,"revoked":false}`) goes with status 200; `metricInc` is not called on the kill path (there is no `kill_enforced_total` counter). Suggestion: add `metricInc("kill_enforced_total", "/session/heartbeat")` at L451. Not a bug.
- **Task 1 × Task 4**: when the server sends kill, heartbeat reads `kill=true` and exits the loop. `net::cancel_in_flight` is not touched on that path (loop ends naturally). OK.
- **Task 2 × Task 5**: PG startup ping + 5 s ping timeout fits well with `log.Fatalf` — process dies early, but still `defer pg.Close()` does not run (see L1).
- **Task 3 × /debug/metrics**: exposed before the process starts serving real traffic (it's in `mux` on register). OK as long as `addr` is `127.0.0.1:8080`. On `0.0.0.0` it leaks. Default is now `127.0.0.1` (main.go:105) — good.

No task broke another.

---

## 4. Overall Status

**Ready to test end-to-end**: YES.
- C++ build compiles (changes only in `net.cpp`, `net.h`, `heartbeat.cpp`).
- Go has new symbols (`metricInc`, `observe`, `rateLimitFetch`, `RatePerHWIDFetch`, `/debug/metrics`), all self-contained.
- Integration Docker mockup should come up with no schema change.

**Ready for production deploy**: NO.

### Remaining blockers (still from the original audit)
1. **Real TLS fingerprint pins** — `Project1/src/net.cpp:163-164` still has the same integration hash repeated. Needs real current + backup.
2. **Real hostname** — `Project1/src/Main.cpp:106` (not re-verified in this pass).
3. **HWID bind TOCTOU** — not addressed (HIGH item from the audit, fix via `SELECT FOR UPDATE` or conditional upsert).
4. **`/rpc/call` without replay-protection token** — not addressed.
5. **`std::atomic` on cross-thread flags** (`s_running`, `s_reason`) — not addressed.
6. **M1 above (CS lifetime)** — new nit to close before shipping.

### Important (nice before beta)
- Health/readiness endpoint.
- Admin endpoint (kill/list).
- Go crypto tests beyond HKDF.
- `fgets` 256 B buffer (`Main.cpp:70-77`).
- `master_secret` rotation.
- L1/L2 fixes above.

### One-line summary
The 5 tasks were applied correctly, with no cross-task regression. Remaining are **2 production blockers from the original audit** (TLS fingerprint pin, hostname) + **1 new nit** (CS lifetime at shutdown). Approved to move to end-to-end tests on the integration harness.
