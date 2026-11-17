# Server Plan (ponytail)

Build the minimum Go backend for the commercial license server that the
shipped C++ client talks to. Parameters below override `SERVER_PLAN.md`
where that doc disagrees with the client source; the client is already
shipped and cannot change.

## Client-forced deviations from SERVER_PLAN

| Item | SERVER_PLAN | Client source | Server uses |
|---|---|---|---|
| Login HKDF salt | `"SecBlind_HKDF_v1"` (16 B) | `hwid_hex_bytes \|\| "SecBlind_HKDF_v1"` | match client |
| Login HKDF info | `hwid_bytes \|\| session_salt` | empty | match client |
| Per-license `session_salt` | required column | unused | column dropped |
| Session-binding[0..32] | `SHA-256(hwid_hex_bytes)` | `hex_to_bytes_32(hwid_hex)` | match client (raw 32 B) |

Everything else (HKDF salt literal, base64 padding, session-binding
[32..128] layout, RPC canonical format, session key derivation,
heartbeat HMAC over ASCII timestamp bytes) follows SERVER_PLAN unchanged.

## Layout

```
server/
  cmd/server/main.go
  internal/api/        handlers + router (one file each)
  internal/store/      postgres.go, redis.go, session.go
  pkg/crypto/          hkdf.go (+ test), aesgcm.go (+ test)
  migrations/0001_init.sql
  config.yaml.example
  README.md
  go.mod
```

One package per concern; no extra internal packages.

## Order

1. `pkg/crypto` with RFC 5869 and NIST GCM test vectors (TDD).
2. Postgres + Redis stores.
3. Handlers `/auth/challenge`, `/auth/login`, `/session/heartbeat`,
   `/payload/fetch`, `/rpc/call`.
4. `main.go` wiring config + stores + router.
5. README (PowerShell) + `.gitignore`.

## Shortcuts (deliberate, documented)

- No TLS in-process. Terminate at Nginx. Server listens plain HTTP on
  `127.0.0.1:<port>`. `shortcut: HTTP only, upgrade when deploying standalone`.
- Rate limit is `INCR` + `EXPIRE`, no token bucket.
  `shortcut: per-minute fixed window, upgrade when abuse volume rises`.
- No migration tool. Plain `.sql` run by `psql -f`.
- No admin API to seed licenses; `psql` insert is in README.
- Integration test and PE fixture skipped — crypto tests cover the
  parameters that would break interop; endpoint E2E needs the C++ client
  built, which is a separate step.
