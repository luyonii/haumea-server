# Server review

Code-review log for the Go license-server implementation. The client
source is shipped and authoritative; the server must match it
byte-for-byte. Reviewed against SERVER_SPEC.md, server/PLAN.md, and the
five crypto-critical client files (`auth.cpp`, `crypto.cpp`,
`watermark.cpp`, `heartbeat.cpp`, `rpc.cpp`, `payload.cpp`).

## Confirmed-correct deviations from `SERVER_PLAN.md`

Both are driven by the shipped client. The server is correct, the doc is wrong.

- **CONFIRMED CORRECT** — `/auth/login` HKDF: salt = `hwid_hex_bytes || "SecBlind_HKDF_v1"`, info empty.
  `internal/api/api.go:228-231` matches `Project1/src/auth.cpp:141-157`. The `licenses.session_salt`
  column does not exist (dropped in `migrations/0001_init.sql`).
- **CONFIRMED CORRECT** — Session-binding `[0..32)` = the 32 raw bytes from hex-decoding the 64-char
  HWID hex string. `internal/api/api.go:484-488` (`hex.DecodeString(hwidHex)`) matches
  `Project1/src/watermark.cpp:75-90` (`hex_to_bytes_32`). It is NOT `SHA-256(hwid_hex_bytes)`.

## Parity — no issues

| Item | Client | Server | OK |
|---|---|---|---|
| HKDF salt/info at `/auth/login` | `hwid \|\| "SecBlind_HKDF_v1"` / empty | same | ✅ |
| Nonce-based auth response | `HMAC(derived, base64_decode(challenge))` | same | ✅ |
| Session key info | derivation uses raw 32-B HWID | `sessionIDRaw \|\| hwidHashBytes` from `hex.DecodeString` | ✅ |
| Session-binding layout | `[0..32)` raw hwid, `[32..64)` SHA256(key), `[64..72)` u64 LE issued_at, `[72..80)` u64 LE ttl, `[80..96)` 16B nonce, `[96..128)` HMAC | same, `ttl=86400` (non-zero) | ✅ |
| AES-256-GCM | 12 B IV, 16 B tag | same | ✅ |
| Heartbeat HMAC | `HMAC(session_key, ascii_timestamp)` | same | ✅ |
| Heartbeat nonce | stored b64 string, compared as-is | same | ✅ |
| RPC canonical | `method\|token\|ts\|params_raw` | same, `json.RawMessage` preserves bytes | ✅ |
| Base64 variant | std + padding | `base64.StdEncoding` | ✅ |

---

## Findings

### HIGH

- **H1 — `/auth/login` does not check revocation status**
  `internal/api/api.go:194-208`. A license in `license_kill` can still log in and
  receive a valid session + entitled module. Only the next heartbeat would return
  `kill=true`, leaving a window where `/payload/fetch` and `/rpc/call` work.
  **Fix**: after the `Banned` check, call `s.PG.KillStatus` and return `banned`
  if revoked.

- **H2 — `/payload/fetch` does not check revocation status**
  `internal/api/api.go:434-450`. Same gap at fetch time: a revocation issued after
  login still serves one module. **Fix**: add `KillStatus` check between
  `GetSession` and `LatestPayload`, return `not_authorized`.

### MED

- **M1 — `TakeChallenge` is GET+DEL, not atomic**
  `internal/store/redis.go:28-39`. Two concurrent `/auth/login` for the same HWID
  race: both can read the nonce before either deletes. Documented as
  a shortcut but trivial to fix with `GETDEL` (go-redis v9 supports it).
  **Fix**: `r.C.GetDel(ctx, key)`.

- **M2 — `LogAbuse` uses the (possibly cancelled) request context**
  `internal/store/postgres.go:118-123`. On a 401 the request handler returns,
  the request `ctx` is cancelled, and the fire-and-forget insert races the
  cancellation — the abuse row may never land. **Fix**: use
  `context.Background()` (with a short timeout) inside `LogAbuse`.

- **M3 — No length cap on `license_key`**
  `internal/api/api.go:180-183`. `readJSON` caps the body at 2 MiB, so a
  misbehaving caller can send a 2 MB activation code that becomes HKDF IKM every
  attempt — amplified work for the server. **Fix**: enforce
  `len(req.LicenseKey) <= 64` (client format is `XXXXX-XXXXX-XXXXX-XXXXX`
  = 23 chars; 64 is generous).

- **M4 — No panic recovery middleware**
  `cmd/server/main.go:85-103`. `net/http` serves an empty 500 on panic but
  the stack trace prints to stderr — fine for debug, not ideal for prod.
  Low-cost fix with a wrapper. Skipped per ponytail (net/http already
  prevents client-visible leakage).

- **M5 — No graceful shutdown**
  `cmd/server/main.go:103`. SIGINT drops in-flight requests. Nginx
  termination masks this; LOW/MED. Skipped per ponytail (shortcut documented).

### LOW

- **L1 — Dead `sessionID` hex-encoded string**
  `internal/api/api.go:281, 314`. Computed, never used (the raw bytes go into
  `info`). Comment "kept for symmetry" is misleading.
  **Fix**: drop the `hex.EncodeToString` and the stray `_ = sessionID`.

- **L2 — Reimplemented `itoa`**
  `internal/store/redis.go:116-137`. Trivially replaceable by `strconv.FormatInt`.
  Not harmful. Skipped.

- **L3 — No rate limit on heartbeat/fetch/rpc**
  Requires a valid session, so impact is bounded to a logged-in caller
  hammering their own session — bounded by the `heartbeat_s` cadence they
  already know. Skipped per ponytail.

- **L4 — License-lookup timing leak**
  PG query happens before challenge verification, so valid vs invalid activation
  codes are time-distinguishable. Mitigation (dummy HKDF) is non-trivial.
  Documented, not fixed.

---

## Applied fixes

- **H1 — FIXED.** `api.go` login handler now calls `s.PG.KillStatus` after
  the banned check and returns `banned` / `license killed`.
- **H2 — FIXED.** `api.go` fetch handler calls `s.PG.KillStatus` after
  session lookup and returns `not_authorized` / `killed`.
- **M1 — FIXED.** `redis.go` `TakeChallenge` now uses `r.C.GetDel` (one atomic
  op). Redis 6.2+ is required; current `redis_addr` targets Redis 7 per README.
- **M2 — FIXED.** `postgres.go` `LogAbuse` now uses a detached
  `context.Background()` with a 2 s timeout so a cancelled request still logs.
- **M3 — FIXED.** `api.go` login handler rejects `license_key` longer than
  64 bytes with `bad_request`.
- **M4 — SKIPPED.** `net/http` already catches panics and sends an empty 500
  to the client. Stack leak is to stderr only, which is server-side.
- **M5 — SKIPPED.** Documented shortcut in PLAN.md; TLS termination at Nginx
  keeps this small.
- **L1 — FIXED.** Removed dead `sessionID` hex string and its placeholder
  assignment.
- **L2 — SKIPPED.** Not a one-liner once the import graph is touched; harmless.
- **L3 — SKIPPED.** The caller already owns the session being hammered.
- **L4 — SKIPPED.** Non-trivial; documented as a known limitation.
