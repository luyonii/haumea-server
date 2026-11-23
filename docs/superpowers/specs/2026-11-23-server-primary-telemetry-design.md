# Server-primary enforcement via heartbeat telemetry — design

Date: 2026-11-23
Status: draft, pending approval

## Intent and why

Today the C++ client's `sentinel` detects debug / VM / hook / tool / tamper
and kills the process locally via `scrub_cb → terminate_silent`. The
server never learns a trip happened, so it cannot ban the license, cannot
correlate across sessions, and the cheater who patches the local kill
keeps running. Project direction is "server-side como principal
segurança"; this change gives the server the signal it needs.

## Goals

- Server receives every sentinel trip from a live client and persists it
  in `abuse_log`.
- Two sentinel trips from the same `license_id` inside a rolling 24 h
  window auto-ban the license (`licenses.banned = true`), killing the
  current session and blocking future logins.
- Reduce the window where a fetched payload remains valid after revoke:
  watermark TTL 86 400 s → 3 600 s.
- No new HTTP endpoint, no new keys, no new crypto primitives.

## Non-goals

- Changing the local client-side defences themselves (anti_debug, anti_vm,
  anti_hook, tool_detect, anti_tamper). Already shipped, treated as
  secondary defence.
- Encrypted telemetry body: the sentinel bitmask is not a secret, just
  needs integrity + anti-replay, which the existing heartbeat HMAC and
  nonce already give.
- Automatic unban. All unban stays manual via admin UI.

## Anti-goals (how this could still fail)

- A cheater who both patches local terminate and blocks the heartbeat
  response wins until session TTL expires. Mitigated by:
  (a) local terminate still runs after fire-and-forget report; (b)
  watermark TTL 1 h shrinks the useful payload window; (c) latest-session
  kill on next login.

## Constraints

- Canonical HMAC string changes on both sides in lockstep. Any client
  older than this change will have every heartbeat rejected as
  `invalid_hmac`. Acceptable: pre-GA, both sides rebuilt together.
- Client stays zero-IAT; no new Win32 imports. New field is JSON only.
- `k_heartbeat` HKDF sub-key reused unchanged (same info tag
  `sb.v1.heartbeat.hmac`).
- Rate limit per-HWID already applies to `/session/heartbeat` and will
  absorb any telemetry flood from a compromised client.

## Approaches considered

| # | Shape | Why not |
|---|-------|---------|
| A | New endpoint `POST /session/report` with its own HMAC key. | More surface, more code on both sides, more things to keep in canonical sync. The report is just another authenticated message over the session; not worth its own endpoint. |
| **B** | **Piggyback two uint32 fields on the existing heartbeat JSON, extend the HMAC canonical string to cover them.** | Chosen. Smallest diff on both sides. Reuses `k_heartbeat`, existing nonce rotation gives anti-replay, existing rate limit protects the channel. |
| C | Only tighten server (TTL, auto-ban on existing `abuse_log` reasons, concurrent-session cap). | Server stays blind to what the client actually detected. Reactive, not proactive. Kept the TTL + auto-ban parts of C; dropped the concurrent-session cap as out of scope for this change. |

## How

### Client (`Project1/src/heartbeat.cpp`, `Project1/include/heartbeat.h`)

1. Add module-level atomic `uint32_t g_sentinel_mask` and
   `uint32_t g_tool_mask`, set by `heartbeat::report_trip(sentinel_mask,
   tool_mask)` (new public API). Call is idempotent; bits are OR-ed in.
2. On every tick, snapshot both atomics into the request JSON as
   `"sentinel_mask"` and `"tool_mask"` (decimal uint32).
3. New canonical HMAC input:
   `timestamp || "|" || sentinel_mask || "|" || tool_mask`.
   Pipe separator matches the convention already used in `/rpc/call`.
4. `sentinel::scan` call path: just before `terminate_silent`, call
   `heartbeat::report_trip(mask, tool_mask)` then
   `heartbeat::flush_once()` (new helper, 2 s hard timeout,
   fire-and-forget; drops on any error — the local terminate still
   runs).

### Server (`server/internal/api/api.go`, `server/internal/store/postgres.go`)

1. `handleHeartbeat`: parse `sentinel_mask` and `tool_mask` as
   `json.Number`, reject if absent or not a valid uint32. Recompute HMAC
   over the new canonical string. Timestamp window and nonce rotation
   unchanged.
2. If `sentinel_mask != 0 || tool_mask != 0`, call
   `s.PG.LogAbuse(ctx, &sess.LicenseID, clientIP(r),
    fmt.Sprintf("sentinel_trip:s=%d,t=%d", sMask, tMask))`.
3. Query `abuse_log` for `license_id = X AND reason LIKE 'sentinel_trip:%'
    AND created_at > now() - interval '24 hours'`. If count ≥ 2, set
   `licenses.banned = true` in the same transaction; call
   `RDB.KillSessionsFor(ctx, licenseID)` and return
   `{ "kill": true, "revoked": true }`. Metric
   `sentinel_autoban_total{reason}` incremented.
4. New helper `s.PG.AutoBanIfSentinelThreshold(ctx, licenseID, threshold,
    window)` so the heartbeat handler stays short.

### Watermark TTL (`server/internal/api/api.go` `buildWatermark`)

`binary.LittleEndian.PutUint64(wm[72:80], 86400)` → `3600`.
Client-side watermark TTL check is already read from the blob, no client
change needed.

### Admin UI

No change for this round. Auto-ban already surfaces in the licenses
list because `banned` is shown.

## Threshold detail

- **Count**: 2 trips in a 24 h rolling window per license, any category.
  Single unified threshold as agreed; simpler than per-category.
- **Trips persist** even if the license is not banned yet, so the second
  trip bans even across days as long as the first is within 24 h.
- **Unban** does not reset the count. Ops must either manually delete
  the old `abuse_log` rows or accept that a flap will re-ban on the
  next trip. Documented as intentional.

## Risk the user must know

- **Lockstep deploy**. The client binary and the Go server in this
  change must ship together. A mismatched pair yields 100 %
  `invalid_hmac` on heartbeat.
- **Fire-and-forget report is best-effort**. A fully offline cheater
  never reports; local terminate is the only defence in that case.
  Expected and accepted.
- **False-positive auto-ban**. If the bitmask reports a noisy heuristic
  (for example `anti_vm` tripping on legitimate virtualised Windows),
  two users on a VM gaming rig get banned. Mitigation: `anti_vm` alone
  is already WARN, not CRITICAL, in `sentinel::scan`; this change does
  **not** promote it. Only CRITICAL categories call `report_trip`.
  Verify this during review.

## What's left to the builder

- The exact JSON field names on the wire (`sentinel_mask`, `tool_mask`
  — plain, no prefix).
- Metric label naming (`sentinel_autoban_total` + reason label).
- Whether `flush_once` should block the terminate path by up to 2 s or
  dispatch on a detached thread and let `terminate_silent` race it.
  Builder's call; the 2 s hard budget is the contract.

## Coverage after this change

| Threat | Before | After |
|--------|--------|-------|
| Debugger attached | Local kill | Local kill + server ban on 2nd trip |
| Hook/inline patch detected | Local kill | Local kill + server ban on 2nd trip |
| Known tool running | Local kill | Local kill + server ban on 2nd trip |
| Patched local terminate | No defence | Server kill via heartbeat response, auto-ban on 2nd trip |
| Blocked heartbeat response | Local kill | Local kill, server times out session at TTL |
| Payload replayed after revoke | 24 h | 1 h |
