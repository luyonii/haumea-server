# Server-primary Telemetry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Pipe client sentinel trips into the server so the server auto-bans the license at 2 trips / 24 h, and shrink the fetched-payload grace window from 24 h to 1 h.

**Architecture:** The existing `/session/heartbeat` endpoint grows two uint32 JSON fields (`sentinel_mask`, `tool_mask`), the HMAC canonical string is extended to cover them, and a non-zero mask triggers `abuse_log` insert + conditional auto-ban. Client-side the sentinel calls `heartbeat::report_trip` right before `terminate_silent`, forcing one last heartbeat with the mask set. Watermark TTL in `buildWatermark` drops from 86400 s to 3600 s.

**Tech Stack:** Go 1.22+ server (chi-free, net/http), PostgreSQL via pgx, Redis via go-redis, C++17 client (WinHTTP, no CRT net), Prometheus client_golang.

**Spec:** [docs/superpowers/specs/2026-11-23-server-primary-telemetry-design.md](../specs/2026-11-23-server-primary-telemetry-design.md)

## Global Constraints

- HMAC key `k_heartbeat` reused unchanged: `HKDFExpand(session_key, "sb.v1.heartbeat.hmac", 32)`.
- New HMAC canonical string: ASCII `timestamp || "|" || sentinel_mask || "|" || tool_mask`, where `sentinel_mask` and `tool_mask` are decimal ASCII uint32 (`strconv.FormatUint` / `std::to_string`), no leading zeros, no sign, no quotes.
- Client stays zero-IAT; no new Win32 imports introduced by this change.
- Threshold: 2 trips per `license_id` inside a 24 h rolling window, any category.
- Watermark TTL field at `wm[72:80]` is little-endian uint64 seconds; new value is 3600.
- Auto-ban sets `licenses.banned = true`; unban is manual only.
- Cliente e servidor devem ser buildados e deployados juntos (canonical mudou em lockstep).

## Review Focus

1. Heartbeat JSON that omits `sentinel_mask` or `tool_mask`: must be rejected `400 bad_request`; no silent default-to-zero that would let an old or tampered client dodge telemetry. Owned by Task 1.
2. `sentinel_mask` or `tool_mask` outside `[0, 2^32-1]` (negative, float, non-numeric): must be rejected `400 bad_request`; the HMAC canonical must never see a mutated value. Owned by Task 1.
3. Two near-simultaneous heartbeats that both cross the 2-trip threshold: auto-ban must be idempotent — second `UPDATE licenses SET banned=true WHERE id=$1` is a no-op, no error returned, no double metric increment. Owned by Task 1.
4. Payload blob fetched at the old 24 h TTL just before this change ships: client still trusts its embedded TTL field, so legacy blobs keep their old window; the TTL change applies only to blobs sealed after deploy. Owned by Task 2, documented inline.
5. `heartbeat::flush_once` hanging past 2 s (network wedge, DNS failure): must not block `terminate_silent`; dispatch on a detached thread with hard deadline, local kill proceeds regardless. Owned by Task 3.

---

## Task 1: Server — heartbeat telemetry + auto-ban

**Files:**
- Modify: `C:\Users\smth fu4v\Documents\Projects\Sec blind\server\internal\api\api.go` — `handleHeartbeat` body around lines 482–596
- Modify: `C:\Users\smth fu4v\Documents\Projects\Sec blind\server\internal\api\metrics.go` — add counter
- Modify: `C:\Users\smth fu4v\Documents\Projects\Sec blind\server\internal\store\postgres.go` — add helper
- Create: `C:\Users\smth fu4v\Documents\Projects\Sec blind\server\internal\api\heartbeat_telemetry_test.go`

**Interfaces:**
- Consumes: existing `s.PG.LogAbuse(ctx, *int64, ip, reason)`, `s.RDB.KillSessionsFor(ctx, licenseID)`, `crypto.HKDFExpand`, `crypto.HMAC256`, `crypto.Equal`.
- Produces:
  - `func (p *PG) AutoBanIfSentinelThreshold(ctx context.Context, licenseID int64, threshold int, window time.Duration) (banned bool, err error)` — returns `banned=true` only if this call is the one that flips `banned` from false to true (`UPDATE … WHERE banned = false … RETURNING id`); concurrent callers see `banned=false, err=nil` on the losing side so no double metric increment.
  - Prometheus counter `sentinel_autoban_total` (no labels).
  - Extended heartbeat request JSON: adds required `sentinel_mask` and `tool_mask` as `json.Number` (parsed via `.Int64()`, range-checked to `[0, 1<<32 - 1]`).
  - Extended heartbeat canonical: `timestamp + "|" + strconv.FormatUint(sMask,10) + "|" + strconv.FormatUint(tMask,10)`.

- [ ] **Step 1: Write the failing tests**

File: `server/internal/api/heartbeat_telemetry_test.go`

```go
// TestHeartbeat_RejectsMissingMaskFields: POST a heartbeat body without
// sentinel_mask → 400 bad_request. Same for tool_mask.
//
// TestHeartbeat_RejectsOutOfRangeMask: sentinel_mask = -1 and
// sentinel_mask = 4294967296 both return 400 bad_request, no abuse_log row.
//
// TestHeartbeat_CanonicalIncludesMasks: a heartbeat with HMAC computed over
// the old canonical (timestamp only) returns 401 invalid_hmac even when
// sentinel_mask=0 and tool_mask=0.
//
// TestHeartbeat_TripLogsAbuse: valid heartbeat with sentinel_mask=1,
// tool_mask=0 returns 200 and inserts an abuse_log row with
// reason matching "sentinel_trip:s=1,t=0".
//
// TestHeartbeat_AutoBanOnSecondTrip: two heartbeats with any non-zero mask
// from the same license inside the 24h window → second call returns
// {"kill": true, "revoked": true} and licenses.banned=true.
//
// TestAutoBanIfSentinelThreshold_Idempotent: call the helper twice in a row;
// first returns banned=true, second returns banned=false, err=nil, and the
// sentinel_autoban_total counter went up by exactly 1 in the handler path.
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./server/internal/api/ -run Heartbeat_ -v`
Expected: all five FAIL (compile error on `AutoBanIfSentinelThreshold` and on the missing-field validation).

- [ ] **Step 3: Implement `AutoBanIfSentinelThreshold` in `server/internal/store/postgres.go`**

Signature: `func (p *PG) AutoBanIfSentinelThreshold(ctx context.Context, licenseID int64, threshold int, window time.Duration) (bool, error)`

Approach: single SQL statement
```sql
WITH trips AS (
  SELECT 1 FROM abuse_log
   WHERE license_id = $1
     AND reason LIKE 'sentinel_trip:%'
     AND created_at > now() - $2::interval
   LIMIT $3
), threshold_met AS (
  SELECT 1 FROM trips HAVING count(*) >= $3
)
UPDATE licenses
   SET banned = true
 WHERE id = $1
   AND banned = false
   AND EXISTS (SELECT 1 FROM threshold_met)
RETURNING id
```
Return `banned=true` iff `RETURNING` yielded a row. `pgx.ErrNoRows` means either threshold not met or already banned — both return `(false, nil)`.

- [ ] **Step 4: Implement heartbeat handler changes in `server/internal/api/api.go`**

In the request struct, add `SentinelMask json.Number \`json:"sentinel_mask"\`` and `ToolMask json.Number \`json:"tool_mask"\``.

Validate both are present (zero-value `json.Number("")` → 400). Parse via `.Int64()`; reject if `< 0` or `> 0xFFFFFFFF`.

Replace canonical: `canon := req.Timestamp + "|" + strconv.FormatUint(sMask,10) + "|" + strconv.FormatUint(tMask,10)`. Run `HMAC256(kHeartbeat, []byte(canon))` and `crypto.Equal` as today.

After HMAC verify, if `sMask != 0 || tMask != 0`:
- `s.PG.LogAbuse(ctx, &sess.LicenseID, clientIP(r), fmt.Sprintf("sentinel_trip:s=%d,t=%d", sMask, tMask))`
- `banned, _ := s.PG.AutoBanIfSentinelThreshold(ctx, sess.LicenseID, 2, 24*time.Hour)`
- If `banned`: `sentinelAutobanTotal.Inc()`, `s.RDB.DeleteSession(ctx, req.Token)`, `s.RDB.KillSessionsFor(ctx, sess.LicenseID)`, respond `{"kill": true, "revoked": true}`, return.

Existing kill/revoke/nonce/TTL path follows unchanged for the non-ban case.

- [ ] **Step 5: Add Prometheus counter in `server/internal/api/metrics.go`**

`sentinelAutobanTotal = promauto.NewCounter(prometheus.CounterOpts{Name: "sentinel_autoban_total", Help: "licenses auto-banned after N sentinel trips"})`

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./server/... -v`
Expected: PASS, including the five new tests above and all existing server tests (the canonical change breaks any fixture that computed the old HMAC in-test; fix those fixtures to the new canonical).

- [ ] **Step 7: Commit**

```bash
git add server/internal/api/api.go server/internal/api/metrics.go server/internal/api/heartbeat_telemetry_test.go server/internal/store/postgres.go
git commit -m "feat(server): sentinel telemetry on heartbeat, auto-ban at 2 trips/24h"
```

---

## Task 2: Server — watermark TTL 1h

**Files:**
- Modify: `C:\Users\smth fu4v\Documents\Projects\Sec blind\server\internal\api\api.go` — `buildWatermark` line ~723
- Modify / create tests under `server/internal/api/` covering `/payload/fetch`

**Interfaces:**
- Consumes: none new.
- Produces: `buildWatermark` emits `wm[72:80] = 3600` (little-endian uint64).

- [ ] **Step 1: Write the failing test**

Add to the nearest existing fetch test file (grep for `TestHandleFetch` or similar; create `payload_watermark_test.go` if none):

```go
// TestBuildWatermark_TTL_OneHour: build a watermark, read wm[72:80] as
// little-endian uint64, assert == 3600.
```

- [ ] **Step 2: Run to verify fails**

Run: `go test ./server/internal/api/ -run Watermark -v` → FAIL (reads 86400).

- [ ] **Step 3: Change the literal in `buildWatermark`**

`binary.LittleEndian.PutUint64(wm[72:80], 86400)` → `binary.LittleEndian.PutUint64(wm[72:80], 3600)`.

Remove the stale `// TTL 24h` comment on the same line; replace with `// TTL 1h; client enforces after clock-rollback. Shortens the window where a payload fetched before kill/revoke stays useful.`

- [ ] **Step 4: Run to verify passes**

Run: `go test ./server/... -v` → PASS.

- [ ] **Step 5: Commit**

```bash
git add server/internal/api/api.go server/internal/api/payload_watermark_test.go
git commit -m "feat(server): shrink payload watermark TTL 24h -> 1h"
```

---

## Task 3: Client — heartbeat `report_trip` + `flush_once` + canonical

**Files:**
- Modify: `C:\Users\smth fu4v\Documents\Projects\Sec blind\Project1\include\heartbeat.h`
- Modify: `C:\Users\smth fu4v\Documents\Projects\Sec blind\Project1\src\heartbeat.cpp`
- Modify / create: `C:\Users\smth fu4v\Documents\Projects\Sec blind\tests\sentinel_tests\stubs.cpp` or a new `tests\heartbeat_tests\` vcxproj if none exercises heartbeat today (check first)

**Interfaces:**
- Consumes: existing `net::post_json`, `crypto::hmac_sha256`, session key + nonce state already held in `heartbeat.cpp` module scope.
- Produces:
  - `void heartbeat::report_trip(uint32_t sentinel_mask, uint32_t tool_mask) noexcept` — OR-s bits into module-level `std::atomic<uint32_t>` pair. Safe to call from any thread, including from a sentinel-tripped context.
  - `bool heartbeat::flush_once(uint32_t timeout_ms) noexcept` — sends exactly one heartbeat with the current mask values, blocks up to `timeout_ms`, returns `true` on 200. Spawns a detached worker if called from a context that cannot block; see Step 3.
  - Tick worker canonical: `std::string canon = ts + "|" + std::to_string(sMask) + "|" + std::to_string(tMask);` then HMAC-SHA256 over `canon.data(), canon.size()`.

- [ ] **Step 1: Write the failing test**

Test name: `TestHeartbeatCanonicalIncludesMasks` in the sentinel/heartbeat test project. Stub `net::post_json` to capture the outbound JSON and the HMAC input. Assertions:

```
// After calling heartbeat::report_trip(0x4, 0x2) and heartbeat::flush_once(500):
// - captured JSON contains "sentinel_mask":4 and "tool_mask":2
// - captured HMAC input equals "<timestamp>|4|2"
// - flush_once returned true within 500 ms
```

Also `TestFlushOnceReturnsFastOnNetworkStall`: stub `net::post_json` to sleep 5000 ms; `flush_once(200)` returns within 400 ms with `false`.

- [ ] **Step 2: Build and run tests, verify they fail**

Run: MSBuild the test project, then run the executable. Expected: compile error on `report_trip` / `flush_once`.

- [ ] **Step 3: Implement in `heartbeat.cpp`**

Add file-scope `std::atomic<uint32_t> g_sentinel_mask{0}, g_tool_mask{0};`.

`report_trip`: fetch-or on both atomics with `memory_order_relaxed`.

Tick worker: just before building the request body, snapshot `g_sentinel_mask.load()` and `g_tool_mask.load()`; include as `sentinel_mask` and `tool_mask` in the JSON (plain integers, no quotes). Build canonical as above. Do not clear the atomics — the server is the source of truth for whether a trip was received.

`flush_once(timeout_ms)`:
- If the tick worker thread is already running, signal it to push one tick now and wait up to `timeout_ms`.
- Otherwise, start a detached thread that sends one heartbeat and returns. Caller uses `std::future` with `wait_for(timeout_ms)`; on timeout return `false` without joining — the worker is daemon-like, the process is about to die anyway.

Update `heartbeat.h` with the two new declarations in the `heartbeat` namespace.

- [ ] **Step 4: Build and run tests, verify they pass**

Expected: both new tests PASS, existing `sentinel_tests` still PASS.

- [ ] **Step 5: Commit**

```bash
git add Project1/include/heartbeat.h Project1/src/heartbeat.cpp tests/
git commit -m "feat(client): heartbeat carries sentinel_mask+tool_mask, new flush_once"
```

---

## Task 4: Sentinel wiring + end-to-end

**Files:**
- Modify: `C:\Users\smth fu4v\Documents\Projects\Sec blind\Project1\src\sentinel.cpp` — the monitor path that reaches `terminate_silent`
- Create: `C:\Users\smth fu4v\Documents\Projects\Sec blind\tests\load\06_sentinel_autoban.js` (k6) — optional smoke, run manually against the staging VPS

**Interfaces:**
- Consumes: `heartbeat::report_trip`, `heartbeat::flush_once` from Task 3.
- Produces: no new public symbols. Side effect: when sentinel decides to abort, the server sees exactly one telemetry heartbeat before the process dies.

- [ ] **Step 1: Write the failing test**

In the existing `sentinel_tests` project, add `TestSentinelReportsBeforeTerminate`: stub `heartbeat::report_trip` to record arguments and `terminate_silent` to set a flag. Simulate a CRITICAL mask (debug bit set). Assertions:

- `report_trip` was called with `sentinel_mask` matching the CRITICAL bits.
- `flush_once` was called with a timeout ≤ 2000.
- `terminate_silent` flag is set *after* both of the above.

- [ ] **Step 2: Build and run, verify fails**

Expected: assertions fail — current code calls `terminate_silent` directly, no telemetry.

- [ ] **Step 3: Edit `sentinel.cpp` monitor path**

At the `scan()` / monitor branch that returns `action::abort_` (today immediately followed by `scrub_cb` + `terminate_silent`):

1. Build `uint32_t sMask` by OR-ing the CRITICAL bits already computed in `scan`: `anti_debug`, `anti_hook`, tamper, and any tool-detect bits that map to CRITICAL.
2. Build `uint32_t tMask` from `tool_mask` directly.
3. `heartbeat::report_trip(sMask, tMask);`
4. `heartbeat::flush_once(2000);` — fire-and-forget, return value ignored.
5. Existing `scrub_cb` + `terminate_silent` continue unchanged.

Only CRITICAL categories trip the report path. `anti_vm` alone stays WARN per the design doc; it must not call `report_trip`.

- [ ] **Step 4: Build and run tests**

Expected: PASS, and all pre-existing sentinel tests still PASS.

- [ ] **Step 5: Manual end-to-end against staging**

Boot server + client against the staging VPS (65.108.60.114 per memory). Trigger a debugger-attached scenario on the client box. Expected on server:

- Prometheus `sentinel_autoban_total` increments by 0 on first trip, by 1 on second trip within 24 h.
- `abuse_log` has two rows `sentinel_trip:s=…`.
- `licenses.banned = true` on the test license after the second trip.
- Next `/auth/login` for that license returns `invalid_credentials` with internal reason `banned`.

Document the run in `TESTING.md` under a new section "Sentinel auto-ban E2E — 2026-11-23".

- [ ] **Step 6: Commit**

```bash
git add Project1/src/sentinel.cpp tests/sentinel_tests/ TESTING.md
git commit -m "feat(client): sentinel reports trip to server before local terminate"
```

---

## Deploy order

1. Merge the server commits (Task 1 + Task 2) first and deploy them to staging. Old clients still work because their heartbeat body omits the new fields → 400 bad_request; this is acceptable for a brief window because no production client exists yet (pre-GA).
2. Rebuild the client with Task 3 + Task 4 and ship it. From this point on a mismatched pair is impossible because the C++ binary embeds the new canonical.
3. Run the end-to-end from Task 4 Step 5 against staging.
4. Promote to production (VPS 65.108.60.114) by `dist/deploy-server.ps1` + distributing the new client binary.
