# Sec-blind — Load / stress test harness (k6)

Load scripts for the Go server. They don't edit the server. k6 runs
outside and hits the `/api/v1/*` endpoints.

## Prerequisites

1. **k6 installed** on the host:
   - Windows (choco): `choco install k6`
   - Windows (winget): `winget install k6 --source winget`
   - Linux (apt):  `sudo apt-get install k6`
   - macOS (brew): `brew install k6`
   - Direct binary: https://github.com/grafana/k6/releases
2. **Server up**, pointing at a test Postgres+Redis. Never run against
   production.
3. **Test activation codes** seeded in Postgres. Scripts read the list
   from env `SB_LICENSES` (CSV). Example:
   ```powershell
   $env:SB_LICENSES = "TEST-AAAA-0001,TEST-AAAA-0002,TEST-AAAA-0003"
   ```
   Seed them with:
   ```sql
   INSERT INTO licenses (key, status, hwid, hwid_bound_at)
   VALUES ('TEST-AAAA-0001','active',NULL,NULL),
          ('TEST-AAAA-0002','active',NULL,NULL),
          ('TEST-AAAA-0003','active',NULL,NULL);
   ```
   For the `03_rpc_burst` and `04_rate_limit_hit` scenarios, create **more**
   activation codes (one per VU) or accept the sharing as noted in each
   script.
4. **Base URL**: `SB_BASE_URL` (default `http://127.0.0.1:8080`).
5. **Server rate-limit config** (`per_ip_rpm`, `per_hwid_rpm`): adjust in
   `config.yaml` for the test. Running scripts with very low defaults
   closes the door fast.

## Run

```powershell
# individual
k6 run tests/load/00_baseline.js

# with env
$env:SB_BASE_URL = "http://127.0.0.1:8080"
$env:SB_LICENSES = "TEST-AAAA-0001,TEST-AAAA-0002,..."
k6 run tests/load/01_login_flow.js

# JSON summary for CI
k6 run --summary-export=summary.json tests/load/01_login_flow.js

# all (sequential)
pwsh tests/load/run_all.ps1

# smoke only
pwsh tests/load/run_all.ps1 -Quick
```

## Scenarios

| # | script | VUs | duration | focus |
|---|--------|-----|---------|------|
| 00 | `00_baseline.js`                | 10  | 1m  | `/auth/challenge` sanity |
| 01 | `01_login_flow.js`              | 50  | 7m  | full challenge→login HMAC |
| 02 | `02_heartbeat_sustained.js`     | 100 | 10m | sustained heartbeat loop   |
| 03 | `03_rpc_burst.js`               | 20  | burst | Redis replay-protection token  |
| 04 | `04_rate_limit_hit.js`          | 30  | 2m  | validate 429 + Retry-After     |
| 05 | `05_payload_fetch_concurrency.js` | 50 | 3m | concurrent `/payload/fetch`  |

## SLOs (thresholds) — CI exit != 0 on failure

- Baseline:    P95 < 100ms, error < 1%
- Login flow:  P95 < 300ms, success > 99%
- Heartbeat:   P95 < 150ms, success > 99.5%
- RPC burst:   nonce_replay = 0, P95 < 200ms
- Rate limit:  429_count > 0, 5xx = 0
- Payload fetch: P99 < 500ms, 5xx = 0

## Key Grafana metrics

All k6 metrics go out via `--out` to InfluxDB/Prometheus. The main ones
are already tagged with `route`:

- `http_req_duration{route="challenge|login|heartbeat|rpc|fetch"}`
- `http_req_failed` per route
- `login_success_rate` (custom, `01_login_flow`)
- `nonce_replay_total` (custom, `03_rpc_burst`)
- `rate_limited_total` (custom, `04_rate_limit_hit`)
- `vus`, `vus_max`
- `iterations` per route

Prometheus remote-write example:
```powershell
k6 run --out experimental-prometheus-rw tests/load/02_heartbeat_sustained.js
```

## Technical notes

- **HKDF**: k6 does not ship HKDF in the stdlib. `_lib.js` implements
  HKDF-Extract + Expand (single block, 32 B output) via `k6/crypto` HMAC.
  Matches `server/pkg/crypto/hkdf.go`.
- **HWID**: exactly 64 lowercase hex chars (server rule). The lib
  generates a unique HWID per VU.
- **Payload GCM decrypt**: out of scope for this harness. k6 measures
  server-side. For client-side measurement, see `05_payload_fetch_concurrency.js`
  note `OUT-OF-BAND`.
- **TLS / cert fingerprint**: the C++ client pins the cert. k6 does not. To
  run against a server with TLS, pass `--insecure-skip-tls-verify` or
  `SB_CERT_FILE=cert.pem` (the script tries `__ENV.CERT_FILE || "cert.pem"`).

## Troubleshooting

- All logins fail with `unknown_license` → activation codes not seeded
  or wrong `SB_LICENSES`.
- `unknown_hwid` after the first OK login → HWID binding recorded and VUs
  reuse the HWID; solution: each VU generates its own HWID (already the
  default).
- 100% 429 → server rate-limit too tight. Adjust `per_ip_rpm` in
  `config.yaml` for the test or run with fewer VUs.
