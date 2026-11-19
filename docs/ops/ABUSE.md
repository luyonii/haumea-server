# ABUSE — Playbook

## Sources

- `abuse_log` table in Postgres: `(id, license_id, ip, reason, ts)`.
- Reasons observed in `server/internal/api/api.go`:
  - `fetch_license_lookup` — session points at a license that doesn't exist.
  - `fetch_killed` — kill flag active, client tried to fetch.
  - `fetch_no_payload` — entitled module missing at fetch time.
  - `hwid_cooldown` — HWID different from the registered one inside the cooldown window.
  - (prefix `failAuth`) other authentication reasons: `unknown_license`, `banned`, `bad_hmac`, `nonce_replay`, `rate_limit_exceeded`, `hwid_mismatch`.
- Full list: `grep -n LogAbuse server/internal/api/api.go` for audit.

## Triage

### Automatic (script `auto_ban.sh`)
- 10 min window, aggregate by IP.
- IP threshold: > 50 distinct events → iptables DROP + log in `/var/log/secblind/autoban.log`.
- License threshold: > 20 fails/hour → marks `needs_review` in an adjacent table (or fires an alert if the table doesn't exist).
- Ban duration: 24 h (unban via cron). Reinfringement: permanent ban after 3 occurrences.

### Manual
- HWID flip-flop: same `license_id` with recurring `hwid_mismatch` from different IPs → sharing/crack. Revoke.
- `bad_hmac` burst: key brute-force attempt or outdated client. Investigate version.
- `nonce_replay` in volume: active replay attempt. P1.

## Entitlement revocation

**Endpoint** (assumed): `POST /api/v1/admin/revoke`
Body: `{"license_id": 1234, "reason": "sharing"}`
Auth: header `Authorization: Bearer <ADMIN_TOKEN>`.

Curl ref:
```bash
curl -X POST https://api.secblind.example/api/v1/admin/revoke \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"license_id": 1234, "reason": "hwid_flipflop"}'
```

## Evidence package (before revoking)

SQL query:
```sql
SELECT id, license_id, ip, reason, ts
FROM abuse_log
WHERE license_id = $1
ORDER BY ts DESC
LIMIT 100;
```

Export JSON + save in `/var/log/secblind/evidence/<license_id>-<ts>.json`. 1-year retention, read-only.

Query by IP (ban):
```sql
SELECT license_id, reason, count(*) AS n
FROM abuse_log
WHERE ip = $1 AND ts > now() - interval '24 hours'
GROUP BY license_id, reason
ORDER BY n DESC;
```

## SLA

| Severity | Trigger | Response |
|---|---|---|
| HIGH | Active replay, mass bad_hmac, confirmed leak | < 1h |
| MED | Sharing suspicion (HWID flip), isolated burst | < 24h |
| LOW | Isolated fail, apparent rate-limit miss | < 7d |

## Flow

1. Alert fired → acknowledge.
2. Pull evidence (SQL above + nginx logs if available).
3. Classify severity.
4. Decision: ban IP (temp/perm), revoke license, or monitor.
5. Execute: `auto_ban.sh --apply` or curl `/admin/revoke`.
6. Post-action: evidence saved, ticket created, post-mortem if HIGH.

## Risks handled manually
- `/admin/revoke` is not implemented yet — confirm with dev before relying on the flow in production.
- IP ban via iptables doesn't persist across reboot — use `iptables-save` + `netfilter-persistent` or nftables with a file.
- False positive: CGNAT/large NAT can accumulate events from legitimate users. Calibrate the threshold after 30 d of data.
- Evidence logs carry IP + license_id → PII, mind access.
