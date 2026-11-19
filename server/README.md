# Sec-blind server

Go backend for the commercial license server that the C++ client in
`..\Project1` talks to.

## Build

```powershell
cd server
go mod tidy
go build .\cmd\server
```

## Infra

PostgreSQL 16 and Redis 7 running locally.

```powershell
# Create DB and apply schema
psql -U postgres -c "CREATE USER secblind WITH PASSWORD 'secblind';"
psql -U postgres -c "CREATE DATABASE secblind OWNER secblind;"
psql -U secblind -d secblind -f .\migrations\0001_init.sql
```

Redis just needs to be reachable at the `redis_addr` from `config.yaml`.

## Config

Copy the example and set the master secret (32 random bytes as 64 hex chars):

```powershell
Copy-Item .\config.yaml.example .\config.yaml
$env:SB_MASTER_SECRET = -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Max 256) })
```

## Seed a test license

```powershell
psql -U secblind -d secblind -c "INSERT INTO licenses (license_key) VALUES ('TEST-1234-5678-ABCD');"
# Later, upload the licensed binary for that activation code (replace with your build):
psql -U secblind -d secblind -c "INSERT INTO payload_builds (license_id, pe_bytes) VALUES ((SELECT id FROM licenses WHERE license_key='TEST-1234-5678-ABCD'), pg_read_binary_file('C:/path/to/payload.dll'));"
```

## Run

Kill any old `server.exe` first, or the stale binary keeps `:8443` bound and the
fresh build never comes up:

```powershell
# Build fresh and run (from server\)
Get-Process server -ErrorAction SilentlyContinue | Stop-Process -Force
go build .\cmd\server
.\server.exe .\config.yaml
```

Listens plain HTTP on the address in `config.yaml`. Terminate TLS 1.3 at
Nginx and reverse-proxy to this port. The client pins the leaf cert
SHA-256; see `Project1\src\net.cpp`.

## Tests

```powershell
go test .\pkg\crypto\...
```

Covers RFC 5869 HKDF vector, RFC 4231 HMAC vector, NIST AES-GCM vector,
and an AES-GCM round-trip.

## Endpoints

All under `/api/v1`. See `..\SERVER_SPEC.md` for shapes.

- `POST /auth/challenge`
- `POST /auth/login`
- `POST /session/heartbeat`
- `POST /payload/fetch`
- `POST /rpc/call` (method `ping` implemented)

## Admin API

Separate private listener (`admin_addr` in `config.yaml`, default loopback-only).
Auth: `X-Admin-Token: $SB_ADMIN_TOKEN` (constant-time compare).

Create license (body optional):

```powershell
curl -k -X POST https://127.0.0.1:8443/api/v1/admin/license `
  -H "X-Admin-Token: $env:SB_ADMIN_TOKEN" `
  -H "Content-Type: application/json" `
  -d '{"prefix":"SB","note":"discord_user:123"}'
# -> 201 { "license_key": "SB-ABCDEF0123456789", "license_id": 42, "created_at": "..." }
```

Status:

```powershell
curl -k https://127.0.0.1:8443/api/v1/admin/license/SB-ABCDEF0123456789 `
  -H "X-Admin-Token: $env:SB_ADMIN_TOKEN"
# -> 200 { license_key, license_id, banned, revoked, revoked_at, hwid_bound,
#         hwid_hex (truncated 16), bound_at, killed, created_at, note }
```

Revoke:

```powershell
curl -k -X POST https://127.0.0.1:8443/api/v1/admin/revoke `
  -H "X-Admin-Token: $env:SB_ADMIN_TOKEN" `
  -H "Content-Type: application/json" `
  -d '{"license_key":"SB-ABCDEF0123456789"}'
```

## Deviations from `SERVER_PLAN.md`

Driven by the shipped client source; see `PLAN.md`:

1. Login HKDF: salt = `hwid_hex_bytes || "SecBlind_HKDF_v1"`, info empty.
   `licenses.session_salt` dropped.
2. Session-binding `[0..32]` = hex-decoded HWID (32 raw bytes), not
   `SHA-256(hwid_hex_bytes)`.
