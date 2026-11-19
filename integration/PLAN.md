# Integration harness plan

Goal: end-to-end smoke test of the commercial license server + loader
pair. Prove the C++ loader in `Project1\` talks byte-for-byte to the Go
license server in `server\` over TLS 1.3 with a leaf-DER SHA-256
fingerprint check, loads a dummy licensed DLL, and the runtime integrity
watchdog survives.

## Topology

```
loader.exe  --TLS1.3-->  nginx:443 (container)  --HTTP-->  host 127.0.0.1:8080 (go server, run by user)
                                                               |
                                 docker compose network:  postgres:5432, redis:6379
```

- Nginx terminates TLS with a self-signed leaf cert for `secblind.local`.
- Client pins the SHA-256 of that leaf's DER.
- Go server stays plain HTTP on host (per `server/README.md`). No server code change.

## Steps

1. `docker compose up -d postgres redis` — DB + cache up.
2. Apply `server/migrations/0001_init.sql` via a one-shot psql.
3. `scripts/build_dummy_payload.ps1` — compile `dummy_payload/payload.c` → `payload.dll` (Developer PowerShell for VS 2026). Stands in for the vendor's commercial binary.
4. `scripts/seed_license.ps1` — generate a `TEST-...` activation code, insert into `licenses`, insert PE bytes into `payload_builds`.
5. `scripts/gen_cert.ps1` — self-signed leaf for `secblind.local`, export DER + key, print SHA-256 hex.
6. User patches `Project1\src\net.cpp` lines 161-162 (both fingerprints = same hash, or one placeholder cleared) and `Project1\src\Main.cpp` line 103 host → `secblind.local`. Rebuild.
7. `docker compose up -d nginx` — reverse proxy with the new cert.
8. User adds `127.0.0.1 secblind.local` to `C:\Windows\System32\drivers\etc\hosts`.
9. User starts the Go server on host: `.\server.exe .\config.yaml` with `SB_MASTER_SECRET` set.
10. User runs the rebuilt loader; watch nginx + go logs for `/auth/challenge → login → heartbeat → payload/fetch`; MessageBox from the DLL confirms end-to-end.

## Tradeoffs

- Nginx vs. direct TLS in Go: Nginx keeps the server untouched and matches the shipped README. Cost: one more container.
- Self-signed vs. mkcert: self-signed is one PowerShell cmdlet, no extra install. The client fingerprint doesn't care about the trust chain.
- Dummy licensed binary = DLL with MessageBox: proves PE map + entrypoint; no network side effects.

## What this harness does NOT do

- No automated client run / assertion. User launches the loader and eyeballs.
- No CI, no teardown scripts (docker compose down is one line, not worth a wrapper).
- No HWID pre-seeding — first login binds whatever the loader reports.
