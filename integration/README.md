# Sec-blind integration harness

End-to-end runbook for the commercial license-server smoke test:
infra + license server + loader + dummy licensed DLL. Everything below
runs from `integration\` unless noted.

## Prereqs
- Docker Desktop (Windows), Developer PowerShell for VS 2026, Go toolchain.
- Admin shell once to edit `hosts`.

## Runbook

1. **Start infra (Postgres + Redis)**
   ```powershell
   docker compose up -d postgres redis
   ```

2. **Build dummy licensed DLL** (Developer PowerShell for VS 2026) — stands in for the vendor's commercial binary
   ```powershell
   .\scripts\build_dummy_payload.ps1
   ```

3. **Seed schema + license + entitled module**
   ```powershell
   .\scripts\seed_license.ps1
   ```
   Note the printed `TEST-XXXX-...` activation code.

   The seed applies only `0001_init.sql`; apply extra migrations by hand. Needed if you plan to test revoke:
   ```powershell
   psql -U secblind -d secblind -f ..\server\migrations\0002_revocation.sql
   ```

4. **Generate self-signed cert and get the fingerprint hash**
   ```powershell
   .\scripts\gen_cert.ps1
   ```
   Copy the printed 64-char lowercase hex SHA-256.

5. **Sync cert pin (only if cert was regenerated)**
   - Compare the SHA-256 printed by `gen_cert.ps1` with `pin_leaf_current` at `Project1\src\net.cpp:166`.
   - If they match, skip to step 6.
   - If they differ (cert was regenerated), replace both pins at `net.cpp:166` and `net.cpp:169` with the new hash (pin2 == pin1 until a rotation key is provisioned).
   - Rebuild `Project1` in VS 2026 (x64 Release).

6. **Map hostname** (admin shell, once)
   ```powershell
   Add-Content C:\Windows\System32\drivers\etc\hosts "`n127.0.0.1 secblind.local"
   ```

7. **Start nginx (TLS front)**
   ```powershell
   docker compose up -d nginx
   ```

8. **Start the Go server on host** (separate shell, from `server\`)
   ```powershell
   cd ..\server
   Copy-Item .\config.yaml.example .\config.yaml -Force
   $env:SB_MASTER_SECRET = -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Max 256) })
   $env:SB_ADMIN_TOKEN = -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Max 256) })
   # main.go resolves admin_token at boot; server exits if SB_ADMIN_TOKEN is unset.
   go run .\cmd\server .\config.yaml
   ```

9. **Run the loader** with the seeded activation code. Expected sequence:
   - `/auth/challenge` → 200
   - `/auth/login` → 200 (binds this machine's HWID on first call)
   - `/session/heartbeat` → 200 every 60s
   - `/payload/fetch` → 200, session-binding verifies, DLL maps, MessageBox `"payload loaded"` appears.

   Watch: `docker compose logs -f nginx` and the Go server stdout.

## Tear down
```powershell
docker compose down -v
```

## Troubleshooting
- `pin mismatch` in loader: re-run `gen_cert.ps1`, re-patch `net.cpp`, rebuild. The nginx cert files must be the exact pair written by the script.
- `connection refused` from nginx to host: Docker Desktop must have `host.docker.internal` enabled (default on Windows).
- TLS handshake fails: confirm `ssl_protocols TLSv1.3;` in `nginx\nginx.conf` and that the client build sets `WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3`.
- Loader connects to the wrong host: check `Main.cpp:114` was patched AND rebuilt (not just edited).
