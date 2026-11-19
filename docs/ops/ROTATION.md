# ROTATION — Credentials, Certs, Keys

## TLS leaf cert — pinned in the client

The client validates the SHA-256 fingerprint of the public key (SubjectPublicKeyInfo). Two fingerprints in `Project1/src/net.cpp`:
- `pin1` — active leaf
- `pin2` — backup leaf (`pin_leaf_backup`)

**Rotate is ONLY safe if the new leaf matches `pin1` OR `pin2`.** Otherwise the client refuses the handshake.

### Procedure
1. Get/generate the new cert (LE, internal, etc).
2. Compute the public-key fingerprint:
   ```bash
   openssl x509 -in new-cert.pem -pubkey -noout \
     | openssl pkey -pubin -outform DER \
     | openssl dgst -sha256 -binary \
     | xxd -p -c 256
   ```
3. Compare with `pin2` in `Project1/src/net.cpp` (line ~168).
4. If MATCH: rotate on the server, swap `pin1 := pin2`, generate a new `pin2` for the next cycle (new client release).
5. If MISMATCH: **ABORT**. Pre-rotate flow:
   - Generate the key/cert for the next rotate.
   - Update `pin2` in the client to that new cert's public-key fingerprint.
   - Publish a new client release, wait for adoption > 95% (version telemetry).
   - Then rotate on the server.

Script: `scripts/ops/rotate_cert_check.sh` / `.ps1`. Takes the new cert as argument, extracts the pins from `net.cpp`, reports MATCH/MISMATCH.

### Cadence
- LE: 60 days (renewal 30 before expiry).
- Internal CA: 1 year. Key reuse only 1 cycle; rotate key every 2 years.

## HKDF salt

Constant `"SecBlind_HKDF_v1"` shared by client+server. Every session derives from it.

### Rotation
- Normal: 24 months.
- Forced: suspected server compromise, key material leak, crypto incident.
- Procedure:
  1. New value: `"SecBlind_HKDF_v2"`.
  2. Server accepts v1 **AND** v2 for a 72 h window (dual-accept): try v2 first, fallback v1.
  3. New client release with v2.
  4. After adoption > 99% + 72 h, remove v1 from the server. Old sessions invalidated, old clients stop authenticating — intended behavior.

## Admin token (`/api/v1/admin/revoke` and admin endpoints)

- Storage: HashiCorp Vault (`secret/secblind/admin-token`) or AWS Secrets Manager.
- Rotation: monthly, automatic via Vault dynamic secret or scheduled script.
- Procedure:
  1. Generate a new token (32 B random, `openssl rand -hex 32`).
  2. Deploy the server with `ADMIN_TOKEN_NEXT=<new>` + `ADMIN_TOKEN=<current>` (dual-accept).
  3. Rotate the token in use by operators (CLI, dashboards).
  4. Final deploy: `ADMIN_TOKEN=<new>`, remove `ADMIN_TOKEN_NEXT`.
- Emergency revocation: invalidate and redeploy without a window. Operators pick up the new token from Vault.

## Postgres + Redis passwords

- Rotation: quarterly.
- Zero-downtime via dual-password overlap (Postgres: `CREATE USER secblind_new`; Redis >= 6: ACL with two users).
- Postgres procedure:
  1. `ALTER USER secblind WITH PASSWORD '<new>';`
  2. Secrets manager updated.
  3. Rolling restart of the server.
- Redis 6+ procedure:
  1. `ACL SETUSER secblind on >newpass ~* +@all`
  2. Secrets updated + rolling restart.
  3. Remove old password: `ACL SETUSER secblind <newpass only>`.

## Rotation checklist (any kind)

- [ ] Backup current secret in an offline vault (emergency break-glass).
- [ ] New secret generated with a CSPRNG source (not `rand()`, not timestamps).
- [ ] Dual-accept window configured before deploy.
- [ ] Rollback plan tested on staging.
- [ ] Monitoring on for the spike of auth errors during the rotation window.
- [ ] Post-mortem in the rotation log (`docs/ops/rotation-log.md`).

## Risks handled manually
- Vault/ASM: high availability + its own vault backup (losing the vault = losing everything).
- MFA on human access to the vault.
- Secret-read audit log (SIEM).
