# BACKUP — Postgres + Redis

Backup/restore runbook. Assumes a Linux host target, admin client via Windows/PowerShell.

## Encryption at rest (mandatory)

All backups (Postgres dump, Redis snapshot) come out encrypted with **age** before touching disk/offsite. Extra dependency on the backup host: the `age` binary (https://github.com/FiloSottile/age) — `apt install age`, `brew install age`, or `go install filippo.io/age/cmd/age@latest`.

- Generate the pair (offline, separate host): `age-keygen -o backup-key.txt`. The `# public key: age1...` line goes to the scripts via `BACKUP_RECIPIENT`; the file (private key) stays offline (physical safe/HSM/Vault).
- `BACKUP_RECIPIENT` env is required. Scripts refuse to run without it — they do not produce plaintext by default.
- Checksum (`sha256sum`) covers the ciphertext. Verification does not require the private key.
- Restore: `age -d -i backup-key.txt file.age > file` before `pg_restore`/copy to `/var/lib/redis/`.

## Postgres

### Daily logical dump
- Schedule: 03:00 UTC, cron.
- Command: `pg_dump -Fc -Z 6 -d secblind -f /var/backup/postgres/daily/secblind-$(date -u +%Y%m%dT%H%M%SZ).dump`
- Credential via `PGPASSWORD` env, never on the CLI.
- Script: `scripts/ops/pg_backup.sh` (Linux) / `scripts/ops/pg_backup.ps1` (Windows admin).
- Retention: 30 days (script removes `mtime +30`).

### Weekly physical basebackup
- Sunday 02:00 UTC.
- Command: `pg_basebackup -D /var/backup/postgres/base/$(date -u +%Y%m%d) -Ft -z -X stream -P`
- WAL archiving enabled in `postgresql.conf`: `archive_mode=on`, `archive_command='test ! -f /var/backup/postgres/wal/%f && cp %p /var/backup/postgres/wal/%f'`.
- Retention: 30 days of base + WAL covering the window.

### Checksum
- For every file produced: `sha256sum file.dump > file.dump.sha256`.
- Periodic verification (weekly): `sha256sum -c *.sha256`.

### Offsite
- Destination: bucket S3 `s3://secblind-backups/postgres/`.
- Versioning: on. Object Lock: Compliance 30d. SSE-KMS (dedicated CMK).
- Upload: `aws s3 cp --sse aws:kms --sse-kms-key-id <arn> ...`.
- Never MFA bypass. Lifecycle: Glacier after 7d, expiration 90d.

### Restore — logical
```bash
# Drop and recreate DB
psql -d postgres -c "DROP DATABASE secblind;"
psql -d postgres -c "CREATE DATABASE secblind OWNER secblind;"
# Decrypt + restore (streaming, no plaintext on disk)
age -d -i backup-key.txt /var/backup/postgres/daily/<dump>.age | pg_restore -d secblind --no-owner --role=secblind
```

### Restore — PITR (basebackup + WAL)
```bash
systemctl stop postgresql
rm -rf /var/lib/postgresql/16/main/*
tar -xzf /var/backup/postgres/base/<date>/base.tar.gz -C /var/lib/postgresql/16/main/
# recovery.signal + postgresql.auto.conf with:
#   restore_command = 'cp /var/backup/postgres/wal/%f %p'
#   recovery_target_time = 'YYYY-MM-DD HH:MM:SS UTC'
touch /var/lib/postgresql/16/main/recovery.signal
chown -R postgres:postgres /var/lib/postgresql/16/main
systemctl start postgresql
# Promote after recovery:
psql -U postgres -c "SELECT pg_wal_replay_resume();"
```

### Restore test
Bi-weekly, on an isolated staging host. Checklist:
1. Restore the latest dump.
2. `SELECT count(*) FROM licenses, abuse_log, sessions;` — counts match the source (within expected drift).
3. Smoke test `/auth/login` against staging.
4. Delete the restore. Test log in `docs/ops/restore-tests.log`.

## Redis

### Dual persistence
`redis.conf`:
```
save 300 1
save 60 10000
appendonly yes
appendfsync everysec
dir /var/lib/redis
```

### Manual snapshot + offsite
- `redis-cli -a $REDIS_PASSWORD BGSAVE`
- Wait for `LASTSAVE` to change.
- Script: `scripts/ops/redis_snapshot.sh` / `.ps1`.
- rsync `/var/lib/redis/dump.rdb` + `appendonly.aof` to offsite S3 every 15 min via cron.
- Retention: 7 days.

### Restore
```bash
systemctl stop redis
age -d -i backup-key.txt /path/to/backup/dump.rdb.age > /var/lib/redis/dump.rdb
age -d -i backup-key.txt /path/to/backup/appendonly.aof.age > /var/lib/redis/appendonly.aof
chown redis:redis /var/lib/redis/*
systemctl start redis
redis-cli -a $REDIS_PASSWORD DBSIZE
```
AOF wins over RDB if `appendonly yes`. If AOF corrupts: `redis-check-aof --fix appendonly.aof`.

## Alerting
- Job failure (exit != 0, or SHA mismatch): PagerDuty P2 immediate.
- Last successful backup > 2h: warning (Opsgenie).
- Last successful backup > 6h: P1.
- S3 PutObject count = 0 in 24h: P2.

## Risks handled manually
- Secrets (`PGPASSWORD`, `REDIS_PASSWORD`, AWS creds) in a secrets manager (Vault/ASM). Never in a versioned `.env`.
- KMS key with annual rotation + deny on delete without MFA.
- Bucket access: dedicated IAM role, only write + list. Delete only via break-glass quorum.
