# BACKUP — Postgres + Redis

Runbook de backup/restore. Assume host Linux target, cliente admin via Windows/PowerShell.

## Postgres

### Daily logical dump
- Horário: 03:00 UTC, cron.
- Comando: `pg_dump -Fc -Z 6 -d secblind -f /var/backup/postgres/daily/secblind-$(date -u +%Y%m%dT%H%M%SZ).dump`
- Credencial via `PGPASSWORD` env, nunca no CLI.
- Script: `scripts/ops/pg_backup.sh` (Linux) / `scripts/ops/pg_backup.ps1` (admin Windows).
- Retenção: 30 dias (script apaga `mtime +30`).

### Weekly physical basebackup
- Domingo 02:00 UTC.
- Comando: `pg_basebackup -D /var/backup/postgres/base/$(date -u +%Y%m%d) -Ft -z -X stream -P`
- WAL archiving habilitado em `postgresql.conf`: `archive_mode=on`, `archive_command='test ! -f /var/backup/postgres/wal/%f && cp %p /var/backup/postgres/wal/%f'`.
- Retenção: 30 dias de base + WAL cobrindo o intervalo.

### Checksum
- Para cada arquivo gerado: `sha256sum file.dump > file.dump.sha256`.
- Verificação periódica (semanal): `sha256sum -c *.sha256`.

### Offsite
- Destino: bucket S3 `s3://secblind-backups/postgres/`.
- Versioning: on. Object Lock: Compliance 30d. SSE-KMS (CMK dedicada).
- Upload: `aws s3 cp --sse aws:kms --sse-kms-key-id <arn> ...`.
- Nunca MFA bypass. Lifecycle: Glacier após 7d, expiração 90d.

### Restore — logical
```bash
# Dropar e recriar DB
psql -d postgres -c "DROP DATABASE secblind;"
psql -d postgres -c "CREATE DATABASE secblind OWNER secblind;"
# Restore
pg_restore -d secblind --no-owner --role=secblind /var/backup/postgres/daily/<dump>
```

### Restore — PITR (basebackup + WAL)
```bash
systemctl stop postgresql
rm -rf /var/lib/postgresql/16/main/*
tar -xzf /var/backup/postgres/base/<date>/base.tar.gz -C /var/lib/postgresql/16/main/
# recovery.signal + postgresql.auto.conf com:
#   restore_command = 'cp /var/backup/postgres/wal/%f %p'
#   recovery_target_time = 'YYYY-MM-DD HH:MM:SS UTC'
touch /var/lib/postgresql/16/main/recovery.signal
chown -R postgres:postgres /var/lib/postgresql/16/main
systemctl start postgresql
# Promote após recovery:
psql -U postgres -c "SELECT pg_wal_replay_resume();"
```

### Teste de restore
Quinzenal, em host staging isolado. Checklist:
1. Restore do último dump.
2. `SELECT count(*) FROM licenses, abuse_log, sessions;` — contagens batem com a origem (dentro de drift esperado).
3. Smoke test `/auth/login` contra staging.
4. Apagar restore. Log de teste em `docs/ops/restore-tests.log`.

## Redis

### Persistence dupla
`redis.conf`:
```
save 300 1
save 60 10000
appendonly yes
appendfsync everysec
dir /var/lib/redis
```

### Snapshot manual + offsite
- `redis-cli -a $REDIS_PASSWORD BGSAVE`
- Aguarda `LASTSAVE` mudar.
- Script: `scripts/ops/redis_snapshot.sh` / `.ps1`.
- rsync `/var/lib/redis/dump.rdb` + `appendonly.aof` para offsite S3 a cada 15min via cron.
- Retenção: 7 dias.

### Restore
```bash
systemctl stop redis
cp /path/to/backup/dump.rdb /var/lib/redis/dump.rdb
cp /path/to/backup/appendonly.aof /var/lib/redis/appendonly.aof
chown redis:redis /var/lib/redis/*
systemctl start redis
redis-cli -a $REDIS_PASSWORD DBSIZE
```
AOF prevalece sobre RDB se `appendonly yes`. Se AOF corromper: `redis-check-aof --fix appendonly.aof`.

## Alerting
- Falha de job (exit != 0, ou SHA mismatch): PagerDuty P2 imediato.
- Último backup bem-sucedido > 2h: warning (Opsgenie).
- Último backup bem-sucedido > 6h: P1.
- Bucket S3 PutObject count = 0 em 24h: P2.

## Riscos cobertos manualmente
- Secrets (`PGPASSWORD`, `REDIS_PASSWORD`, AWS creds) em secrets manager (Vault/ASM). Nunca em `.env` versionado.
- KMS key com rotation anual + deny em delete sem MFA.
- Acesso ao bucket: IAM role dedicada, só write + list. Delete only via quorum break-glass.
