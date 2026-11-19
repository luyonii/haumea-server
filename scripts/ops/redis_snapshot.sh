#!/usr/bin/env bash
# redis_snapshot.sh — BGSAVE + encrypt (age) + rsync offsite.
# needs age installed and BACKUP_RECIPIENT env set to age pubkey (age1...). Private key stays offline.
# Env: REDIS_PASSWORD, OFFSITE, BACKUP_RECIPIENT. REDIS_HOST/REDIS_DIR opcionais.
# OFFSITE: destino rsync, e.g. "user@host:/backup/redis/" ou "s3-mount/redis/".
set -euo pipefail

: "${REDIS_PASSWORD:?REDIS_PASSWORD env obrigatorio}"
: "${OFFSITE:?OFFSITE destino rsync obrigatorio}"
: "${BACKUP_RECIPIENT:?BACKUP_RECIPIENT (age pubkey) obrigatorio — nao exportar plaintext}"
REDIS_HOST="${REDIS_HOST:-127.0.0.1}"
REDIS_DIR="${REDIS_DIR:-/var/lib/redis}"

# redis-cli le REDISCLI_AUTH do ambiente: mantem a senha fora de argv/ps.
export REDISCLI_AUTH="$REDIS_PASSWORD"
unset REDIS_PASSWORD
trap 'unset REDISCLI_AUTH' EXIT

# Trigger snapshot assincrono, aguarda LASTSAVE mudar.
LAST_BEFORE=$(redis-cli -h "$REDIS_HOST" --no-auth-warning LASTSAVE)
redis-cli -h "$REDIS_HOST" --no-auth-warning BGSAVE > /dev/null

NOW="$LAST_BEFORE"
for _ in $(seq 1 60); do
    sleep 2
    NOW=$(redis-cli -h "$REDIS_HOST" --no-auth-warning LASTSAVE)
    [ "$NOW" != "$LAST_BEFORE" ] && break
done
[ "$NOW" = "$LAST_BEFORE" ] && { echo "BGSAVE nao concluiu em 120s" >&2; exit 1; }

# Cifra em tmp dir e envia offsite. Plaintext nao sai do host.
STAGE="$(mktemp -d)"
chmod 700 "$STAGE"
trap 'rm -rf "$STAGE"; unset REDISCLI_AUTH' EXIT

age -r "$BACKUP_RECIPIENT" -o "$STAGE/dump.rdb.age" < "$REDIS_DIR/dump.rdb"
if [ -f "$REDIS_DIR/appendonly.aof" ]; then
    age -r "$BACKUP_RECIPIENT" -o "$STAGE/appendonly.aof.age" < "$REDIS_DIR/appendonly.aof"
fi

rsync -a --partial "$STAGE"/*.age "$OFFSITE/"

echo "snapshot ok -> $OFFSITE"
