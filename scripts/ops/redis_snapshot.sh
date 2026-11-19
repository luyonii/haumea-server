#!/usr/bin/env bash
# redis_snapshot.sh — BGSAVE + rsync offsite.
# Env: REDIS_PASSWORD obrigatorio. REDIS_HOST (default 127.0.0.1), REDIS_DIR (default /var/lib/redis).
# OFFSITE: destino rsync, e.g. "user@host:/backup/redis/" ou "s3-mount/redis/".
set -euo pipefail

: "${REDIS_PASSWORD:?REDIS_PASSWORD env obrigatorio}"
: "${OFFSITE:?OFFSITE destino rsync obrigatorio}"
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

# Copia dump.rdb + appendonly.aof para offsite.
rsync -a --partial "$REDIS_DIR/dump.rdb" "$REDIS_DIR/appendonly.aof" "$OFFSITE/" 2>/dev/null || \
    rsync -a --partial "$REDIS_DIR/dump.rdb" "$OFFSITE/"

echo "snapshot ok -> $OFFSITE"
