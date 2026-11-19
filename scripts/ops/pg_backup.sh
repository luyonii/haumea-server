#!/usr/bin/env bash
# pg_backup.sh — daily logical dump, encrypted at rest + sha256 + rotate 30d.
# needs age installed and BACKUP_RECIPIENT env set to age pubkey (age1...).
# Private key stays offline. Checksum covers the ciphertext.
# Env: PGPASSWORD, BACKUP_RECIPIENT. PGHOST/PGUSER/PGDB opcionais.
set -euo pipefail

: "${PGPASSWORD:?PGPASSWORD env obrigatorio}"
: "${BACKUP_RECIPIENT:?BACKUP_RECIPIENT (age pubkey) obrigatorio — nao gerar plaintext}"
PGHOST="${PGHOST:-localhost}"
PGUSER="${PGUSER:-secblind}"
PGDB="${PGDB:-secblind}"
DEST="${BACKUP_DIR:-/var/backup/postgres/daily}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
FILE="$DEST/secblind-$STAMP.dump.age"

mkdir -p "$DEST"

# Dump custom format + compressao 6, cifra com age (pipe, sem plaintext em disco).
pg_dump -h "$PGHOST" -U "$PGUSER" -Fc -Z 6 -d "$PGDB" | age -r "$BACKUP_RECIPIENT" -o "$FILE"

# Checksum sobre o ciphertext.
sha256sum "$FILE" > "$FILE.sha256"

# Rotate 30d.
find "$DEST" -type f \( -name 'secblind-*.dump.age' -o -name 'secblind-*.dump.age.sha256' \) -mtime +30 -delete

echo "backup ok: $FILE"
