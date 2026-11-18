#!/usr/bin/env bash
# pg_backup.sh — daily logical dump + sha256 + rotate 30d.
# Env: PGPASSWORD, PGHOST (default localhost), PGUSER (default secblind), PGDB (default secblind).
set -euo pipefail

: "${PGPASSWORD:?PGPASSWORD env obrigatorio}"
PGHOST="${PGHOST:-localhost}"
PGUSER="${PGUSER:-secblind}"
PGDB="${PGDB:-secblind}"
DEST="${BACKUP_DIR:-/var/backup/postgres/daily}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
FILE="$DEST/secblind-$STAMP.dump"

mkdir -p "$DEST"

# Dump custom format + compressao nivel 6.
pg_dump -h "$PGHOST" -U "$PGUSER" -Fc -Z 6 -d "$PGDB" -f "$FILE"

# Checksum.
sha256sum "$FILE" > "$FILE.sha256"

# Rotate 30d.
find "$DEST" -type f \( -name 'secblind-*.dump' -o -name 'secblind-*.dump.sha256' \) -mtime +30 -delete

echo "backup ok: $FILE"
