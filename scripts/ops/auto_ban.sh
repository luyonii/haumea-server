#!/usr/bin/env bash
# auto_ban.sh — IPs com > THRESHOLD eventos no abuse_log nos ultimos 10min viram iptables DROP.
# Dry-run por default. --apply para executar.
# Env: PGPASSWORD, PGHOST, PGUSER, PGDB.
set -euo pipefail

APPLY=0
[ "${1:-}" = "--apply" ] && APPLY=1

: "${PGPASSWORD:?PGPASSWORD env obrigatorio}"
PGHOST="${PGHOST:-localhost}"
PGUSER="${PGUSER:-secblind}"
PGDB="${PGDB:-secblind}"
THRESHOLD="${BAN_THRESHOLD:-50}"
LOG="${AUTOBAN_LOG:-/var/log/secblind/autoban.log}"

mkdir -p "$(dirname "$LOG")"

# shortcut: janela fixa 10min, THRESHOLD por IP, upgrade = sliding window + per-reason weighting.
SQL="SELECT ip, count(*) AS n
     FROM abuse_log
     WHERE ts > now() - interval '10 minutes'
     GROUP BY ip
     HAVING count(*) > $THRESHOLD
     ORDER BY n DESC;"

mapfile -t ROWS < <(psql -h "$PGHOST" -U "$PGUSER" -d "$PGDB" -tA -F '|' -c "$SQL")

if [ "${#ROWS[@]}" -eq 0 ]; then
    echo "nenhum IP acima do threshold ($THRESHOLD/10min)"
    exit 0
fi

TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
for row in "${ROWS[@]}"; do
    [ -z "$row" ] && continue
    IP="${row%%|*}"
    N="${row##*|}"

    # Validacao basica IPv4/IPv6 — nunca passar input raw pra iptables.
    if ! [[ "$IP" =~ ^[0-9a-fA-F:.]+$ ]]; then
        echo "skip IP invalido: $IP" >&2
        continue
    fi

    if [ "$APPLY" -eq 1 ]; then
        # Idempotente: adiciona so se nao existe.
        if ! iptables -C INPUT -s "$IP" -j DROP 2>/dev/null; then
            iptables -A INPUT -s "$IP" -j DROP
            echo "$TS BAN $IP events=$N" | tee -a "$LOG"
        else
            echo "$TS SKIP $IP ja banido events=$N" | tee -a "$LOG"
        fi
    else
        echo "DRYRUN BAN $IP events=$N"
    fi
done

[ "$APPLY" -eq 0 ] && echo "dry-run. use --apply para executar."
