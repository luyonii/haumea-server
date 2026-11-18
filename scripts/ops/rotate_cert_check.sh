#!/usr/bin/env bash
# rotate_cert_check.sh — compara SPKI SHA-256 do novo cert com pin1/pin2 em Project1/src/net.cpp.
# Uso: ./rotate_cert_check.sh <path/to/new-cert.pem>
set -euo pipefail

CERT="${1:-}"
[ -z "$CERT" ] && { echo "uso: $0 <new-cert.pem>" >&2; exit 2; }
[ -f "$CERT" ] || { echo "cert nao encontrado: $CERT" >&2; exit 2; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NET_CPP="$SCRIPT_DIR/../../Project1/src/net.cpp"
[ -f "$NET_CPP" ] || { echo "nao achei net.cpp em $NET_CPP" >&2; exit 2; }

# Hash SPKI do novo cert.
NEW_HASH=$(openssl x509 -in "$CERT" -pubkey -noout \
    | openssl pkey -pubin -outform DER \
    | openssl dgst -sha256 -binary \
    | xxd -p -c 256)

# Extrai pins dos literais OBF("...") adjacentes a pin1/pin2.
# Formato esperado em net.cpp: auto pin1 = OBF("<64hex>"); e idem pin2.
PIN1=$(grep -oE 'pin1[[:space:]]*=[[:space:]]*OBF\("[0-9a-fA-F]{64}"\)' "$NET_CPP" | grep -oE '[0-9a-fA-F]{64}' | head -1 || true)
PIN2=$(grep -oE 'pin2[[:space:]]*=[[:space:]]*OBF\("[0-9a-fA-F]{64}"\)' "$NET_CPP" | grep -oE '[0-9a-fA-F]{64}' | head -1 || true)

echo "new SPKI sha256: $NEW_HASH"
echo "pin1 (ativo):    ${PIN1:-<nao-extraido>}"
echo "pin2 (backup):   ${PIN2:-<nao-extraido>}"

if [ "$NEW_HASH" = "$PIN1" ]; then
    echo "MATCH: bate com pin1 (ativo). Rotate seguro (sem efeito util)."
    exit 0
elif [ "$NEW_HASH" = "$PIN2" ]; then
    echo "MATCH: bate com pin2 (backup). Rotate seguro. Lembrar de gerar novo pin2 para proximo ciclo."
    exit 0
else
    echo "MISMATCH: novo cert nao bate com nenhum pin. ABORT rotate — cliente vai recusar." >&2
    exit 1
fi
