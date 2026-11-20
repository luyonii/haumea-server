#!/usr/bin/env bash
# rotate_cert.sh — provision the standby (pin2) cert for zero-downtime rotation.
#
# WHEN TO RUN: quarterly, or immediately on suspected key/cert compromise, or
# when the live leaf is within ~30d of expiry. Run as root on the VPS.
#
# WHAT IT DOES:
#   1. Generates a fresh RSA-2048 keypair + self-signed leaf (same CN/SANs as
#      prod, 365d, basicConstraints CA:TRUE critical — required so SChannel can
#      load it in LocalMachine\Root for the WinHTTP path).
#   2. Writes it to /root/.secblind/next.{crt,key}, chmod 400, owner root.
#   3. Prints the SHA-256 of the FULL DER certificate. THIS is the value that
#      goes into pin2 at Project1/src/net.cpp.
#
# PIN DERIVATION NOTE (important): the loader's verify_cert_pin() hashes
# CERT_CONTEXT.pbCertEncoded, i.e. the ENTIRE DER-encoded leaf — NOT the SPKI.
# pin1 (the live prod cert) is also a full-cert-DER hash. So pin2 must be the
# full-cert-DER hash too, or the pin check can never match the standby cert.
# The SPKI hash is printed below for reference only; do not paste it into
# net.cpp while the loader pins the full cert.
#
# SWAP PROCEDURE (zero-downtime; the loader already trusts pin2 == next.crt):
#   a. Build+ship a loader release whose pin2 == the hash printed below, so
#      fielded clients accept BOTH the current leaf (pin1) and next.crt (pin2).
#   b. On the VPS, swap the live cert for the standby:
#        cp /root/.secblind/next.crt /home/sam/secblind/integration/nginx/cert/leaf.crt
#        cp /root/.secblind/next.key /home/sam/secblind/integration/nginx/cert/leaf.key
#        docker exec integration-nginx-1 nginx -t && \
#        docker exec integration-nginx-1 nginx -s reload
#   c. nginx now serves next.crt; old clients still match via pin2, so no
#      downtime. In the NEXT loader release, set pin1 := this hash and generate
#      a fresh pin2 with this script again (pin1 and pin2 must never be equal,
#      or the dual-pin rotation buffer is gone).
set -euo pipefail

OUT_DIR="${SECBLIND_NEXT_DIR:-/root/.secblind}"
CN="secblind.local"
SAN="DNS:secblind.local, IP:65.108.60.114"
DAYS=365

crt="$OUT_DIR/next.crt"
key="$OUT_DIR/next.key"

mkdir -p "$OUT_DIR"

cfg="$(mktemp)"
trap 'rm -f "$cfg"' EXIT
cat > "$cfg" <<EOF
[req]
distinguished_name = dn
x509_extensions = v3
prompt = no
[dn]
CN = $CN
[v3]
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, keyCertSign, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = $SAN
EOF

openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$key" -out "$crt" -days "$DAYS" \
    -config "$cfg" -outform PEM >/dev/null 2>&1

chmod 400 "$crt" "$key"
chown root:root "$crt" "$key" 2>/dev/null || true

# Self-check: cert must parse and carry CA:TRUE, and the pin hash must be 64 hex.
if ! openssl x509 -in "$crt" -noout -ext basicConstraints 2>/dev/null | grep -q "CA:TRUE"; then
    echo "FATAL: generated cert missing basicConstraints CA:TRUE" >&2
    exit 1
fi

pin="$(openssl x509 -in "$crt" -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1)"
if ! printf '%s' "$pin" | grep -Eq '^[0-9a-f]{64}$'; then
    echo "FATAL: computed pin is not 64 hex chars: '$pin'" >&2
    exit 1
fi

spki="$(openssl x509 -in "$crt" -pubkey -noout \
    | openssl pkey -pubin -outform DER \
    | openssl dgst -sha256 -r | cut -d' ' -f1)"

echo
echo "Standby cert written:"
echo "  $crt (chmod 400, root)"
echo "  $key (chmod 400, root)"
echo
echo "=> NEW pin2 for Project1/src/net.cpp (full-cert DER SHA-256):"
echo "   $pin"
echo
echo "   (SPKI SHA-256, reference only, NOT the current pin: $spki)"
echo
echo "Next: set pin2 at net.cpp to the value above, rebuild the loader, ship it,"
echo "then follow the SWAP PROCEDURE comment at the top of this script."
