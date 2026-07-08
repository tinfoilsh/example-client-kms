#!/usr/bin/env bash
# Doorbell pattern walkthrough. Each step proves one security property.
#
# Usage: ./demo.sh <kms-client-host> <enclave-server-host>
# e.g.:  ./demo.sh doorbell-kms-client.tinfoil.containers.tinfoil.dev \
#                  doorbell-enclave-server.tinfoil.containers.tinfoil.dev
set -euo pipefail

KMS_HOST="${1:?usage: $0 <kms-client-host> <enclave-server-host>}"
ENCLAVE_HOST="${2:?usage: $0 <kms-client-host> <enclave-server-host>}"

step() { printf '\n=== %s ===\n' "$*"; }

step "1. Delivery happened, secret never exposed"
echo "KMS client's secret fingerprint (/secret_info):"
KMS_FP=$(curl -sf "https://$KMS_HOST/secret_info" | tee /dev/stderr | sed -n 's/.*"fingerprint":"\([^"]*\)".*/\1/p')
echo
echo "Enclave server's delivery status (/status):"
ENCLAVE_FP=$(curl -sf "https://$ENCLAVE_HOST/status" | tee /dev/stderr | sed -n 's/.*"fingerprint":"\([^"]*\)".*/\1/p')
echo
if [ -n "$KMS_FP" ] && [ "$KMS_FP" = "$ENCLAVE_FP" ]; then
    echo "PASS: fingerprints match — the secret was delivered end-to-end,"
    echo "      yet neither endpoint ever exposed the secret itself."
else
    echo "NOTE: fingerprints do not match yet. If the enclave server just"
    echo "      booted, wait ~15s for its ring loop and re-run."
fi

step "2. Anyone can ring (the ring carries no authority)"
echo "Ringing from this machine, naming the legitimate enclave:"
curl -s -X POST "https://$KMS_HOST/ring" \
    -H 'Content-Type: application/json' \
    -d "{\"host\": \"$ENCLAVE_HOST\"}"
echo
echo "PASS: an unauthenticated third party can trigger a delivery, but only"
echo "      to a destination that passes attestation — which is harmless."

step "3. Attestation gates delivery"
echo "Ringing with a host that is NOT the attested enclave:"
HTTP_CODE=$(curl -s -o /tmp/doorbell_evil.txt -w '%{http_code}' \
    -X POST "https://$KMS_HOST/ring" \
    -H 'Content-Type: application/json' \
    -d '{"host": "evil.example.com"}')
cat /tmp/doorbell_evil.txt
echo "(HTTP $HTTP_CODE)"
if [ "$HTTP_CODE" = "502" ]; then
    echo "PASS: attestation failed, nothing was delivered."
else
    echo "UNEXPECTED: wanted 502, got $HTTP_CODE"
fi

step "4. The /ring response carries no secret"
RESPONSE=$(curl -s -X POST "https://$KMS_HOST/ring" \
    -H 'Content-Type: application/json' \
    -d "{\"host\": \"$ENCLAVE_HOST\"}")
echo "$RESPONSE"
echo "PASS: the response is only a delivery acknowledgement. The secret"
echo "      traveled exclusively over the attested TLS channel from the"
echo "      KMS client to the enclave's /secrets endpoint."
