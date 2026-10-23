#!/bin/sh
# Smoke checks of the running conformance bench, with OpenSSL as the judge:
# the PKI chain, the CRL, both TSAs and the OCSP responder. Exits non-zero on the first failure.
set -eu

BENCH="$(cd "$(dirname "$0")" && pwd)"
PKI="$BENCH/pki/out"
DSS_URL="${NACRE_DSS_URL:-http://127.0.0.1:18080}"
PKI_URL="http://127.0.0.1:18081"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

wait_for() {
  url="$1"
  deadline=$(($(date +%s) + 300))
  until [ "$(curl -s --max-time 10 -o /dev/null -w '%{http_code}' "$url")" = 200 ]; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
      fail "$url did not answer 200 within 300 s"
    fi
    sleep 2
  done
  echo "ok: $url answers 200"
}

[ -f "$PKI/root.cert.pem" ] || fail "no PKI in $PKI: run pki-init first (conformance/README.md)"

wait_for "$DSS_URL/"
wait_for "$PKI_URL/crl/intermediate.crl"

openssl verify -CAfile "$PKI/root.cert.pem" -untrusted "$PKI/intermediate.cert.pem" \
  "$PKI/signer.cert.pem" "$PKI/tsa.cert.pem" "$PKI/tsa2.cert.pem" || fail "the PKI chain does not verify"

revoked_serial="$(openssl x509 -in "$PKI/revoked.cert.pem" -noout -serial | cut -d= -f2)"
curl -sf --max-time 30 -o "$work/intermediate.crl" "$PKI_URL/crl/intermediate.crl" || fail "no CRL served"
openssl crl -inform DER -in "$work/intermediate.crl" -CAfile "$PKI/intermediate.cert.pem" \
  -noout -verify 2>&1 | grep -q 'verify OK' || fail "intermediate.crl is not signed by the intermediate"
openssl crl -inform DER -in "$work/intermediate.crl" -noout -text |
  grep -q "Serial Number: $revoked_serial" || fail "intermediate.crl does not list $revoked_serial"
echo "ok: intermediate.crl lists the revoked serial $revoked_serial"

echo "Nacre conformance bench" > "$work/data"
openssl ts -query -data "$work/data" -sha256 -cert -out "$work/query.tsq" 2> /dev/null
# Each endpoint must answer with a token that verifies and is signed by its own TSA.
for pair in "tsa:Nacre Test TSA" "tsa2:Nacre Test Document TSA"; do
  endpoint="${pair%%:*}"
  name="${pair#*:}"
  curl -sf --max-time 30 -H 'Content-Type: application/timestamp-query' --data-binary "@$work/query.tsq" \
    -o "$work/$endpoint.tsr" "$PKI_URL/cgi-bin/$endpoint" || fail "$endpoint did not answer"
  openssl ts -verify -data "$work/data" -in "$work/$endpoint.tsr" -CAfile "$PKI/root.cert.pem" \
    -untrusted "$PKI/intermediate.cert.pem" 2> /dev/null | grep -q 'Verification: OK' ||
    fail "the $endpoint token does not verify"
  openssl ts -reply -in "$work/$endpoint.tsr" -text 2> /dev/null |
    grep -q "^TSA: .*CN *= *$name\$" || fail "the $endpoint token is not signed by $name"
  echo "ok: $endpoint answers a verifiable token signed by $name"
done

ocsp_status() {
  openssl ocsp -url "$PKI_URL/cgi-bin/ocsp" -issuer "$PKI/intermediate.cert.pem" \
    -cert "$PKI/$1.cert.pem" -CAfile "$PKI/root.cert.pem" 2> /dev/null |
    sed -n "s|^.*$1.cert.pem: ||p"
}
for pair in signer:good revoked:revoked; do
  cert="${pair%%:*}"
  expected="${pair#*:}"
  status="$(ocsp_status "$cert")"
  if [ "$status" != "$expected" ]; then
    fail "OCSP says '$status' for $cert, expected '$expected'"
  fi
  echo "ok: OCSP says $status for $cert"
done

echo "bench ready"
