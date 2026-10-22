#!/bin/sh
# Signs the bench's reference PDFs into out/ (ignored by git) with the running DSS and the
# PKI pki-init just generated; run at every bench start, since the keys change each time.
# With --record, also keeps DSS's validation answer for each as a corpus file of
# nacre-conformance (only when the DSS version moves).
# DSS only lays the signature out: the bench's own keys sign, with OpenSSL. Needs curl, jq,
# openssl and the bench up (conformance/README.md).
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
PKI="$HERE/../pki/out"
OUT="$HERE/out"
CORPUS="$HERE/../../crates/nacre-conformance/tests/corpus"
DSS_URL="${NACRE_DSS_URL:-http://127.0.0.1:18080}"
REST="$DSS_URL/services/rest"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

b64() { openssl base64 -A -in "$1"; }
der_b64() { openssl x509 -in "$1" -outform DER -out "$work/cert.der" && b64 "$work/cert.der"; }

post() {
  curl -sf -H 'Content-Type: application/json' -H 'Accept: application/json' \
    --data-binary "@$2" -o "$3" "$REST/$1"
}

# sign <certificate stem> <output pdf>
sign() {
  signing_date="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
  jq -n \
    --arg doc "$(b64 "$HERE/unsigned.pdf")" \
    --arg cert "$(der_b64 "$PKI/$1.cert.pem")" \
    --arg chain "$(der_b64 "$PKI/intermediate.cert.pem")" \
    --arg date "$signing_date" \
    '{
      parameters: {
        signatureLevel: "PAdES_BASELINE_B",
        signaturePackaging: "ENVELOPED",
        digestAlgorithm: "SHA256",
        encryptionAlgorithm: "ECDSA",
        signingCertificate: { encodedCertificate: $cert },
        certificateChain: [ { encodedCertificate: $chain } ],
        blevelParams: { signingDate: $date }
      },
      toSignDocument: { bytes: $doc, name: "unsigned.pdf" }
    }' > "$work/params.json"

  post signature/one-document/getDataToSign "$work/params.json" "$work/tbs.json"
  jq -r .bytes "$work/tbs.json" | openssl base64 -d -A -out "$work/tbs.bin"
  openssl dgst -sha256 -sign "$PKI/$1.key.pem" -out "$work/sig.der" "$work/tbs.bin"

  jq --arg value "$(b64 "$work/sig.der")" \
    '. + { signatureValue: { algorithm: "ECDSA_SHA256", value: $value } }' \
    "$work/params.json" > "$work/sign.json"
  post signature/one-document/signDocument "$work/sign.json" "$work/signed.json"
  jq -r .bytes "$work/signed.json" | openssl base64 -d -A -out "$2"
  echo "signed $2 with $1 at $signing_date"
}

# record <signed pdf> <corpus file>
record() {
  jq -n --arg doc "$(b64 "$1")" --arg name "$(basename "$1")" \
    '{ signedDocument: { bytes: $doc, name: $name }, originalDocuments: [], policy: null,
       signatureId: null }' > "$work/validate.json"
  post validation/validateSignature "$work/validate.json" "$2"
  echo "recorded $2: $(jq -c '[.SimpleReport.signatureOrTimestampOrEvidenceRecord[]?.Signature
    | {Indication, SubIndication, SignatureFormat}]' "$2")"
}

case "${1:-}" in
  '') record=no ;;
  --record) record=yes ;;
  *) echo "usage: $0 [--record]" >&2; exit 2 ;;
esac
[ -f "$PKI/signer.key.pem" ] || { echo "no PKI in $PKI: run pki-init first" >&2; exit 1; }

mkdir -p "$OUT"
sign signer "$OUT/pades-baseline-b.pdf"
sign revoked "$OUT/pades-baseline-b-revoked.pdf"
if [ "$record" = yes ]; then
  record "$OUT/pades-baseline-b.pdf" "$CORPUS/dss-6.5.1-pades-baseline-b.json"
  record "$OUT/pades-baseline-b-revoked.pdf" "$CORPUS/dss-6.5.1-pades-baseline-b-revoked.json"
fi
