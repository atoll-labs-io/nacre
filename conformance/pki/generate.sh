#!/bin/sh
# Generates a fresh test PKI for the conformance bench in out/ (ADR-0011), which git
# ignores: no private key is ever committed. The compose service pki-init runs it at every
# bench start; it also runs on the host with OpenSSL >= 3.2 (for -jdktrust).
# Every run changes every key and serial: the reference PDFs are signed again afterwards
# (conformance/reference/generate.sh).
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
PKI_DIR="$HERE/out"
export PKI_DIR
CNF="$HERE/openssl.cnf"
SUBJECT_PREFIX="/C=FR/O=Nacre conformance bench"

# The directory itself stays: a running container may have it mounted.
mkdir -p "$PKI_DIR"
find "$PKI_DIR" -mindepth 1 -delete
cd "$PKI_DIR"
mkdir .newcerts
for ca in root intermediate; do
  : > "$ca.index"
  echo 01 > "$ca.crlnumber"
done
echo 1000 > root.serial
echo 2000 > intermediate.serial
echo 01 > tsa.serial
echo 01 > tsa2.serial

key() {
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1.key.pem"
}

csr() {
  openssl req -new -config "$CNF" -key "$1.key.pem" -subj "$SUBJECT_PREFIX/CN=$2" -out "$1.csr"
}

key root
csr root "Nacre Test Root CA"
openssl ca -batch -notext -config "$CNF" -name root_ca -selfsign -keyfile root.key.pem \
  -extensions v3_root -in root.csr -out root.cert.pem

key intermediate
csr intermediate "Nacre Test Intermediate CA"
openssl ca -batch -notext -config "$CNF" -name root_ca \
  -extensions v3_intermediate -in intermediate.csr -out intermediate.cert.pem

leaf() {
  key "$1"
  csr "$1" "$2"
  openssl ca -batch -notext -config "$CNF" -name intermediate_ca \
    -extensions "$3" -in "$1.csr" -out "$1.cert.pem"
}

leaf signer "Nacre Test Signer" v3_signer
leaf tsa "Nacre Test TSA" v3_tsa
leaf tsa2 "Nacre Test Document TSA" v3_tsa
leaf revoked "Nacre Test Revoked Signer" v3_signer

openssl ca -batch -config "$CNF" -name intermediate_ca -revoke revoked.cert.pem \
  -crl_reason keyCompromise

for ca in root intermediate; do
  openssl ca -batch -config "$CNF" -name "${ca}_ca" -gencrl -crlexts crl_ext -out "$ca.crl.pem"
  openssl crl -in "$ca.crl.pem" -outform DER -out "$ca.crl"
  rm "$ca.crl.pem"
done

# Java reads a certificate bag marked with this trust attribute as a trusted entry,
# which is how DSS's keystore source finds its anchors without keytool.
openssl pkcs12 -export -nokeys -in root.cert.pem -name nacre-test-root \
  -jdktrust anyExtendedKeyUsage -passout pass:nacre-anchors -out anchors.p12

rm -rf .newcerts ./*.csr ./*.old
# The responders read the configuration next to the state they serve.
cp "$CNF" openssl.cnf
# Throwaway keys, but the host scripts must read them when a root container wrote them (CI).
chmod a+r ./*.pem anchors.p12
echo "PKI generated in $PKI_DIR"
