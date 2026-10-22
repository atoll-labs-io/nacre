# Test corpus of `nacre-revocation`

Every subject, key and document here is fictitious and exists only to test this crate.
No private key is kept: the keys below are generated in a temporary directory and
deleted once the files are written.

## `openssl/`

CRLs and certificates written by OpenSSL 3.6.5, all DER.

- `ec-ca.der`: a self-signed P-256 CA, `CN=Nacre OpenSSL CRL fixture CA,O=Nacre tests,C=FR`,
  `keyUsage` `keyCertSign, cRLSign`.
- `leaf.der`: a P-256 leaf issued by it, serial `1001`, distribution point
  `http://crl.example.test/ca.crl`. Not revoked.
- `revoked.der`: a second leaf, serial `1002`, same distribution point, revoked with reason
  `keyCompromise`.
- `ec-ca.crl`: the CA's CRL. `openssl crl -text` prints `Last Update: Oct  1 00:00:00 2026
  GMT`, `Next Update: Oct  1 00:00:00 2036 GMT`, and one entry: serial `1002`, revocation
  date `Jun  1 00:00:00 2026 GMT`, reason `Key Compromise`.
- `rsa-ca.der`, `rsa-ca.crl`: an RSA-2048 CA and its empty CRL, same dates.

`openssl ca` stamps a revocation with the current time; the commands below set it to a fixed
date in the CA's index, and give the CRL fixed `lastUpdate` and `nextUpdate`, so the files
can be regenerated without touching the tests (keys and signatures change, dates do not).

Commands, run from this directory:

```sh
set -eu
OUT=openssl
T=$(mktemp -d)
cat > $T/ca.cnf <<'CNF'
[ ca ]
default_ca = fixture_ca
[ fixture_ca ]
dir = ${ENV::CA_DIR}
new_certs_dir = $dir
database = $dir/index
serial = $dir/serial
crlnumber = $dir/crlnumber
certificate = $dir/ca.pem
private_key = $dir/ca.key
default_md = sha256
policy = policy_any
unique_subject = no
[ policy_any ]
commonName = supplied
organizationName = optional
countryName = optional
[ v3_ca ]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[ v3_leaf ]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature, nonRepudiation
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
crlDistributionPoints = URI:http://crl.example.test/ca.crl
[ crl_ext ]
authorityKeyIdentifier = keyid:always
CNF
ca() { # dir key-algorithm-options subject
  mkdir $T/$1; : > $T/$1/index; echo 1000 > $T/$1/serial; echo 01 > $T/$1/crlnumber
  openssl genpkey $2 -out $T/$1/ca.key
  openssl req -new -key $T/$1/ca.key -subj "$3" -out $T/$1/ca.csr
  CA_DIR=$T/$1 openssl ca -batch -notext -config $T/ca.cnf -selfsign -keyfile $T/$1/ca.key \
    -extensions v3_ca -startdate 20260101000000Z -enddate 20360101000000Z \
    -in $T/$1/ca.csr -out $T/$1/ca.pem
}
ca ec "-algorithm EC -pkeyopt ec_paramgen_curve:P-256" "/CN=Nacre OpenSSL CRL fixture CA/O=Nacre tests/C=FR"
ca rsa "-algorithm RSA -pkeyopt rsa_keygen_bits:2048" "/CN=Nacre OpenSSL RSA CRL fixture CA/O=Nacre tests/C=FR"
for leaf in leaf revoked; do
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $T/$leaf.key
  openssl req -new -key $T/$leaf.key -subj "/CN=Nacre OpenSSL CRL fixture $leaf/O=Nacre tests/C=FR" -out $T/$leaf.csr
  CA_DIR=$T/ec openssl ca -batch -notext -config $T/ca.cnf -extensions v3_leaf \
    -startdate 20260101000000Z -enddate 20360101000000Z -in $T/$leaf.csr -out $T/$leaf.pem
done
CA_DIR=$T/ec openssl ca -batch -config $T/ca.cnf -revoke $T/revoked.pem -crl_reason keyCompromise
# openssl ca stamps the revocation with the current time: fix it so the fixtures stay stable.
sed -i 's/\t[0-9]*Z,keyCompromise/\t260601000000Z,keyCompromise/' $T/ec/index
for c in ec rsa; do
  CA_DIR=$T/$c openssl ca -batch -config $T/ca.cnf -gencrl -crlexts crl_ext \
    -crl_lastupdate 20261001000000Z -crl_nextupdate 20361001000000Z -out $T/$c.crl.pem
  openssl crl -in $T/$c.crl.pem -outform DER -out $OUT/$c-ca.crl
  openssl x509 -in $T/$c/ca.pem -outform DER -out $OUT/$c-ca.der
done
for leaf in leaf revoked; do openssl x509 -in $T/$leaf.pem -outform DER -out $OUT/$leaf.der; done
rm -rf $T
```

## `attacks/`

One CRL per known attack, listed in `docs/security/attacks/revocation.md` and each rejected
by its own test in `tests/attacks.rs`, with the certificates the cases need. Every CRL is
correctly signed apart from its one defect and lists the leaf `leaf.der`, so a skipped rule
would answer "revoked" instead of the expected error. The keys are fictitious fixed P-256
secrets written in the example.

The files are the output of a cargo example, deterministic (RFC 6979 ECDSA, fixed dates).
Regenerate them from the repository root with:

```sh
cargo run -p nacre-revocation --example forge_crl_attacks -- crates/nacre-revocation/tests/corpus/attacks
```
