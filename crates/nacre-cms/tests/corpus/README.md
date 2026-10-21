# Test corpus of `nacre-cms`

Every subject, key and document here is fictitious and exists only to test this crate.
No private key is kept: the keys below are generated in a temporary directory and
deleted once the files are written.

## `openssl/`

Signatures written by OpenSSL 3.6.5, the CMS judge of ADR-0007.

- `content.bin`: a fictitious text, the signed content of every file below.
- `ec-detached.der`: detached, P-256 key, CAdES attributes (`signingCertificateV2`).
- `rsa-detached.der`: detached, RSA-2048 key, without `-cades`, so it carries no
  `signingCertificateV2`.
- `ec-attached.der`: the content encapsulated (`-nodetach`), P-256 key, CAdES attributes.

Commands, run from this directory:

```sh
T=$(mktemp -d)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout $T/ec.key -out $T/ec.pem -subj "/CN=Nacre OpenSSL EC fixture/O=Nacre tests/C=FR" -days 3650
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout $T/rsa.key -out $T/rsa.pem -subj "/CN=Nacre OpenSSL RSA fixture/O=Nacre tests/C=FR" -days 3650
openssl cms -sign -binary -cades -in openssl/content.bin -signer $T/ec.pem -inkey $T/ec.key \
  -md sha256 -outform DER -out openssl/ec-detached.der
openssl cms -sign -binary -in openssl/content.bin -signer $T/rsa.pem -inkey $T/rsa.key \
  -md sha256 -outform DER -out openssl/rsa-detached.der
openssl cms -sign -binary -nodetach -cades -in openssl/content.bin -signer $T/ec.pem -inkey $T/ec.key \
  -md sha256 -outform DER -out openssl/ec-attached.der
rm -rf $T
```

Regenerating them changes every file (fresh keys, signing time), and the tests still pass.

## `attacks/`

One file per known attack on CMS `SignedData`, listed in `docs/security/attacks/cms.md`
and each rejected by its own test in `tests/attacks.rs`. Every file is a detached
signature over `openssl/content.bin`, correctly signed apart from its one defect, by the
fictitious test key `TestSigner::from_secret(&[0x11; 32])` of `nacre-core`.

The files are the output of a cargo example, deterministic (RFC 6979 ECDSA, fixed dates).
Regenerate them from the repository root with:

```sh
cargo run -p nacre-cms --example forge_attacks -- crates/nacre-cms/tests/corpus/attacks
```
