# Test corpus of `nacre-pades`

Every subject, key and document here is fictitious or public test material.

- `unsigned.pdf`: a copy of `conformance/reference/unsigned.pdf`, one page of fictitious
  text written by hand for the conformance bench.
- `rsa-detached.der`: a copy of `crates/nacre-cms/tests/corpus/openssl/rsa-detached.der`, a
  detached CMS written by OpenSSL with a fictitious, self-signed RSA-2048 test certificate
  (`CN=Nacre OpenSSL RSA fixture`); its commands are in `crates/nacre-cms/tests/corpus/README.md`.
- `pki/`: copies of fictitious test material from `crates/nacre-revocation/tests/corpus/`,
  whose commands are in `crates/nacre-revocation/tests/corpus/README.md`. From `openssl/`:
  `ec-ca.der` (a self-signed P-256 CA, `CN=Nacre OpenSSL CRL fixture CA`), `leaf.der` and
  `revoked.der` (both issued by it) and `ec-ca.crl` (its CRL). From `ocsp-openssl/`:
  `good.der`, an OCSP response. The B-LT tests store them in `/DSS` without judging them.
