# Test corpus of `nacre-tsp`

Public certificates and random data only: no document, no private key. The time-stamped
data is 64 random bytes, so only the SHA-256 of random bytes ever left this machine.

## `recorded/`

Recorded on 2026-10-22 with OpenSSL 3.6.5 and curl.

- `data.bin`: 64 random bytes, not a document.
- `request.tsq`: `TimeStampReq` over the SHA-256 of `data.bin` (NULL hash parameters),
  nonce `0xD41CBFF4FDED9D81` drawn by OpenSSL, `certReq` TRUE.
- `bench.tsr`: the answer of the bench TSA configuration (`conformance/pki/openssl.cnf`,
  section `bench_tsa`) on a throwaway PKI generated under a temporary directory: ECDSA
  P-256, `signingCertificateV2`, policy `2.999.1.1`.
- `digicert.tsr`: the answer of DigiCert's public TSA, `http://timestamp.digicert.com`:
  RSA-4096, `signingCertificate` v1 and v2, `signingTime`.
- `freetsa.tsr`: the answer of FreeTSA, `https://freetsa.org/tsr`: SHA-512 and
  `ecdsa-with-SHA512` on a P-384 key, which `nacre-cms` cannot verify yet; it must stay
  `Indeterminate`.

Tests only read these files: no test, example or fuzz target calls a public TSA.

Commands, run from `recorded/` (the bench copy needs the repository root in `$REPO`):

```sh
head -c 64 /dev/urandom > data.bin
openssl ts -query -data data.bin -sha256 -cert -out request.tsq
curl -sS -H 'Content-Type: application/timestamp-query' --data-binary @request.tsq \
  http://timestamp.digicert.com -o digicert.tsr
curl -sS -H 'Content-Type: application/timestamp-query' --data-binary @request.tsq \
  https://freetsa.org/tsr -o freetsa.tsr
T=$(mktemp -d)
cp -r "$REPO/conformance/pki/generate.sh" "$REPO/conformance/pki/openssl.cnf" $T/
sh $T/generate.sh
PKI_DIR=$T/out openssl ts -reply -config $T/out/openssl.cnf -queryfile request.tsq -out bench.tsr
rm -rf $T
```

Regenerating draws a new nonce: the `NONCE` constant of `tests/request.rs` and
`tests/recorded.rs` then follows `openssl ts -query -in request.tsq -text`, and the
attack corpus is forged again.

## `attacks/`

One file per known attack on a time-stamp response, listed in
`docs/security/attacks/tsp.md` and each rejected by its own test in `tests/attacks.rs`.
Each answers `recorded/request.tsq` (same imprint, same nonce) and is correct apart from
its one defect. They are forged by
`cargo run -p nacre-tsp --example forge_attacks -- crates/nacre-tsp/tests/corpus/attacks`
with a fixed test secret written in the example, RFC 6979 ECDSA and a fixed `genTime`
(`20261022092550.25Z`), so the output is deterministic.

- `valid.tsr`: the baseline, signed by a self-signed TSA certificate whose critical
  extended key usage is `timeStamping` alone.
- `nonce-absent.tsr`: the `TSTInfo` carries no nonce.
- `imprint-other.tsr`: the `TSTInfo` time-stamps the SHA-256 of another content.
- `no-timestamping-eku.tsr`: signed by the same key, but the carried certificate is the
  `nacre-core` test signer's, a CA without extended key usage.
- `signature-invalid.tsr`: one bit of the signature flipped.
- `ess-v1-only.tsr`: `signingCertificate` (v1, SHA-1 `ESSCertID`) instead of
  `signingCertificateV2`.
- `content-type-other.tsr`: the signed content is typed `id-data`, in both its
  `eContentType` and its `contentType` attribute, instead of `id-ct-TSTInfo`.
- `eku-not-critical.tsr`: the TSA certificate's extended key usage is `timeStamping`
  alone but not critical.
- `eku-extra-purpose.tsr`: the TSA certificate's critical extended key usage holds
  `timeStamping` and `codeSigning`.
- `imprint-algorithm-other.tsr`: the `TSTInfo` carries the requested 32-byte imprint,
  labelled SHA3-256 instead of SHA-256.
- `imprint-parameters-other.tsr`: the imprint's SHA-256 identifier has `INTEGER 0` as
  parameters, neither absent nor `NULL`.
