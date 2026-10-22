# Research — s07-tsp-client

[Story](../stories.md)

## Structuring facts
1. **False assumption (notes): FreeTSA's token cannot be verified by `nacre-cms`.** A FreeTSA token fetched on 2026-10-22 signs with `sha512` + `ecdsa-with-SHA512` on a P-384 key; `SignedData::verify(None)` returns `UnsupportedAlgorithm(2.16.840.1.101.3.4.2.3)`, kind `Indeterminate` (check at `crates/nacre-cms/src/verify.rs:181`). DigiCert's token (SHA-256, RSA-4096, `rsaEncryption` as signature algorithm) **verifies** unchanged. Extending `nacre-cms` lies outside `Owns`: DigiCert is the public fixture that must verify, FreeTSA a fixture that must fail `Indeterminate`, and the SHA-384/512 + P-384 support is an issue for the lead to file.
2. The trait returns the **token**, not the response: `TimestampAuthority::timestamp(&self, DigestAlgorithm, &[u8]) -> Result<Vec<u8>, nacre_core::Error>` (`crates/nacre-core/src/timestamp.rs:4-7`). The HTTP implementation must check status, imprint, nonce and signature itself before handing the token over; its own error travels as `nacre_core::Error::Timestamp(BoxError)` (`crates/nacre-core/src/error.rs:16`), kind `Unavailable` whatever the cause (`error.rs:28`).
3. `nacre-cms` verifies an encapsulated token as is: `verify(None)` hashes `econtent` with SHA-256 against `messageDigest` and checks the signature (`crates/nacre-cms/src/verify.rs:45-51`, `72-123`). It does **not** check that `eContentType` is `id-ct-TSTInfo`, does not require `signingCertificateV2` (checked only when present, `verify.rs:97-102`), never reads `signingCertificate` v1, and does not judge the certificate (no EKU). Those three rules are nacre-tsp's.
4. `der::asn1::GeneralizedTime` refuses fractional seconds (`der-0.8.2/src/asn1/generalized_time.rs:26,35,127`), which RFC 3161 §2.4.2 allows in `genTime`. None of the three recorded tokens carries a fraction, but a TSA in the wild may: `genTime` must be read by hand.
5. Without `http`, `cargo tree -p nacre-tsp -e normal` shows no `ureq` when `ureq` is optional, even with a self dev-dependency enabling `http`: proven on `nacre-conformance` (0 `ureq` lines without the feature, 2 with `--features http`).

## Story
`crates/nacre-tsp/`: from a digest, build a DER `TimeStampReq` (RFC 3161) with a nonce and `certReq`; read the `TimeStampResp` and verify its `TSTInfo` (same imprint, same nonce, status granted, valid signature). Criteria (`docs/stories.md:128-132`):
1. Request with nonce and `certReq`; response read; imprint, nonce, status and signature checked.
2. Differing imprint, nonce or signature → rejected, each with its own error.
3. Under feature `http`, a `TimestampAuthority` calls a TSA over HTTP (`application/timestamp-query`) and returns a verified token from s02's local TSA.
4. Without `http`, no network dependency (`cargo tree`).
5. Hostile response → error, never panic; a fuzz target; `docs/security/attacks/tsp.md` lists replay without nonce, token of another imprint, TSA certificate without `id-kp-timeStamping`, each with its rejected case.

Notes: keep a recorded response from the local TSA and from at least one public TSA; CI never calls a public TSA; only the imprint leaves.

## Current code
- No `crates/nacre-tsp/` and no `docs/security/attacks/tsp.md` exist. The workspace picks the crate up by its folder (`Cargo.toml` `members = ["crates/*"]`, workspace clippy lints `unwrap_used`, `expect_used`, `panic`, `indexing_slicing` denied).
- `nacre-cms` (s03, frozen after it): `SignedData::from_der` (`crates/nacre-cms/src/model.rs:84`), `econtent()` (`model.rs:180`), `verify(None)` → `VerifiedSigner` with `certificate()` the signer's DER (`verify.rs:25`) and `signer_info()`; signer certificate found by `sid` among `certificates` (`verify.rs:125-148`); only `sha256` as signer digest (`verify.rs:181`), signature `ecdsa-with-SHA256`, `sha256WithRSAEncryption` or `rsaEncryption` (`verify.rs:186-190`), P-256 or RSA keys. `Error::kind()` at `crates/nacre-cms/src/error.rs:71`. OIDs at `crates/nacre-cms/src/oid.rs` (no TSTInfo, no SHA-384/512).
- `nacre-cms` examples forge corpora by hand from public fields: `crates/nacre-cms/examples/forge_attacks.rs` (fixed secret `[0x11; 32]`, RFC 6979, fixed dates; `TST_INFO` constant at line 37; `substitute_certificate` builds a certificate at line 142).
- Bench TSA: `conformance/pki/cgi-bin/tsa` runs `openssl ts -reply -config $PKI_DIR/openssl.cnf`; config `[bench_tsa]` at `conformance/pki/openssl.cnf:87-101`: `signer_digest = sha256`, `certs` = intermediate, `ess_cert_id_alg = sha256` (so `signingCertificateV2`), policy `2.999.1.1`, digests sha256/384/512. TSA certificate profile `v3_tsa` (`openssl.cnf:72-79`): P-256 key, critical EKU `timeStamping`. Served at `http://127.0.0.1:18081/cgi-bin/tsa` (`conformance/pki/serve.sh:17`, `conformance/README.md:20`). PKI regenerated at every bench start into `conformance/pki/out/` (ignored).
- `nacre-conformance` uses `ureq` 3 behind `http` with `default-features = false` (`crates/nacre-conformance/Cargo.toml:18,22`), body limit and timeout pattern in `crates/nacre-conformance/src/client.rs:8-12,37-43`; `pki_dir()` at `crates/nacre-conformance/src/lib.rs:53`.
- CI: `ci.yml` runs clippy `--all-features` and `cargo test --workspace`, and fuzzes every `crates/*/fuzz` 60 s per target with no workflow change (`.github/workflows/ci.yml:19-49`); `conformance.yml` starts the bench and runs `cargo test --workspace --all-features -- --ignored` (`conformance.yml:35-41`).

## Attachment points
- New crate `crates/nacre-tsp/` (lib, tests, `tests/corpus/`, `examples/forge_attacks.rs`, `fuzz/` with its own `[workspace]` as `crates/nacre-cms/fuzz/Cargo.toml`).
- `impl nacre_core::TimestampAuthority` behind feature `http` (ADR-0006: `ureq`, TLS through rustls).
- A conformance test `#[ignore = "conformance"]` in `crates/nacre-tsp/tests/`: picked up by `conformance.yml:41` with no workflow edit.
- `docs/security/attacks/tsp.md`, in French, shaped as `docs/security/attacks/cms.md`.

## Verified interfaces
- `nacre_core::DigestAlgorithm { Sha256, Sha384, Sha512 }`, `#[non_exhaustive]`, `output_len()` (`crates/nacre-core/src/algorithm.rs:21-37`): a `match` needs a wildcard arm.
- `nacre_core::ErrorKind { InvalidInput, InvalidSignature, Indeterminate, Signer, Unavailable }` (`crates/nacre-core/src/error.rs:40`); every crate's `Error` exposes `kind()` (ADR-0012), tested as a table (`crates/nacre-cms/src/error.rs` `every_variant_has_its_kind`).
- `nacre_core::TestSigner::from_secret(&[u8; 32])` (`crates/nacre-core/src/test_signer.rs:31`): its certificate is a `cabf::Root` (`test_signer.rs:33`), a CA with **no EKU**: a ready "TSA certificate without `id-kp-timeStamping`".
- `x509_cert::TbsCertificate::get_extension::<ExtendedKeyUsage>() -> Result<Option<(bool, _)>>` (critical flag first; error on a duplicated extension) (`x509-cert-0.3.0/src/certificate.rs:265-276`); `ExtendedKeyUsage(pub Vec<ObjectIdentifier>)` defaults to **non-critical** when built (`x509-cert-0.3.0/src/ext/pkix/keyusage.rs:133,141`): a forged TSA certificate needs a hand-built `Extension { critical: true, .. }`.
- `getrandom` 0.4.3 is already in the tree (through `rsa` and `p256`, `cargo tree -i getrandom`): `getrandom::fill(&mut [u8])`, `getrandom::u64()` (`getrandom-0.4.3/src/lib.rs:87,157`).
- `ureq` 3.5.0 features: `default = ["rustls", "gzip"]`, `rustls` = rustls + ring.

### Recorded material (fetched during this research, kept out of the worktree)
`/tmp/s07probe/` holds, if `/tmp` survived: `data.bin` (64 random bytes, not a document), `request.tsq` (`openssl ts -query -data data.bin -sha256 -cert`: SHA-256 with NULL parameters, nonce `0x00D41CBFF4FDED9D81` encoded on 9 bytes, `certReq` TRUE, 70 bytes), and three answers to that same request: `bench.tsr` (bench config on a throwaway PKI generated in `/tmp`, verifies), `digicert.tsr` (`http://timestamp.digicert.com`, verifies, carries `signingCertificate` v1 **and** v2 and `signingTime`, no `tsa` field), `freetsa.tsr` (`https://freetsa.org/tsr`, fails `UnsupportedAlgorithm`). sha256: request `b4af5db6…4619`, bench `212acbd3…b68f`, digicert `f3a2d581…bc99`, freetsa `d1975ae1…7c6a`. All three responses are `SEQUENCE { SEQUENCE { INTEGER 0 }, ContentInfo }`, no `statusString`. Without `certReq`, the bench token carries no certificate and `nacre-cms` answers `SignerCertificateNotFound`.

## Traps
- **Check order is a contract**, as in `nacre-cms` (`verify.rs:70-71`): each attack case must reach the rule that names it, and the forged cases must be correct apart from their one defect (testing-doctrine, false test 5).
- `openssl ts -reply` refuses a signer certificate without the timeStamping EKU, so the "no EKU" case cannot come from OpenSSL: it is forged in Rust.
- `openssl ts -query` draws its own nonce: an encoder test compares against a recorded `.tsq` with that nonce, not a chosen one. OpenSSL writes NULL hash parameters; RFC 3161 TSAs echo the imprint's AlgorithmIdentifier as sent.
- Bench keys, serials and the TSA certificate change at every start (`conformance/pki/README.md:27-28`): the conformance test compares against `pki_dir()/tsa.cert.pem` read at run time, never a constant.
- `rustls` brings `ring`, whose build script compiles C and assembly: the reviewer's dependency lens will want it named; `--all-features` clippy in CI builds it.
- Errors carry no token bytes (ADR-0012): `Display` never prints the response, the imprint or the nonce.
- No clock read (convention): `genTime` is returned, never compared with now.
- `Cargo.lock` is ignored; pin nothing unless a release candidate appears (none here).
- DER only: `der` rejects BER (indefinite lengths). A TSA answering BER would fail `InvalidInput`; none of the three does.
- Other lanes of this wave own `crates/nacre-pades/` (s06) and `crates/nacre-revocation/` (s09): no overlap. s08 will call this crate to embed a token, s14 to verify an embedded one, without a nonce.

## Open questions
- Is a token carrying only `signingCertificate` v1 (SHA-1 `ESSCertID`) acceptable? Accepting it leaves the certificate binding unchecked (no SHA-1 in the tree, `nacre-cms` ignores v1); refusing it loses v1-only TSAs (FreeTSA is one, already refused for SHA-512). The plan decides.
- Should the EKU rule be RFC 3161 §2.3 to the letter (EKU present, critical, `id-kp-timeStamping` its only purpose)? The three recorded TSA certificates satisfy it.
- Nonce size: 64 bits as OpenSSL, or more? RFC 3161 sets no size.

## Complexity
Story: 4 (third-party integration, risk: real TSAs diverge). After reading: **4**. The verification itself rests on `nacre-cms`; the cost is in the ASN.1 of request, response and `TSTInfo`, the forged corpus, and the divergence already observed (FreeTSA, v1/v2 ESS attributes, fractional `genTime`). Not a 5: no state, no migration.

## Split
Not needed at 4.
