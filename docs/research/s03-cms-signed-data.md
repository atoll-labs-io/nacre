# Research — s03-cms-signed-data

[Story](../stories.md)

## Structuring facts
- Story assumption incomplete: the story asks for a *detached* SignedData, but `nacre-cms` is touched by no later story (`docs/architecture.md:63`; s07, s08, s16 own other crates, `docs/stories.md:125,143,282`) while s07 reads RFC 3161 tokens with it (`docs/stories.md:135`) — tokens whose `TSTInfo` is *encapsulated*, often RSA-signed (FreeTSA, DigiCert) — and s08 adds an unsigned attribute to an existing `SignerInfo` (`docs/stories.md:147`). Reading must therefore accept encapsulated content, verify RSA PKCS#1 v1.5 as well as ECDSA P-256, and re-encode a decoded `SignedData` byte-identically with one more unsigned attribute. Otherwise s07/s08 need a new story.
- Story assumption imprecise: `openssl cms -verify -binary -content <file>` alone does not accept a signature from the only signer available, `TestSigner`. Its self-signed certificate carries `keyUsage keyCertSign|cRLSign` and no `digitalSignature` (`cabf::Root::new(false, …)`, `crates/nacre-core/src/test_signer.rs:33`, x509-cert `src/builder/profile/cabf.rs:171-175`), so OpenSSL 3.6.5 refuses it with "unsuitable certificate purpose" (probe in /tmp). `-inform DER -CAfile <cert.pem> -purpose any -cades` accepts it, and `-cades` also makes OpenSSL check `signing-certificate-v2` (probe: without the attribute, "missing signing certificate attribute"). Judging key usage is s16's job, not s03's.
- `der` 0.8.2 decoding a `SetOfVec` **re-sorts it silently** (`der-0.8.2/src/asn1/set_of.rs:626-636`) instead of rejecting an unsorted set. Verifying over a re-encoding of decoded signed attributes would therefore sign-check bytes the signer never signed. The verified bytes must be the received ones, with the `[0]` tag replaced by `0x31`. The same holds for `certificates`, to round-trip unchanged.
- `der` bounds nesting at 64 (`der-0.8.2/src/reader/position.rs:20,76-78`, `ErrorKind::NestingDepth`), and DER mode rejects indefinite lengths, which covers the "deep nesting" and "wrong lengths" hostile inputs without code of our own. BER input (some foreign tools) is refused, not read.
- The CI fuzz job runs `cargo +nightly fuzz list` / `run` from `crates/nacre-cms/` (`.github/workflows/ci.yml:41-49`). The root manifest is frozen (`Cargo.toml:3`), so `crates/nacre-cms/fuzz/Cargo.toml` must declare its own `[workspace]`. Neither nightly nor `cargo-fuzz` is installed on this machine (`rustup toolchain list`: stable, 1.97, 1.99).

## Story
s03 writes Nacre's own CMS `SignedData` (RFC 5652) in a new crate `crates/nacre-cms/`, plus `docs/security/attacks/cms.md`. Complexity written: 3. Depends on s01. Surface `endpoint`. Owns `crates/nacre-cms/`, `docs/security/attacks/cms.md` (`docs/stories.md:48-54`).

Acceptance criteria (`docs/stories.md:57-61`):
1. A digest and a `Signer` give a detached DER `SignedData` with signed attributes `content-type`, `message-digest`, `signing-certificate-v2`; `openssl cms -verify -binary -content <file>` accepts it.
2. A profile can forbid an attribute: under the PAdES profile, `signing-time` is never written.
3. A DER `SignedData` produced by OpenSSL is read and its signature verified; changing one byte of the content or of the signed attributes makes verification fail.
4. Hostile DER (truncated, wrong lengths, deep nesting) gives an error, never a panic; a fuzz target `crates/nacre-cms/fuzz/` exists.
5. `docs/security/attacks/cms.md` lists the known attacks (algorithm confusion, signed attributes absent or duplicated, inconsistent `message-digest`, `SignerIdentifier` not designating the certificate), each with its rejected corpus case.

Notes (`docs/stories.md:64`): no `cms` crate, only `der`, `x509-cert`, `spki`; signed attributes are signed as a DER `SET OF`, not as `[0] IMPLICIT`; leave room for later unsigned attributes without re-signing.

## Current code
- Workspace: `Cargo.toml:1-9` is a virtual manifest, `members = ["crates/*"]`, plus `[workspace.lints.clippy]` denying `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`. Only `crates/nacre-core/` exists. `crates/nacre-cms/` does not.
- `nacre-core` (`crates/nacre-core/src/lib.rs:1-34`) exports `Signer`, `SignatureAlgorithm`, `DigestAlgorithm`, `Error`, `BoxError`, `TestSigner` (feature `test-signer`), `TimestampAuthority`, `RevocationSource`, `ValidationReport`.
- `.github/workflows/ci.yml:9-17` runs fmt, clippy (`--all-targets --all-features -D warnings`) and `cargo test --workspace` on `ubuntu-latest`. `:19-50` is the fuzz loop over `crates/*/fuzz`, never exercised yet (`docs/reviews/s01-workspace-contract.md:170-172`).
- `docs/security/` does not exist. `cms.md` is the first attacks file.

## Attachment points
- New folder `crates/nacre-cms/` joins the workspace by its folder alone (`Cargo.toml:3`, `docs/architecture.md:69`).
- New folder `crates/nacre-cms/fuzz/` is picked up by the CI glob (`.github/workflows/ci.yml:28`), with no workflow edit.
- `nacre-cms` consumes `nacre_core::Signer` (`crates/nacre-core/src/signer.rs:4-17`). It is consumed later by `nacre-pades` (s06, s08, s11, s12), `nacre-tsp` (s07), `nacre-validate` (s14, s16).

## Verified interfaces
- `Signer::algorithm() -> SignatureAlgorithm`, `certificate_chain() -> &[Vec<u8>]` (signer first, never empty), `sign_digest(&[u8]) -> Result<Vec<u8>, nacre_core::Error>`; ECDSA output is a DER `ECDSA-Sig-Value`, RSA output raw bytes (`crates/nacre-core/src/signer.rs:4-17`).
- `SignatureAlgorithm` is `#[non_exhaustive]` {`EcdsaP256Sha256`, `RsaPkcs1v15Sha256`}, `.digest()` is SHA-256 for both (`crates/nacre-core/src/algorithm.rs:1-18`). `DigestAlgorithm` is `#[non_exhaustive]` {`Sha256`, `Sha384`, `Sha512`}, with `output_len()` (`:20-38`). Matches need a wildcard arm.
- `nacre_core::Error` is `#[non_exhaustive]`: `DigestLength`, `Signer(BoxError)`, `Timestamp`, `Revocation` (`crates/nacre-core/src/error.rs:1-19`).
- `TestSigner::from_secret(&[u8; 32])` gives a P-256 signer with a one-certificate chain, `CN=Nacre test signer,O=Nacre tests,C=FR`, serial 1, validity 2026–2036, and refuses a digest that is not 32 bytes (`crates/nacre-core/src/test_signer.rs:15-72`). p256 `sign_prehash` is RFC 6979 deterministic, so a fixed secret yields reproducible files.
- `x509-cert` 0.3: `Certificate::tbs_certificate()`, `.issuer() -> &Name`, `.serial_number() -> &SerialNumber`, `.subject_public_key_info()` (`x509-cert-0.3.0/src/certificate.rs:177-208,341`). The existing test reads a key with `VerifyingKey::from_sec1_bytes(spki.subject_public_key.raw_bytes())` (`crates/nacre-core/tests/contract_signer.rs:22-24`).
- `der` 0.8.2 features `alloc`, `derive`, `oid`, `pem` exist (`der-0.8.2/Cargo.toml:56-76`); `der_derive` 0.8.0 is in the registry.
- `rsa` 0.10.0-rc.19 (2026-10-06, crates.io) depends on `sha2 ^0.11`, `spki ^0.8`, `signature ^3`, `const-oid ^0.10`, all aligned with p256 0.14. Default features `std`, `encoding`. MSRV 1.85. ADR-0004 allows it for verification only (`docs/decisions/0004-rustcrypto-foundations-and-x509-boundary.md:24`).
- `libfuzzer-sys` 0.4.13 is the current release; `g++` is present for its build script.
- OpenSSL 3.6.5 locally. `openssl cms -sign -binary -outform DER` writes definite-length DER with signed attributes contentType, signingTime, messageDigest, smimeCapabilities, in DER order; `-cades` adds `id-smime-aa-signingCertificateV2`; ECDSA signature algorithm `ecdsa-with-SHA256`, absent parameters for `sha256` (probe output).

## Traps
- **Pre-commit hook**: it refuses an added line holding `-----BEGIN … PRIVATE KEY` (`.polype/hooks/po-gate.sh:229`). The OpenSSL fixtures' keys must not be committed: only certificates, contents and signatures.
- **Lints**: integration tests open with `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]` (`crates/nacre-core/tests/contract_signer.rs:1-6`); library code may not use any of them. `#![forbid(unsafe_code)]` heads `lib.rs` (`crates/nacre-core/src/lib.rs:1`).
- **`rsa` is a release candidate**: with no `Cargo.lock` in git (`.gitignore:4`), CI resolves the newest pre-release each run. Pin `=0.10.0-rc.19`.
- **ECDSA high-S**: OpenSSL may emit a high-S signature. The verifier must accept it, as OpenSSL does.
- **ESSCertIDv2**: `hashAlgorithm` is `DEFAULT sha256`, so DER omits it; a reader should also accept it written explicitly.
- **Fuzz crate**: it cannot use `[lints] workspace = true` (its own workspace has no lints). `nacre-cms`'s own `[lints] workspace = true` must still resolve when built as a path dependency of the fuzz workspace: `cargo check --manifest-path crates/nacre-cms/fuzz/Cargo.toml` on stable proves both. The root `.gitignore` ignores `Cargo.lock` at any depth, but not `fuzz/target`, `fuzz/corpus`, `fuzz/artifacts`.
- **OpenSSL in `cargo test`**: ADR-0007 makes `openssl cms` the CMS judge, run in CI (`docs/decisions/0007-dss-local-pinned-conformance-judge.md:22`); `ubuntu-latest` ships it, and the `check` job runs every non-ignored test. Temporary files go under `env!("CARGO_TARGET_TMPDIR")`, never the source tree.
- **Fixtures answering for another check** (testing-doctrine §5): each attack case must be correctly signed apart from its one defect, or the signature check rejects it first and the test proves nothing.
- No migration, no screen, no shared file edited.

## Open questions
- Write `issuerSerial` in `ESSCertIDv2`? Answer: omit it, since `certHash` is what DSS and OpenSSL check. s06's conformance run confirms it.
- Accept several `SignerInfo`s? Answer: no. Every AdES profile and RFC 3161 token has exactly one; any other count is refused.
- The "chaîne contournée" attack (brief finding 4, issue #11) is a chain judgement, s16's (`docs/stories.md:285`). s03 covers only its CMS share, the certificate substitution caught by `signing-certificate-v2`, and the attacks file records the rest as s16's.
- SHA-384/512 and other signature algorithms: refused as unsupported for now. If s07's recorded TSA responses use them, s07 cannot add them without a story on `nacre-cms`.

## Complexity
3 → 4. Main risk: `nacre-cms` freezes after this story, while five later crates rely on its reading API (encapsulated content, RSA, unsigned attributes, certificate access), and its bytes must match OpenSSL exactly. The work goes beyond one business rule: it covers two signature algorithms, two content modes, round-trip encoding, an attack corpus and a fuzz target. Still not a 5: no external system at run time, and no split is needed.

## Split
Not required (score 4).
