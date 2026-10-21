---
validated: yes
---
# Plan — s03-cms-signed-data

[Story](../stories.md) · [Research](../research/s03-cms-signed-data.md)

Branch `story/s03-cms-signed-data`. Read `docs/research/s03-cms-signed-data.md` first; this plan builds on it without repeating it.

Validated autonomously (`Plan validation: autonomous`): no human reviewed this plan. No structural choice is left open. The libraries are set by ADR-0001 and ADR-0004 (`der`, `spki`, `x509-cert`, `p256`, `sha2`, `rsa` for verification, no `cms`), the CMS judge by ADR-0007 (`openssl cms`, in CI) and the fuzzer by ADR-0008. The reserved ADR-0012 is not used.

## Story
A new crate `crates/nacre-cms/` signs a digest with a `nacre_core::Signer` into a detached DER `SignedData` (RFC 5652), and reads and verifies one, including OpenSSL's. Criteria (`docs/stories.md:57-61`):
1. Signed attributes `content-type`, `message-digest`, `signing-certificate-v2`; OpenSSL accepts the result.
2. A profile forbids an attribute; under PAdES, `signing-time` is never written.
3. An OpenSSL `SignedData` is read and verified; one byte changed in the content or the signed attributes fails.
4. Hostile DER returns an error, never a panic; a fuzz target exists in `crates/nacre-cms/fuzz/`.
5. `docs/security/attacks/cms.md` lists the attacks, each with a rejected corpus case.

Scope added by the research (structuring facts 1–2): `nacre-cms` freezes after s03. Reading therefore also covers encapsulated content (s07's tokens), RSA PKCS#1 v1.5 SHA-256 verification, and adding an unsigned attribute without re-signing (s08). The OpenSSL check runs `-inform DER -CAfile <cert> -purpose any -cades`, because the test signer's certificate has no `digitalSignature` bit.

## Reuse

| New code | Rung that holds | Why each rung above fails |
| --- | --- | --- |
| ASN.1 model of `ContentInfo`, `SignedData`, `SignerInfo`, `Attribute`, `ESSCertIDv2` | new code on `der` derive (installed rung for the encoding) | Not in the repository. The `cms` crate has it but is forbidden (ADR-0001, `docs/stories.md:64`). `der` encodes, and Nacre writes the format. |
| DER encoding, nesting bound, sorting of SET OF | dependency: `der` 0.8 (`SetOfVec`, `NestingDepth` at 64, `der-0.8.2/src/reader/position.rs:20`) | — |
| Certificate parsing, issuer and serial | dependency: `x509-cert` 0.3 (`certificate.rs:177-208`) | Nothing in the repository parses certificates outside the test signer |
| SHA-256, ECDSA P-256 and RSA verification | dependencies: `sha2` 0.11, `p256` 0.14, `rsa` `=0.10.0-rc.19` | No primitive is ever written (ADR-0001) |
| Signing a digest | repository: `nacre_core::Signer::sign_digest` (`crates/nacre-core/src/signer.rs:16`) | — |
| Test signer for fixtures and tests | repository: `nacre_core::TestSigner` (`crates/nacre-core/src/test_signer.rs:31`) | — |
| Error enum | dependency: `thiserror` 2, as in `crates/nacre-core/src/error.rs:6-7` | — |
| Attack corpus generator | new code: one cargo example | No tool builds a correctly signed SignedData with one chosen defect. OpenSSL cannot duplicate attributes or forge a `sid`. |

## Tasks
1. [x] **Crate skeleton.**
   - `crates/nacre-cms/Cargo.toml`:
     - `name = "nacre-cms"`, `version = "0.1.0"`, edition 2024, `rust-version = "1.97"`, `license = "MIT OR Apache-2.0"`, a description, and `[lints] workspace = true`.
     - dependencies: `nacre-core = { path = "../nacre-core", version = "0.1.0" }`, `der = { version = "0.8", features = ["alloc", "derive", "oid"] }`, `spki = { version = "0.8", features = ["alloc"] }`, `x509-cert = "0.3"`, `sha2 = "0.11"`, `p256 = { version = "0.14", features = ["ecdsa"] }`, `rsa = "=0.10.0-rc.19"` (pinned: no lock file in git, research Traps), `thiserror = "2"`.
     - dev-dependencies: `nacre-core` with `features = ["test-signer"]`, and `p256`/`x509-cert` (`builder`)/`der` (`pem`) for the generator and tests.
   - `src/lib.rs` opens with `#![forbid(unsafe_code)]`, and its crate docs say "experimental" (convention, `AGENTS.md`).
   - `src/error.rs` holds one `#[non_exhaustive]` `thiserror` enum `Error`, with variants:
     - `Der(der::Error)`, `NotSignedData`, `SignerCount(usize)`, `UnsupportedAlgorithm(ObjectIdentifier)`, `AlgorithmMismatch`, `MissingSignedAttributes`, `MissingAttribute(ObjectIdentifier)`, `DuplicateAttribute(ObjectIdentifier)`, `AttributeValueCount(ObjectIdentifier)`, `ForbiddenAttribute(ObjectIdentifier)`, `ContentTypeMismatch`;
     - `ContentMissing`, `ContentAmbiguous`, `DigestLength { expected, actual }`, `MessageDigestMismatch`, `SignerCertificateNotFound`, `SigningCertificateMismatch`, `SignatureInvalid`, `Certificate(der::Error)`, `Signer(nacre_core::Error)`.
   - `src/oid.rs` holds the OIDs:
     - content types `id-signedData`, `id-data`;
     - attributes `contentType`, `messageDigest`, `signingTime`, `id-aa-signingCertificateV2` (1.2.840.113549.1.9.16.2.47);
     - algorithms `sha256`, `ecdsa-with-SHA256`, `id-ecPublicKey`, `prime256v1`, `rsaEncryption`, `sha256WithRSAEncryption`.

   Check: `cargo clippy -p nacre-cms --all-targets --all-features -- -D warnings` passes; there is no test yet.
2. [x] **OpenSSL fixtures** in `crates/nacre-cms/tests/corpus/openssl/`:
   - Files: `content.bin` (a fictitious text), `ec-detached.der` (`openssl cms -sign -binary -cades -outform DER`, P-256 key), `rsa-detached.der` (RSA-2048, without `-cades`, so `signing-certificate-v2` stays optional on read) and `ec-attached.der` (`-nodetach`).
   - The keys are generated under `/tmp` and thrown away: no key file and no `PRIVATE KEY` line in git (research Traps, pre-commit).
   - `tests/corpus/README.md` gives the exact commands, the OpenSSL version (3.6.5), and says every subject is fictitious.

   Check: `openssl asn1parse -inform DER` reads each file, and `openssl cms -verify -binary -inform DER -noverify` accepts each with `content.bin` (attached: without `-content`).
3. [x] **Model, decoding and encoding** (`src/model.rs`), with public types and fields:
   - `ContentInfo`, `SignedData` (version, `digest_algorithms`, `encap_content_info { econtent_type, econtent: Option<Vec<u8>> }`, `certificates: Vec<Vec<u8>>` as raw TLVs in received order, `crls` raw and optional, `signer_infos`), and `SignerInfo` (version, `sid: SignerIdentifier { IssuerAndSerialNumber | SubjectKeyIdentifier }`, `digest_algorithm`, `signed_attrs: Option<SignedAttributes>`, `signature_algorithm`, `signature: Vec<u8>`, `unsigned_attrs: Vec<Attribute>`).
   - **`SignedAttributes` keeps the received content octets of `[0]`.** `to_be_signed()` returns `0x31 ‖ length ‖ those octets`. `from_attributes(Vec<Attribute>)` builds them DER-sorted through `SetOfVec`, keeping duplicates, so the generator can forge them. `attributes()` parses them on demand. They are never re-encoded from a decoded set (research structuring fact 3).
   - `SignedData::from_der(&[u8])` checks `id-signedData`; `to_der()` writes `ContentInfo`.

   Test `round_trip_is_byte_identical` (`tests/read.rs`): `to_der(from_der(x)) == x` for the three OpenSSL fixtures. It fails if any raw field is re-encoded or re-sorted.
4. [x] **Signing** (`src/sign.rs`): `pub fn sign_detached(digest: &[u8], signer: &dyn Signer, profile: &Profile, signing_time: Option<x509_cert::time::Time>) -> Result<Vec<u8>, Error>`.
   - `digest.len()` must equal `signer.algorithm().digest().output_len()`, else `DigestLength`.
   - `sid` is the issuer and serial of `certificate_chain()[0]`. `certificates` is the whole chain, DER-sorted.
   - The signed attributes are `contentType = id-data`, `messageDigest = digest`, `signingCertificateV2 { certs: [ESSCertIDv2 { certHash: SHA-256(cert) }] }` (`hashAlgorithm` omitted as DEFAULT, no `issuerSerial`), plus `signingTime` when it is given.
   - The signature is `signer.sign_digest(SHA-256(to_be_signed()))`. The algorithm identifiers follow `signer.algorithm()`: `ecdsa-with-SHA256` without parameters, `sha256WithRSAEncryption` with NULL, and `UnsupportedAlgorithm` for any other variant, since the enum is non-exhaustive.
   - `Profile` is a struct: `Profile::CMS` forbids nothing, `Profile::PADES` forbids `signingTime`, and `pub const fn forbidding(&'static [ObjectIdentifier])` serves later profiles (CAdES) without an edit here. A forbidden attribute that is asked for → `ForbiddenAttribute`, and nothing is written.

   Tests (`tests/sign.rs`):
   - `detached_signature_carries_required_attributes` decodes the output: no `econtent`, the three attributes present, `messageDigest == digest`, the ESS hash equals SHA-256 of the certificate.
   - `openssl_accepts_nacre_signature`: the certificate as PEM and the files under `env!("CARGO_TARGET_TMPDIR")`, then `openssl cms -verify -binary -inform DER -content <f> -CAfile <cert.pem> -purpose any -cades`, whose exit status must be 0. A missing `openssl` fails the test, never skips it.
   - `pades_profile_refuses_signing_time` → `ForbiddenAttribute(signingTime)`.
   - `cms_profile_writes_signing_time`: the attribute is present, which proves the profile, and not the absence of the feature, is what drops it.
   - `wrong_digest_length_is_refused` → `DigestLength`.
5. [x] **Verification** (`src/verify.rs`): `SignedData::verify(&self, detached: Option<&[u8]>) -> Result<VerifiedSigner<'_>, Error>` and `verify_detached_digest(&self, digest: &[u8])` (for s14's ByteRange digest). The checks run **in this order**, so that each attack case reaches its own rule:
   1. exactly one `SignerInfo`, else `SignerCount`;
   2. `signed_attrs` present, else `MissingSignedAttributes`;
   3. duplicate `attrType` → `DuplicateAttribute`, detected by sorting the OIDs, never pairwise. More than one value in `contentType`, `messageDigest` or `signingTime` → `AttributeValueCount`;
   4. `contentType` and `messageDigest` present, else `MissingAttribute`;
   5. `contentType` equals `eContentType`, else `ContentTypeMismatch`;
   6. the certificate designated by `sid` (issuer DER bytes and serial equal, or SKI extension equal) is among `certificates`, else `SignerCertificateNotFound`;
   7. the digest algorithm is SHA-256, and the signature algorithm is in {`ecdsa-with-SHA256`, `sha256WithRSAEncryption`, `rsaEncryption`}, else `UnsupportedAlgorithm`. It must agree with the key of the certificate (EC P-256 ↔ ECDSA, RSA ↔ RSA), else `AlgorithmMismatch`;
   8. when `signingCertificateV2` is present, the `certHash` of its first `ESSCertIDv2` equals SHA-256 of that certificate's DER, else `SigningCertificateMismatch`. A `hashAlgorithm` other than SHA-256 → `UnsupportedAlgorithm`;
   9. content: detached together with `econtent` → `ContentAmbiguous`, neither → `ContentMissing`. SHA-256 of the content equals `messageDigest`, else `MessageDigestMismatch`;
   10. the signature over SHA-256(`to_be_signed()`) checks with the certificate's key (p256 `verify_prehash` on a DER signature, accepting high S; rsa `pkcs1v15::VerifyingKey<Sha256>` prehash), else `SignatureInvalid`.

   `VerifiedSigner` exposes the signer certificate's DER; `SignedData` exposes `econtent` for s07.

   Tests (`tests/read.rs`):
   - `openssl_ecdsa_detached_verifies`;
   - `openssl_rsa_detached_verifies`;
   - `openssl_attached_verifies_and_exposes_content` (`econtent == content.bin`);
   - `changed_content_byte_fails` → `MessageDigestMismatch`;
   - `changed_signed_attribute_byte_fails`: flip one byte inside the `signingTime` value of `ec-detached.der`, located by searching the fixture's bytes rather than a magic offset → `SignatureInvalid`.
6. [x] **Unsigned attributes without re-signing**: `SignerInfo::push_unsigned_attribute(Attribute)`. The unsigned attributes are written as a DER-sorted `[1] IMPLICIT SET OF`, and no other field changes.

   Test `unsigned_attribute_added_without_resigning` (`tests/read.rs`): sign with `TestSigner`, decode, push an attribute (the OID of `signature-time-stamp`, any DER value), `to_der`, decode again. It checks that the attribute is read back, `to_be_signed()` and `signature` are byte-identical, and `verify` still passes.
7. [x] **Attack corpus and attacks file.**
   - Example `crates/nacre-cms/examples/forge_attacks.rs` (`cargo run -p nacre-cms --example forge_attacks -- crates/nacre-cms/tests/corpus/attacks`) uses `TestSigner::from_secret(&[0x11; 32])` and the public model. Each file is correctly signed apart from its one defect (testing-doctrine §5). The output is deterministic (RFC 6979).
   - The eight files, each with the error it must give:
     - `alg-confusion.der`: `sha256WithRSAEncryption` declared over an ECDSA signature with an EC key → `AlgorithmMismatch`;
     - `signed-attrs-absent.der`: no `signedAttrs`, the signature over the content digest → `MissingSignedAttributes`;
     - `message-digest-absent.der` → `MissingAttribute(messageDigest)`;
     - `signed-attrs-duplicate.der`: two `messageDigest` attributes with the right value → `DuplicateAttribute`;
     - `message-digest-mismatch.der` → `MessageDigestMismatch`;
     - `sid-unknown.der`: serial 2 in `sid`, the certificate has serial 1 → `SignerCertificateNotFound`;
     - `cert-substitution.der`: `certificates` holds a second certificate with the same key, issuer and serial but another validity, while the ESS hash names the original → `SigningCertificateMismatch`;
     - `content-type-mismatch.der`: `eContentType` ≠ `contentType` → `ContentTypeMismatch`.
   - `tests/corpus/README.md` gets the regeneration command.
   - `docs/security/attacks/cms.md` (French, as every framing document under `docs/`): one row per attack, with its corpus file, the rejecting test, and the error. It notes that the "chaîne contournée" attack (brief finding 4, issue #11) belongs to s16 for chain judgement, and that s03 covers only certificate substitution.

   Tests (`tests/attacks.rs`): one test per file, asserting **the exact variant** through `include_bytes!` and `verify(Some(content))`, never a bare `is_err()`.
8. [x] **Hostile input and fuzz target.**

   Tests (`tests/hostile.rs`):
   - `truncated_or_corrupted_der_is_an_error`: every prefix of `ec-detached.der` and of a Nacre signature, plus each length octet of the first 64 bytes replaced by `0x00`, `0x7f`, `0x84`, `0xff`. Every case must return `Err` from `from_der`, or from `verify` on success, with no panic.
   - `deep_nesting_is_an_error`: 10 000 nested definite-length constructed headers (e.g. `0x30 0x83 …`, each length covering the rest) → `Err`, with no stack overflow.

   Fuzz target:
   - `crates/nacre-cms/fuzz/Cargo.toml`: `[package] name = "nacre-cms-fuzz"`, `publish = false`, edition 2024, `rust-version = "1.97"`, `[package.metadata] cargo-fuzz = true`; deps `libfuzzer-sys = "0.4"` and `nacre-cms = { path = ".." }`; **`[workspace] members = ["."]`**; `[[bin]] name = "signed_data"`, `path = "fuzz_targets/signed_data.rs"`, `test = false`, `doc = false`, `bench = false`.
   - `fuzz_targets/signed_data.rs` runs `from_der`, then on success `to_der`, `verify(Some(data))` and `verify(None)`.
   - `fuzz/.gitignore` lists `target`, `corpus`, `artifacts`, `coverage`.

   Checks:
   - `cargo check --manifest-path crates/nacre-cms/fuzz/Cargo.toml` on stable proves the separate workspace and the lint inheritance of the path dependency.
   - Then, user-space with no sudo: `rustup toolchain install nightly --profile minimal`, `cargo +nightly install cargo-fuzz --locked`, and from `crates/nacre-cms/`, `cargo +nightly fuzz list` and `cargo +nightly fuzz run signed_data -- -max_total_time=60`, as the CI loop does (`.github/workflows/ci.yml:45-48`). Record the outcome in the verification record. A crash becomes a corpus file under `tests/corpus/` before its fix (ADR-0008).
9. [x] **Closing checks**:
   - `cargo fmt --all --check`;
   - the full suite through `po-run --story s03-cms-signed-data --label test -- 'cargo test --workspace'`;
   - then, after the last edit, `po-run --story s03-cms-signed-data --label typecheck -- 'cargo clippy --workspace --all-targets --all-features -- -D warnings'`;
   - rerun the generator and check `git diff --exit-code crates/nacre-cms/tests/corpus/attacks` (the corpus is the generator's output).

## Scene viewpoints
—

## Run interdicts
- Empty diff on `Cargo.toml`, `rust-toolchain.toml`, `.gitignore`, `.github/workflows/`, `crates/nacre-core/` (frozen, `docs/architecture.md:59-60`).
- No `cms`, `x509-tsp` or `pkcs7` crate: `cargo tree -p nacre-cms -i cms` finds nothing, and neither `Cargo.toml` of `nacre-cms` names them.
- No `[workspace.dependencies]` anywhere. No `Cargo.lock` committed, the fuzz one included.
- No private key in git: `git grep -n "PRIVATE KEY"` and `git ls-files '*.pem' '*.key'` are empty on the story's diff.
- No read of the clock in `crates/nacre-cms/src/`: no `SystemTime`, `Instant` or `chrono`. `signing-time` is a parameter.
- No `unwrap`, `expect`, `panic!` or indexing in `crates/nacre-cms/src/`, and no `unsafe` anywhere in the crate.
- Tests write only under `CARGO_TARGET_TMPDIR`, never in the source tree. No test opens a network connection.
- The signed attributes are never verified from a re-encoding: `to_be_signed()` derives from the received octets.
- Outside `crates/nacre-cms/` and `docs/security/attacks/cms.md`, only `docs/research/`, `docs/plans/` and `docs/verif/` of this story change.

## The pivot
Everything rests on **keeping received bytes**: the signed attributes, the certificates and the CRLs as they arrived. Verification hashes `0x31 ‖ received content`, and re-encoding writes them back unchanged. Three ways it could be wrong:
- a `der` derive on `SetOfVec<Attribute>` slips in for `signed_attrs`, which sorts silently on decode (`der-0.8.2/src/asn1/set_of.rs:626-636`). Compare `to_be_signed()` with the fixture's own bytes at the offset `openssl asn1parse` gives (`cont [0]` at 501 in the probe): the round-trip test and `changed_signed_attribute_byte_fails` both turn red.
- the check order of task 5 lets an earlier rule answer for an attack case. Each attack test asserts its exact variant, and the reviewer neutralises one rule at a time and reruns `tests/attacks.rs`.
- the read API misses what s06/s07/s08/s14/s16 need while the crate freezes: compare it with `docs/stories.md:109-113,127-135,147,250,285`. In particular s07 needs encapsulated content and RSA, and s08 needs `push_unsigned_attribute` and the signature value.

## Files touched
- `crates/nacre-cms/Cargo.toml`, `src/{lib,error,oid,model,sign,verify}.rs`
- `crates/nacre-cms/examples/forge_attacks.rs`
- `crates/nacre-cms/tests/{sign,read,attacks,hostile}.rs`
- `crates/nacre-cms/tests/corpus/README.md`, `tests/corpus/openssl/*`, `tests/corpus/attacks/*.der`
- `crates/nacre-cms/fuzz/{Cargo.toml,.gitignore,fuzz_targets/signed_data.rs}`
- `docs/security/attacks/cms.md`
- `docs/research/s03-cms-signed-data.md`, `docs/plans/s03-cms-signed-data.md`, `docs/verif/s03-cms-signed-data.md`

## Test strategy
Twenty-four automated tests, within `Test budget: 25`, all integration tests of the public API: the crate is the service layer, with no adapter or persistence.

| File | Tests | Rule each one proves (it fails if the rule is deleted) |
| --- | --- | --- |
| `tests/sign.rs` | 5 | required attributes and ESS hash; OpenSSL acceptance (the external judge); the PAdES profile refuses `signing-time`; the CMS profile writes it; digest length |
| `tests/read.rs` | 7 | ECDSA, RSA and encapsulated verification of OpenSSL output; content byte → `MessageDigestMismatch`; attribute byte → `SignatureInvalid`; byte-identical round trip; unsigned attribute without re-signing |
| `tests/attacks.rs` | 8 | one per corpus case, each on its own rule of task 5, with the exact variant |
| `tests/hostile.rs` | 2 | truncation and wrong lengths → `Err`; deep nesting → `Err` |

- The rule "exactly one `SignerInfo`" is the only check with no test of its own. It is the first check, so no attack case reaches it, and it is cheap to read in review.
- The OpenSSL test runs `openssl` from `PATH`, present on `ubuntu-latest` and locally (3.6.5). ADR-0007 makes it the CMS judge.
- The fuzz run (60 s) is a check, not a test.

Visual checks: none (library, Surface `endpoint`).

## Done when
- One commit `s03-cms-signed-data: …` on `story/s03-cms-signed-data`, landed through a pull request whose CI is green, the fuzz job included. That is the first non-empty run of the fuzz loop.
- `cargo fmt --check`, the full suite and clippy recorded green in `docs/verif/s03-cms-signed-data.md`.
- Each of the five criteria is traced to its test above, with no open critical finding in review.
