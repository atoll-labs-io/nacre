# Research — s16-validate-chain

[Story](../stories.md)

## Structuring facts
- **Story gap: `Owns` is too narrow.** The convention gives each format its known attacks in `docs/security/attacks/<format>.md`, one corpus case and one rejecting test each (`AGENTS.md`, Conventions). Two attack files hand the chain to s16 and will be false once it ships: `docs/security/attacks/cms.md:22` ("Chaîne contournée … relève de s16", brief finding 4, issue #11) and `docs/security/attacks/pades.md:79` ("une signature intègre finit donc `INDETERMINATE` / `NO_CERTIFICATE_CHAIN_FOUND`"). The stories review already flagged it as a major (`docs/reviews/stories.md:68`). `Owns: crates/nacre-validate/` (`docs/stories.md:282`) does not cover them: the story must add `docs/security/attacks/cms.md` and `docs/security/attacks/pades.md` to `Owns` before `/po-execute`, or the implementer cannot write them.
- No chain code exists anywhere. `nacre-cms` proves the signature and its binding to a certificate carried in the `SignedData`, not trust in it (`crates/nacre-cms/src/verify.rs:43-44`). `validate` throws away the signer it verified (`crates/nacre-validate/src/validate.rs:169-171`, `.map(|_| ())`) and every sound signature ends `INDETERMINATE` / `NO_CERTIFICATE_CHAIN_FOUND` (`crates/nacre-validate/src/report.rs:96-105`).
- The bench PKI of s02 is regenerated at every bench start and never committed (`conformance/pki/README.md`, `conformance/pki/generate.sh:1-8`): criterion 1 as written ("la racine de la PKI de s02") can only be checked by an `#[ignore = "conformance"]` test. Committed tests need their own fictitious PKI, forged deterministically.
- Certificate signature verification exists twice, private, in crates this story does not own (`crates/nacre-cms/src/verify.rs:253-273`, `crates/nacre-revocation/src/verify.rs:50-126`); `/DSS /Certs` reading exists once, private, in `nacre-pades` (`crates/nacre-pades/src/archive.rs:152-184`). nacre-validate must hold its own copies.
- Criterion 3's sub-indications are not settled by any file of the repository: DSS's mapping of expired, key-usage and basic-constraint failures was never observed on the bench. See Open questions.

## Story
Build the signer's chain from the certificates of the CMS and of `/DSS` up to an anchor the caller supplies, and judge it (RFC 5280 path validation written by Nacre over `x509-cert` models, ADR-0004), at a control date given as a parameter (s17 replaces it by the proven date).
1. With the s02 bench root as anchor, the chain of an s06 signature is built and judged valid.
2. With no anchor, `validate` gives `INDETERMINATE` / `NO_CERTIFICATE_CHAIN_FOUND`, never `TOTAL_PASSED`.
3. A certificate expired at the control date, a key usage incompatible with signing (`digitalSignature` or `nonRepudiation` absent), or a violated basic constraint gives the matching EN 319 102-1 sub-indication.
4. Chain building and judging are a public API of `nacre-validate`, usable by CAdES, XAdES, JAdES without PDF.

## Current code
- `validate(pdf)` (`validate.rs:25-27`) → `validate_with(pdf, max_signatures)` (`:29-104`): collects signature fields, skips document timestamps (`:40-42`), runs `check` per signature (`:53-59`), qualifies later revisions (`:60-64`), then picks the outcome by precedence (`:90-101`): integrity defect, then `AddedByRevisionNotAllowed`, then `RevisionNotAllowed`, then `sound`.
- `check` (`:112-121`) → `signed_bytes` (`:125-160`) then `verify` (`:162-172`), which calls `SignedData::from_der(der).and_then(|s| s.verify_detached_digest(&digest).map(|_| ()))`.
- `SignatureValidation` (`report.rs:5-20`, `#[non_exhaustive]`): `field`, `report`, `digest_verified`, `signature_verified`, `defect`, `later_revisions`. Built only by `sound` (`:96-105`) and `defective` (`:107-132`); `defective` maps revision defects to `(failed, true, true)` (`:119-121`) and the rest to `(failed, false, false)` (`:122`).
- `Defect` (`report.rs:62-93`, `#[non_exhaustive]`): structural, revision and `Cms(nacre_cms::Error)` variants.
- `Error` (`error.rs:5-15`): `Pdf`, `TooManySignatures`, `TooManyRevisions`; `kind()` (`:19-27`); the table test `every_variant_has_its_kind` (`:35-49`).
- `lib.rs:1-21` crate doc states the chain is not judged (`:19-20`); exports at `:28-31`.
- `Cargo.toml:12-24`: deps `nacre-core`, `nacre-pdf`, `nacre-cms`, `sha2`, `der`, `thiserror`; dev-deps `nacre-core[test-signer]`, `nacre-pades`, `der[oid]`. No `x509-cert`, `p256`, `rsa`, `spki` yet.

## Attachment points
- `validate.rs:162-172` (`verify`): keep the `VerifiedSigner` (`crates/nacre-cms/src/verify.rs:17-32`, `certificate()` gives the signer DER) and `SignedData::certificates` (`crates/nacre-cms/src/model.rs:67-78`, raw DER, non-`0x30` choices to skip as `verify.rs:127-130` does).
- `validate.rs:90-101`: the precedence match, where a chain verdict joins after the revision rules.
- `report.rs:96-132`: `sound` / `defective`, and a new chain field on `SignatureValidation`.
- `lib.rs:28-31`: new `pub mod`/`pub use` for the chain API.
- `error.rs:5-15`: a variant for an unreadable trust anchor.
- `Cargo.toml`: `x509-cert = "0.3"`, `spki = "0.8"`, `p256 = { version = "0.14", features = ["ecdsa"] }`, `rsa = "=0.10.0-rc.19"` as `nacre-revocation` declares them (`crates/nacre-revocation/Cargo.toml`); dev-deps for forging (`x509-cert` `builder`, `p256` `pkcs8`/`pem`, `der` `pem`, `nacre-conformance`).
- `tests/corpus/README.md`, `tests/attacks.rs`, `tests/hostile.rs:16-34` (iterates `corpus/attacks/`, calls `validate` only).
- `examples/forge_pades_attacks.rs` writes every PADES attack deterministically (`:1-8`); its helpers take `&TestSigner` (`:113`, `:504-569`).

## Verified interfaces
- `nacre_pades::sign(pdf: &[u8], signer: &dyn Signer, signing_time: DateTime) -> Result<Vec<u8>, Error>` (`crates/nacre-pades/src/sign.rs:65`); the CMS carries the signer's whole `certificate_chain()` (`crates/nacre-cms/src/sign.rs:76`).
- `Signer` trait: `algorithm`, `certificate_chain(&self) -> &[Vec<u8>]`, `sign_digest` (`crates/nacre-core/src/signer.rs:4`); a bench implementation to copy: `BenchSigner` (`crates/nacre-pades/tests/support/mod.rs:10-69`), `bench_certificate` (`:28-33`), `nacre_conformance::pki_dir()` (`crates/nacre-conformance/src/lib.rs:53`).
- `TestSigner` is a self-signed `cabf::Root` with `keyUsage` `keyCertSign | cRLSign` only (`crates/nacre-core/src/test_signer.rs:33-34`; `x509-cert-0.3.0/src/builder/profile/cabf.rs:171-173`): every existing test signs with a CA certificate that has no signing key usage.
- `x509_cert::Certificate`: `tbs_certificate()`, `signature_algorithm()`, `signature()`; `TbsCertificateInner::{issuer, subject, validity, subject_public_key_info, extensions, get_extension}` (`x509-cert-0.3.0/src/certificate.rs:169-352`); `get_extension` errors on a duplicate extension (`:265-276`). `Time::to_system_time()` is how the repository compares dates (`crates/nacre-revocation/src/crl.rs:70-80`).
- Control date precedent: `Crl::status(&self, certificate: &[u8], issuer: &[u8], at: SystemTime)` (`crates/nacre-revocation/src/crl.rs:98-103`), DER in, `SystemTime` date.
- Signed TBS bytes as received: `signed_tbs` (`crates/nacre-revocation/src/crl.rs:168-174`); outer/inner algorithm equality check (`crates/nacre-revocation/src/verify.rs:26-29`); ECDSA P-256 / RSA PKCS#1 v1.5 SHA-256 verification (`:50-126`).
- Forging profile with chosen `basicConstraints` and `keyUsage`: `Small` (`crates/nacre-revocation/examples/forge_attacks.rs:213-250`), `certificate()` (`:259-264`).
- `/DSS` writing: `Update::add_stream`, `Update::set_catalog` (`crates/nacre-pdf/src/revision.rs:110`, `:122`), as `crates/nacre-pades/src/dss.rs:80-128` uses them; streams written unfiltered (`dss.rs:108`, `Dictionary::new()`). `nacre-pdf` exposes no stream decoder (`crates/nacre-pdf/src/lib.rs:32-38`).
- `SubIndication` has every EN 319 102-1 value, incl. `OutOfBoundsNoPoe`, `ChainConstraintsFailure`, `CertificateChainGeneralFailure`, `TryLater`, `NoCertificateChainFound` (`crates/nacre-core/src/report.rs:62-88`).

## Traps
- **Existing tests pin "no anchor".** `s06_signature_is_verified_but_indeterminate` (`tests/validate.rs:106-122`) and the helper `allowed` (`:41-49`, asserts `defect.is_none()` and `Indeterminate`) are used by seven tests; the attack helpers (`tests/attacks.rs:15-56`) assert `TOTAL_FAILED`. Keeping `validate(pdf)` as "no anchor" and `defect: None` for "no path found" leaves all of them unchanged.
- **Corpus bytes.** Every PADES corpus file is rewritten by `forge_pades_attacks` and pinned by SHA-256 in `tests/corpus/README.md`; tests assert object numbers (`tests/attacks.rs`). Chain cases must come from a separate forge so existing output stays byte-identical.
- **`hostile.rs` reads every file of `corpus/attacks/`** (`tests/hostile.rs:21-24`): new chain files are fuzzed by it for free, but only through `validate` without anchors, which never reaches chain code.
- **Bounded input** (Conventions): candidate issuers multiply when many certificates share a name and key; path search needs a depth cap and a signature-check budget, or a hostile `/DSS` turns it exponential.
- **Third-party corpus** (`certified-dss.pdf`, RSA; pyHanko files) has no anchor in the repository and stays `NO_CERTIFICATE_CHAIN_FOUND`; a filtered `/DSS /Certs` stream (pyHanko may compress) is skipped, as `archive.rs:152-154` does.
- `tsp.md:25` also hands the TSA chain to s16, but s17 criterion 4 takes it (`docs/stories.md:305`): out of scope here, outside `Owns`.
- Full suite `cargo test --workspace`; conformance job `cargo test --workspace --all-features -- --ignored` picks up a new ignored test with no workflow change. No migration. New dependencies are RustCrypto crates ADR-0004 already names.

## Open questions
- **Sub-indications of criterion 3.** EN 319 102-1 reads: a certificate outside its validity with no POE → `INDETERMINATE` / `OUT_OF_BOUNDS_NO_POE`; a path failing a validation constraint → `CHAIN_CONSTRAINTS_FAILURE`; any other path failure → `CERTIFICATE_CHAIN_GENERAL_FAILURE`. Whether DSS 6.5.1 files a CA flag or path-length violation under the second or the third, and whether its default policy only *warns* on a signing key usage, was not observed. The forged PKI is not DSS's anchor, so this lane cannot ask DSS; the s18 campaign will. The plan decides.
- **Outcome of a valid chain before revocation is judged (s17).** `TOTAL_PASSED` would accept a revoked signer; s17's own criterion gives `INDETERMINATE` / `TRY_LATER` when no revocation data exists (`docs/stories.md:304`). The plan decides.
- **Trust anchor semantics.** RFC 5280 judges neither the anchor's validity nor its extensions; DSS's behaviour for an expired anchor certificate was not observed.
- **Name matching.** RFC 5280 §7.1 compares names after normalisation; byte equality of the DER `Name` is stricter (a mismatch finds no path, never a false path).
- Does a valid chain whose leaf is itself an anchor need revocation (DSS treats a trusted certificate as such)? Left to s17.

## Complexity
Story 3 → 4. RFC 5280 path building and judging (search bounded against hostile input, validity, basic constraints, path length, key usage, critical extensions), certificate signature verification copied in, a new public PDF-free API, a forged deterministic PKI with one corpus case per chain attack, the attack docs, and one bench test. Nothing touches `nacre-core` or another crate.

## Split
Not needed below 5. If the lead prefers, the attack corpus and docs (plan tasks 6-7) could become their own story; criterion 3 would then have no corpus case.
