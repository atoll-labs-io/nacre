# Review — s03-cms-signed-data

[Story](../stories.md) · [Plan](../plans/s03-cms-signed-data.md) · [Verification](../verif/s03-cms-signed-data.md)

Diff reviewed: `git diff main...story/s03-cms-signed-data`, in a context that did not write it. Findings rated critical, major or minor.

Review status: complete
Fix loop: 0
Reviewed tree: f6d8d737646c8e46994bc5cbd2dcdcd58d542cbc

## When blocked
- Failure cause: —
- Missing: —
- Required adaptation: —
- Next action: —

## Ownership
I listed the diff with `git diff --name-only main...story/s03-cms-signed-data` and held each path against `Owns: crates/nacre-cms/, docs/security/attacks/cms.md` (`docs/stories.md:54`).
- [x] Every path is inside `Owns` (`crates/nacre-cms/**`, `docs/security/attacks/cms.md`) or is this story's own evidence (`docs/research/`, `docs/plans/`, `docs/verif/`, `docs/qa/s03-cms-signed-data/`).
- [x] Nothing is outside `Owns`.
- [x] Nothing is inside another running story's `Owns`. The other running worktrees are s02 (`conformance/`, `crates/nacre-conformance/`, `.github/workflows/conformance.yml`) and s04 (`crates/nacre-pdf/`); neither overlaps.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s03-cms-signed-data` exits 0, so I reused the record. `po-gate` is not on PATH; I ran the project's copy at `.polype/hooks/po-gate.sh`. By hand: `Tree:` 1a1bfd1f… and both run trees (7c926864… for the suite, 02951eac… for clippy) are identical to HEAD outside `docs/`, and both runs exited 0. I did not rerun the suite or clippy (`Verification mode: record`). From the record's "Not proven here": the fuzz run, `cargo fmt --check` and the fuzz manifest `cargo check` were run locally but are not `po-run` rows, and the OpenSSL version on `ubuntu-latest` is proven only in CI.
- [x] `po-gate qa-current s03-cms-signed-data` exits 0. The QA report is complete. Its one verified finding (minor) is carried below, and its `## Not seen` items are under Not verified.

## Plan
- [x] Tasks 1–9 are all present. One deviation, listed under Findings: in task 4, an unknown signer algorithm returns `Error::Signer`, not `UnsupportedAlgorithm`. Nothing is outside the plan.
- [x] Run interdicts, checked one by one:
  - Files that must not change: no diff on `Cargo.toml`, `rust-toolchain.toml`, `.gitignore`, `.github/`, `crates/nacre-core/`.
  - Forbidden crates: none of `cms`, `x509-tsp` or `pkcs7` is in either manifest, and `cargo tree -p nacre-cms -i cms` finds no such package.
  - Workspace and lock files: no `[workspace.dependencies]`, and no `Cargo.lock`, `.pem` or `.key` is tracked.
  - Private keys: no added `PRIVATE KEY` line (the only matches are prose in the plan and research).
  - Panics and unsafe code: no clock read, no `unwrap`, `expect` or `panic!` in `src/`, and `#![forbid(unsafe_code)]` is present.
  - Test files: the OpenSSL test writes only under `CARGO_TARGET_TMPDIR`.
  - Signed bytes: `to_be_signed()` uses the received octets (`model.rs:341-343`).

## References
- [x] I opened and confirmed these against the registry sources:
  - `nacre_core::Signer` and its methods.
  - `der` 0.8.2: `SliceReader`, `Header`, `SetOfVec`, and `Position::MAX_DEPTH = 64` (per reader).
  - ecdsa 0.17 `verify_prehashed`, which rejects high-S only when `C::NORMALIZE_S`; p256 0.14 sets `NORMALIZE_S = false` (`p256-0.14.0/src/ecdsa.rs:60`), so the code's high-S comment is true.
  - `rsa` 0.10.0-rc.19 `pkcs1v15::VerifyingKey::from_public_key_der`.
  - The `x509-cert` accessors.
- [x] Values checked:
  - OIDs: id-signedData, id-data, contentType, messageDigest, signingTime, signingCertificateV2 `1.2.840.113549.1.9.16.2.47`, TSTInfo `…16.1.4`, signature-time-stamp `…16.2.14`, sha256, ecdsa-with-SHA256, id-ecPublicKey, prime256v1, rsaEncryption, sha256WithRSAEncryption.
  - Versions: SignedData version 1 and SignerInfo version 1 match RFC 5652 §5.1 and §5.3 for id-data with issuerAndSerialNumber.
  - SHA-256 is 32 bytes, and `ESSCertIDv2.hashAlgorithm` is omitted as DEFAULT.

## Rules
- [x] `AGENTS.md` conventions are respected: the "experimental" crate doc, one `thiserror` enum, no output, the clippy denies, the corpus README noting sources, the attacks file in French, and a fuzz crate with its own workspace.
- [x] No accepted ADR is contradicted (ADR-0001, ADR-0003, ADR-0004, ADR-0007, ADR-0008).

## Tests
- [x] Floor: `po-gate floor-guard s03-cms-signed-data main` exits 0, so nothing was lowered.
- [x] The assertions name exact variants. The attack fixtures are each correctly signed apart from their one defect: the forged fields (`signatureAlgorithm`, `sid`, `certificates`, `eContentType`) are outside the signed attributes, and re-signed cases go through `resign`. Two exceptions, listed under Findings: `deep_nesting_is_an_error` proves nothing about depth, and the pivot rule is untested.
- [x] Within `Test budget: 25`: 22 tests (sign 5, read 7, attacks 8, hostile 2).
- [x] Bite (each mutation run against the test files that exercise it, then undone and confirmed with `git diff --exit-code <file>`; the worktree ends clean):
  - ContentTypeMismatch return removed (`verify.rs:90`): 1 test fails (`content_type_mismatch_is_rejected`).
  - signingCertificateV2 check skipped (`verify.rs:101`): 1 test fails (`substituted_certificate_is_rejected`).
  - EC key accepts any declared signature algorithm (`verify.rs:207`): 1 test fails (`algorithm_confusion_is_rejected`).
  - DuplicateAttribute return removed (`verify.rs:157`): 1 test fails (`duplicated_signed_attribute_is_rejected`).
  - The plan's pivot, `to_be_signed()` rebuilt from the decoded, re-sorted attributes (`model.rs:342`): **0 failing tests across all 22** in attacks, hostile, read and sign. This is a finding.
- [x] The crate is new, so no existing test was made useless.

## Neighbours
- [x] The crate is new and nothing in the workspace calls it yet. `nacre-core` is unchanged.

## Lenses
Lenses run: dependencies — triggered by the new manifests `crates/nacre-cms/Cargo.toml` and `crates/nacre-cms/fuzz/Cargo.toml`, which add `der`, `spki`, `x509-cert`, `sha2`, `p256`, `rsa =0.10.0-rc.19`, `thiserror` and `libfuzzer-sys`. Security, migration and performance were not triggered: no matching path or content. The code is a verifier, though, so I read it with security in mind throughout.
- [x] Each lens finding is graded and listed below.

## Findings
- major — crates/nacre-cms/src/model.rs:341 — The rule the plan calls its pivot is untested: signed attributes must be verified over the received octets, never a re-encoding. Replacing `to_be_signed()` with a re-encoding of the decoded, DER-sorted attributes fails none of the 22 tests.
  The cause is that every fixture already carries its signed attributes in DER order (OpenSSL and Nacre both write them that way), so re-sorting is a no-op.
  Two documents claim coverage that does not exist:
  - The plan says (§ The pivot) that `round_trip_is_byte_identical` and `changed_signed_attribute_byte_fails` "both turn red".
  - `docs/security/attacks/cms.md` (section "Attributs signés réordonnés") names those same tests as the protection.
  The code is correct today; what is missing is the regression guard for the crate's core invariant, in a crate that freezes after s03.
  Fix: add one generated case whose signed attributes are deliberately out of DER order and signed over those bytes, and assert the exact outcome the plan intends (verification over the received bytes).
- minor — crates/nacre-cms/tests/hostile.rs:212 — `deep_nesting_is_an_error` never reaches any depth.
  - The 10 000-level blob fails at once: `ContentInfo::from_der` expects an OID at `model.rs:43` and finds a SEQUENCE.
  - The same blob injected as a certificate fails `Certificate::from_der` on a tag mismatch within three levels.
  The test would pass with no depth protection at all. Separately, `docs/security/attacks/cms.md` ("Entrée DER hostile") credits "profondeur bornée à 64" from `der`. But `nested()` (`model.rs:394`) opens a fresh `SliceReader` at each level, whose depth starts at 0 (`der-0.8.2/src/reader/position.rs:22-28`), so that bound never builds up.
  The real protection is structural: the hand-written decoder never recurses, and attribute values stay opaque `Any`. QA's c4 evidence confirms deep blobs placed in the open fields are handled. Criterion 4 therefore holds, but the test and the attacks file explain it wrongly.
  Fix: correct the attacks file, and rebuild the test so the deep blob sits where a recursive decode would happen (for example inside a signed attribute value), as QA did.
- minor — crates/nacre-cms/src/verify.rs:55 — Two public paths have no test, in a crate that freezes:
  - `verify_detached_digest`, the ByteRange entry point s14 relies on. QA exercised it against the attack files only (`c5-attacks-error.txt`).
  - The `SubjectKeyIdentifier` branch of signer-certificate lookup (`verify.rs:138-141`).
  A broken digest closure or a broken SKI match would fail no test. Fix: one positive `verify_detached_digest` test on a Nacre signature, plus one wrong-digest refusal.
- minor — crates/nacre-cms/src/sign.rs:69 — The code departs from the plan's task 4. The plan says an unknown `SignatureAlgorithm` variant gives `UnsupportedAlgorithm`; the code returns `Error::Signer(nacre_core::Error::Signer("unsupported signature algorithm"))`. The branch is unreachable today (two variants), but a caller matching `UnsupportedAlgorithm` will miss it once `nacre-core` adds a variant. Fix: align the code with the plan, or record the deviation in the plan.
- minor — crates/nacre-cms/src/verify.rs:137 — Issuer matching compares two different things. One side is the sid's received issuer bytes; the other is `tbs.issuer().to_der()`, a re-encoding of the decoded `Name`, and `der` re-sorts each RDN's `SET OF` on decode (research, structuring fact 3).
  For a certificate whose multi-valued RDN is not in DER order (some foreign CAs), a valid signature would give `SignerCertificateNotFound`. `sign.rs:81` likewise writes a re-encoded issuer into the sid, so it would not byte-match such a certificate.
  Found by reading only; not reproduced. Fix: compare against, and copy, the certificate's received issuer TLV.
- minor — crates/nacre-cms/src/error.rs:13 — Carried over from the QA report (verified finding 1). The `Display` messages name attributes and algorithms only by dotted OID, for example `the profile forbids attribute 1.2.840.113549.1.9.5` or `unsupported algorithm 2.16.840.1.101.3.4.2.2`, so a developer must look up what they mean. Evidence: `docs/qa/s03-cms-signed-data/c2-profile.txt`, `c2-profile-error.txt`, `c5-attacks.txt`, `c3-read-verify-openssl-error.txt`.
- minor — crates/nacre-cms/fuzz/Cargo.toml:11 — Dependencies lens. The plan names each new dependency and its reason, but neither the plan, the research nor the verification record says the build scripts were read. That matters for `libfuzzer-sys` (its `build.rs` compiles C++) and for the release candidate `rsa =0.10.0-rc.19`. Fix: record that review.
- minor — docs/plans/s03-cms-signed-data.md:150 — The test strategy says "Twenty-four automated tests", but its own table and the suite count 22 (5 + 7 + 8 + 2).

## Not verified
- The CI side of criteria 1 and 4 (QA `## Not seen`): neither the OpenSSL test nor the 60 s fuzz job has been observed on GitHub Actions; both were replayed only locally. Someone should watch the pull request's `check` and fuzz jobs go green; it will be the first non-empty run of the fuzz loop.
- Real signing hardware and a real PKI chain (QA `## Not seen`): only `TestSigner` and throw-away self-signed certificates were used, and judging the chain belongs to s16. This gets covered by s06/s16's DSS conformance runs.
- The fuzz run itself: I did not run cargo-fuzz. I rely on the verification record (4 291 980 runs in 61 s) and on QA's `c4-fuzz-target.txt`.
- The unit suite, clippy and `cargo fmt --check`: not rerun. I relied on the verification record, which is current for this code; fmt is not a `po-run` row.
- RSA verification beyond the single OpenSSL RSA-2048 fixture and QA's fresh RSA signatures: no RSA-4096, no explicit-NULL versus absent parameter variants, no `sha256WithRSAEncryption` declared in place of `rsaEncryption`. Someone should verify a real TSA token (FreeTSA, DigiCert) during s07.
- The issuer-matching interop issue (finding 5) is reasoned from the code and `der`'s documented re-sort, not reproduced with a real certificate. A person could build a certificate with an unsorted multi-valued RDN and check it.
- The production build: not run. No routing or manifest outside the new crate changed (`Build stage: ship-if-route`), so it waits for ship.

Max severity: major
Ship allowed: yes
