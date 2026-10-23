# Review — s08-pades-bt

[Story](../stories.md) · [Plan](../plans/s08-pades-bt.md) · [Verification](../verif/s08-pades-bt.md)

Diff reviewed: `git diff main...story/s08-pades-bt`, in a context that did not write it. Findings rated critical, major or minor.

Review status: complete
Fix loop: 0
Reviewed tree: 649fb7ed5f79f2d7fcc545e7111012ba97dccf0b

## When blocked
- Failure cause: —
- Missing: —
- Required adaptation: —
- Next action: —

## Ownership
I listed the diff with `git diff --name-only main...story/s08-pades-bt` and checked each path against `Owns: crates/nacre-pades/`.
- [x] Every path inside `Owns`. There are 8 code paths, all under `crates/nacre-pades/`. The rest is the story's own pipeline evidence (`docs/research/`, `docs/plans/`, `docs/verif/`, `docs/qa/s08-pades-bt/`), which is in scope by construction.
- [x] Outside `Owns`: none.
- [x] Inside another running story's `Owns`: none. The other worktrees are s10 (`crates/nacre-revocation/`) and s15 (`crates/nacre-validate/`), and neither overlaps.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s08-pades-bt` exits 0. I also checked it by hand: the code outside `docs/` at `Tree: f449438…` equals HEAD. With `Verification mode: record` I reused the record for `cargo test --workspace` and `cargo clippy --workspace --all-targets --all-features -- -D warnings`, both exit 0. Its "Not proven here" section says the DSS run was done by hand and not recorded by `po-run`; that run is listed under Not verified.
- [x] `po-gate qa-current s08-pades-bt` exits 0 (`QA status: complete`, and `Tree: 5841213…` equals HEAD outside `docs/`). The QA report has two verified findings. Both are carried below at minor.

## Plan
- [x] Tasks 1 to 6 are all present and nothing was added outside the plan. Each item matches the plan: the error variants and their kinds, `with_token` as the only place the attribute is built, the imprint over `signer_infos[0].signature`, the placeholder `Any::new(OctetString, MAX-4)` (header `04 82 3F FC`, 16 384 DER bytes), the `Level` enum (`#[non_exhaustive]`, no `Debug`), `sign_at_level`, and `sign` delegating with `Level::B`. The re-exports, crate doc, `description` and dev-dependency are as planned, the conformance test exists, and there are 5 service tests plus 3 kind rows.
- [x] Run interdicts, checked one by one:
  - The diff outside `crates/nacre-pades/` holds only the story's own docs.
  - `sign` keeps its exact signature, and the existing tests of `tests/sign.rs` are unmodified and pass (`reserve_leaves_only_the_signature_slack` included).
  - `[dependencies]` is unchanged, and `nacre-tsp` appears only under `[dev-dependencies]`.
  - Nothing under `src/` constructs `nacre_core::Error::Timestamp`, reads a clock or uses the network.
  - `src/` has no index or unwrap. `ObjectIdentifier::new_unwrap` is a const evaluation; clippy passed under the workspace lints.
  - The conformance test uses only the bench TSA (`127.0.0.1:18081`).
  - The signer and the TSA are each called once, with no dry-run TSA request. The `Sizing` dry run does not reach the signer, as at B-B.

## References
- [x] I opened `SignedData::from_der`/`to_der` (`crates/nacre-cms/src/model.rs:84,144`), `push_unsigned_attribute` (`:282`), `Attribute` (`:289`), unsigned attributes written as a sorted `[1]` set (`:274-276`), `nacre_cms::Error::SignerCount` (`crates/nacre-cms/src/error.rs:15`), `TimestampAuthority::timestamp` (`crates/nacre-core/src/timestamp.rs:4-8`), the kind of `nacre_core::Error::Timestamp` (`crates/nacre-core/src/error.rs:16,28`), `HttpTsa::new` and `reports_dir`. All match their use.
- [x] Values:
  - The OID `1.2.840.113549.1.9.16.2.14` is `id-aa-signatureTimeStampToken`, as RFC 3161 Appendix A defines it.
  - The imprint covers the content octets of the signature value, as RFC 3161 Appendix A requires.
  - 16 380 = 0x3FFC, so the placeholder's DER length is exactly 16 384.
  - The 16 384 bound is argued in the plan (2.7 times the recorded 6 KB DigiCert token).

## Rules
- [x] The `AGENTS.md` conventions are respected: one `thiserror` enum, `kind()` delegating, no secret or path in messages, no clock read, no network in `src/`.
- [x] No accepted ADR is contradicted. ADR-0016 / s39: `Timestamp` delegates to `inner.kind()` and never builds the core variant.

## Tests
- [x] Floor: `po-gate floor-guard s08-pades-bt main` exits 0, so nothing was lowered.
- [x] The assertions pin criteria 2, 3 and 4 and the malformed-token case. None of the six empty test shapes appear. The fake TSA records the imprint it was asked for and does not decide the outcome itself.
- [x] Within `Test budget` 25: 5 new tests plus 3 table rows, and 1 ignored conformance test.
- [x] Bite, each run on `cargo test -p nacre-pades --test sign` only, then undone and confirmed with `git diff --exit-code` on the file:
  - The imprint over the whole CMS instead of the signature value fails 1 test (`level_t_stores_the_token_over_the_signature_value`).
  - Removing the `token.len() > TIMESTAMP_TOKEN_MAX` check fails 1 test (`oversized_token_is_refused`). Without the check, the 16 385-byte token was embedded into a PDF, so the check is required and not redundant with `embed`.
  - A placeholder of `MAX - 5` fails 1 test (`largest_token_fits_with_only_the_signature_slack`).
- [x] The story made no test useless.

## Neighbours
- [x] Other callers of `sign` (`crates/nacre-validate/src/validate.rs:174`, `tests/validate.rs`, `tests/hostile.rs`, `examples/forge_pades_attacks.rs`, `crates/nacre-pkcs11/tests/conformance.rs`, `examples/sign_pdf.rs`) keep the unchanged signature and the B-B path. `contents_capacity(.., false)` returns the same value as before. `Error` is `#[non_exhaustive]`, so the new variants break no match. All of this compiled and passed under the recorded workspace clippy and test runs.

## Lenses
Lenses run: dependencies — `crates/nacre-pades/Cargo.toml` adds the dev-dependency `nacre-tsp` (in-repository path crate, named in plan task 5, dev only, no lockfile in git; nothing to flag)
- [x] No lens finding.

## Findings
- minor — crates/nacre-pades/src/error.rs:12 — The `Timestamp` message is the same as that of the `nacre_core::Error::Timestamp` it wraps. Walking `source()` therefore prints "the timestamp authority failed" twice before the real cause (QA finding 2, verified, `docs/qa/s08-pades-bt/tsa-failure.txt`). The plan dictated this wording. A wrapper message that adds context, or `#[error(transparent)]`, would avoid the repetition.
- minor — crates/nacre-pades/src/timestamp.rs:50 — A TSA failure names the role ("timestamp authority") but not which authority failed, because `TimestampAuthority` exposes no name or URL (QA finding 1, verified, `docs/qa/s08-pades-bt/tsa-failure.txt`).
  - This meets the research's corrected criterion 3, but `docs/stories.md:148` still says « une erreur qui nomme la TSA ».
  - The same applies to criterion 1 at `docs/stories.md:146` (« `sign` au niveau T », while the code adds `sign_at_level`) and to criterion 4.
  - The plan's Done-when gives the lead the job of carrying the corrected criteria into `docs/stories.md`, and into s11/s12. This has not been done yet; it lives outside this diff.
- minor — crates/nacre-pades/tests/sign.rs:233 — The test helper `der_of_len` encodes lengths 128 to 255 of content in a way DER does not allow. For n in 130..=257 it produces the long form `81 xx` even when the content length is below 128. The tests only use n = 100, 16 384 and 16 385, so no current result is affected.

## Not verified
- **Criterion 1 (DSS declares `TOTAL_PASSED` at `PAdES-BASELINE-T` against the s02 local TSA)**, from the QA report's Not seen. The test `bench_signature_is_pades_baseline_t` is `#[ignore = "conformance"]`, and `po-run` did not record its run. The only trace is the verif note and a leftover `target/conformance/s08-pades-t.xml` dated 2026-10-22 15:03. That file shows a `total-passed` main indication and a timestamp, but I could not read the level `PAdES-BASELINE-T` from it. I did not start the bench. A person should start `conformance/compose.yaml` and run `cargo test -p nacre-pades --test conformance -- --ignored bench_signature_is_pades_baseline_t`, or rely on `.github/workflows/conformance.yml` passing on the pull request.
- **Behaviour against a real remote TSA or under network latency**, from the QA report's Not seen: it needs the real network. The plan forbids calling a public TSA from tests. A person may run one manual signature against FreeTSA or DigiCert and check that the token stays within 16 384 bytes.
- **nacre-pades does not verify the token it embeds** (plan pivot, by design). A caller's own `TimestampAuthority` that returns an unverified token gets it embedded; only `Any::from_der` checks that it is a single DER value. I did not treat this as a defect, since the plan settles it explicitly. Later validation (s17) should judge such tokens.
- **The production build** was not run: it is deferred to ship (`Build stage: ship-if-route`), and the diff changes no routing. The only manifest change is a dev-dependency. The project has no E2E command (`E2E: —`).
- One `po-bounds` refusal happened during the review: `git check-ignore` was refused in reviewer mode. It was incidental (checking whether `target/` is ignored), I dropped it, and the review did not need it.

Max severity: minor
Ship allowed: yes
