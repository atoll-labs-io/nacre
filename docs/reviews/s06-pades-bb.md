# Review — s06-pades-bb

[Story](../stories.md) · [Plan](../plans/s06-pades-bb.md) · [Verification](../verif/s06-pades-bb.md)

Diff reviewed: `git diff main...story/s06-pades-bb`, in a context that did not write it. Findings rated critical, major or minor.

Review status: complete
Fix loop: 0
Reviewed tree: debbde3762bf39f9bb1c1a54dc22973aee43785a

## When blocked
- Failure cause: —
- Missing: —
- Required adaptation: —
- Next action: —

## Ownership
I listed the diff with `git diff --name-only main...story/s06-pades-bb`: 25 files, all added.
- [x] Every path is inside `Owns`. Eleven are under `crates/nacre-pades/`, which matches `Owns: crates/nacre-pades/`. The other fourteen are the story's own evidence: `docs/research/`, `docs/plans/`, `docs/verif/` and `docs/qa/s06-pades-bb/`.
- [x] No path is outside `Owns`. The diff is empty outside `crates/nacre-pades/` and `docs/`.
- [x] No path is inside another running story's `Owns`. The running worktrees are s07 (`crates/nacre-tsp/`) and s09 (`crates/nacre-revocation/`). s08 also owns `crates/nacre-pades/`, but it has no worktree and no branch in flight.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s06-pades-bb` exited 0, so I reused the record (`Verification mode: record`). `cargo test --workspace` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` both exited 0 on code identical to `Tree: 3c2e586…` outside `docs/`. I read its "Not proven here" section, and it is carried below.
- [x] `po-gate qa-current s06-pades-bb` exited 0. The story goes to QA (`Surface: endpoint`, `QA stage: surfaces`). The QA report has no verified finding, so none is carried. Its `## Not seen` items are under Not verified.

## Plan
- [x] Tasks 1–5 are all present, with the files the plan lists. Nothing was changed outside the plan.
- [x] Each run interdict is respected:
  - The diff is empty outside `crates/nacre-pades/` and the story's `docs/`.
  - There is no `[workspace.dependencies]`, no `Cargo.lock`, and no `cms` or `x509-tsp` crate. Every dependency (sha2 0.11, der 0.8, x509-cert 0.3, thiserror 2, p256 0.14) is already in the graph, with one p256 v0.14.0 in `cargo tree`.
  - `grep SystemTime|Instant` over `src/` finds nothing.
  - There is no print, no logger, and `#![forbid(unsafe_code)]` is set.
  - There is no timestamp reserve, no `/DSS` and no level parameter.
  - `nacre-pdf` is not touched, so #46 and #48 stay open.
  - There is no fuzz target, which is correct since the crate parses nothing itself.

## References
- [x] I opened and checked each call against its source:
  - `nacre_cms::sign_detached` (`crates/nacre-cms/src/sign.rs:45`): it checks digest length, refuses an unknown algorithm, sorts the chain and calls `sign_digest` once.
  - `Update::sign`, `PreparedSignature::{signed_parts, embed}` (`crates/nacre-pdf/src/revision.rs:136,503,512`). `contents_len` is in bytes, written as hex ×2, and `embed` refuses an oversized CMS with `SignatureTooLarge`.
  - `Document::signature_fields`, `nacre_conformance::{Dss, pki_dir, reports_dir}`.
  - `der::DateTime` getters, and `DateTime::from_system_time`. That function is gated on `der/std`, which is enabled in the graph through pkcs8/rsa.
  - The corpus copies match their sources byte for byte (`cmp`).
- [x] Values:
  - `ECDSA_P256_MAX = 72` is the DER maximum: a 2-byte SEQUENCE header plus two INTEGERs of 2 + 33 bytes.
  - The RSA bound is the length of the SPKI bit string, which is always longer than the modulus, and it is unit-tested.
  - The `/M` text `D:YYYYMMDDHHmmSSZ` is valid ISO 32000 syntax.
  - A dry run with a longer placeholder can only add DER length octets, so its length stays an upper bound.

## Rules
- [x] The `AGENTS.md` conventions are respected:
  - edition 2024 and `rust-version = "1.97"`
  - workspace lints
  - the crate doc says "Experimental"
  - one `thiserror` enum with `kind()` (ADR-0012)
  - no clock read
  - test data under `tests/corpus/` with a `README.md`
  - the dev-only `nacre-conformance` is a path with no version
  - the conformance tests are `#[ignore = "conformance"]` and assert the exact level
- [x] No accepted ADR is contradicted (ADR-0001, ADR-0003, ADR-0004, ADR-0007, ADR-0012).

## Tests
- [x] Floor: `po-gate floor-guard s06-pades-bb main` exited 0, so nothing was lowered. It also printed an awk warning about multibyte locale.
- [x] The assertions pin down criteria 2–5 on real bytes:
  - the CMS is read back from `/Contents`, cut at its DER length, and checked against SHA-256 of the `/ByteRange` bytes
  - both prefixes are checked
  - the revision count is checked
  - the slack equality is checked
  - the signer call count is checked
- [x] None of the six empty shapes is present. `Counting` wraps the real `TestSigner` and does not mock the condition under test.
- [x] Size: 9 tests in all (2 unit, 5 service, 2 conformance), within `Test budget` 25.
- [x] Bite 1: in `reserve.rs`, I changed `contents_capacity` to return `dry.len() + 8` and ran `tests/sign.rs`. 1 test failed (`reserve_leaves_only_the_signature_slack`). I undid it and `git diff --exit-code` was clean.
- [x] Bite 2: I made `Sizing::sign_digest` also call `self.inner.sign_digest` and ran `tests/sign.rs`. 1 test failed (`the_signer_signs_once`). I undid it and `git diff --exit-code` was clean.
- [x] The story makes no existing test useless; it is a new crate.

## Neighbours
- [x] Nothing outside this crate calls `nacre-pades`, so it has no other callers. I read the code it calls (`nacre-cms`, `nacre-pdf`) and found no change needed there.

## Lenses
Lenses run: dependencies — new manifest `crates/nacre-pades/Cargo.toml` with a dependency list.
- [x] No dependency finding. Each dependency is named and given a reason in the plan's `## Reuse` and task 1, all are already in the workspace graph at the same versions, and there is no lockfile.

## Findings
- minor — crates/nacre-pades/src/sign.rs:41 — The document digest is always SHA-256, and so is the dry-run digest `[0; 32]` at `reserve.rs:68`. Neither reads `signer.algorithm().digest()`.
  - Today both algorithms are SHA-256, so this is correct.
  - A future algorithm on another digest would fail with `DigestLength`, not silently. But the hash choice is coded in two places that s08 and later levels will extend.
- minor — crates/nacre-pades/src/sign.rs:18 — The rustdoc points callers to `DateTime::from_system_time`, which der gates behind its `std` feature.
  - `nacre-pades` enables only `der/alloc`. The function is available only because pkcs8 and rsa turn `std` on through feature unification.
  - Enabling `std` on nacre-pades' own `der` dependency would make this hold by construction.

## Not verified
- I did not rerun the DSS verdicts for criteria 1 and 3 (`TOTAL_PASSED`, `PAdES-BASELINE-B`, after one signature and after two). The driver forbids starting the bench.
  - I relied on the QA transcripts committed under `docs/qa/s06-pades-bb/` (DSS 6.5.1, both formats `PAdES-BASELINE-B`). The two ignored tests in `tests/conformance.rs` still need a green CI `conformance.yml` run before the plan's "Done when" holds.
  - The record says `BenchSigner` was only compiled locally.
- Whether DSS accepts `ESSCertIDv2` without `issuerSerial` at B-B rests on the same QA and CI evidence. The QA transcripts show acceptance.
- From the QA report's `## Not seen`: criterion 5 was observed only with a 70-byte ECDSA value, never 71 or 72, and never with an RSA signer. The reason given is that the tmp quota prevented building a second signer.
  - That gap is left to `rsa_bound_covers_the_signature` and `reserve_leaves_only_the_signature_slack`.
  - To cover it, a person should sign a PDF with an RSA signer chained to a trusted anchor and have DSS judge it.
- From the QA report's `## Not seen`: criterion 5's invalid input (a signer with an unsupported algorithm) was not exercised, for the same reason. No test covers the `_` arm of `max_signature_len` either. `sign_detached` refuses such an algorithm anyway.
- From the QA report's `## Not seen`: behaviour in a real PDF reader (Acrobat, Okular) was not seen. To cover it, a person should open a signed output in one.
- The QA report noted that DSS answered HTTP 500 to a PDF with a damaged header. That belongs to the bench, not this diff, and I did not investigate it.
- The record notes that `cargo fmt` was applied but not recorded. I did not run a format check; CI and the commit hook cover it.
- Pending, and the lead's job rather than the implementer's: rewriting criterion 5 in `docs/stories.md:114` in its concrete form, and updating issue #9, as the plan's "Done when" asks.
- Both of the following are named in the research, out of this story's `Owns`, and filed as #46 and #48:
  - a non-signature field already named `SignatureN` would still collide
  - `nacre-pdf` does not check `/SubFilter`

Max severity: minor
Ship allowed: yes
