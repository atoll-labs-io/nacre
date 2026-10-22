# Review — s38-error-kind

Story: s38-error-kind — Une catégorie d'erreur grossière à montrer aux tiers
Worktree: /home/lecrabe/dev/atoll/nacre/.worktrees/s38-error-kind
Scope: `git diff main...story/s38-error-kind`
Reviewed tree: cbc47573026b533f7b6f6d1b4f0294f5260b2aec
Fix loop: 0
Lenses run: Dependencies (`crates/nacre-pdf/Cargo.toml`: its dependency list gains `nacre-core`)

## Scope check
All 7 code paths in the diff are inside `Owns` (`crates/nacre-core/`, `crates/nacre-cms/src/error.rs`, `crates/nacre-pdf/src/error.rs`, `crates/nacre-pdf/Cargo.toml`). The other paths are this story's own pipeline evidence (research, plan, verif, qa). One other lane is running: s02-conformance-harness, which owns `conformance/`, `crates/nacre-conformance/` and `.github/workflows/conformance.yml`. It shares no path with this diff.

## What was relied on
- `po-gate verif-current s38-error-kind` exited 0 with `Verification mode: record`. The record proves `cargo test --workspace` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` on this code, so I did not rerun them. Its "Not proven here" section says build and conformance are left to ship and CI, and that the kind meanings are not compared with DSS verdicts.
- `po-gate qa-current s38-error-kind` exited 0. The QA report is complete, current and committed.
- `po-gate floor-guard s38-error-kind main` exited 0, so nothing was lowered.
- The project has no `E2E` command (`—`). The build is left to ship (`Build stage: ship-if-route`). The manifest change only adds an internal path dependency.

## Steps
- **References.** Every reference resolves:
  - `nacre_core::ErrorKind` is exported at `crates/nacre-core/src/lib.rs`.
  - `ObjectIdentifier` is imported in `crates/nacre-cms/src/error.rs:1` and `ObjectId` in `crates/nacre-pdf/src/error.rs:1`.
  - `der::ErrorKind::Failed` and `TestSigner::from_secret` exist.
  - The `nacre-pdf` dependency line has the same form as the one in `nacre-cms`.
- **Plan.** Tasks 1 to 4 are present. Task 5 is the record's runs.
  - There is no `_ =>` arm in any `kind()`.
  - The existing variants and `#[error]` texts are unchanged: the three `error.rs` files only gain lines.
  - `nacre-core` gains no dependency, and there is no `[workspace.dependencies]` and no ADR-0013.
  - The cms mapping matches the plan row by row. The pdf mapping matches it too: the 3 unsupported cases go to `Indeterminate` and everything else to `InvalidInput`.
  - The code agrees with ADR-0012 (a coarse kind, the detailed messages kept, a fixed `Display`).
- **Test tables.** The cms table has 21 rows for 20 variants; the extra row shows the delegation. The pdf table has 30 rows for 30 variants; I counted the enum myself.
- **Bite.** Each mutation was undone, and `git diff --exit-code` on the file confirmed it.
  1. `nacre-cms` `SignatureInvalid` → `InvalidInput`: 1 test failed (`every_variant_has_its_kind`).
  2. `nacre-core` `Timestamp | Revocation` → `Signer`: 2 tests failed (`core_kinds`, and the cms `every_variant_has_its_kind` through its delegation row). `kind_display_is_fixed` still passed, as it should.
  3. A leak planted in `TestSigner::from_secret` (`{secret:?}` added to the error): 1 test failed (`errors_never_show_the_secret`, on the byte list).
- **Values.** The five `Display` texts are fixed literals with no field. The `[0xFF; 32]` scalar is above the P-256 order, and both the test and the QA observed that it is refused.
- **Neighbours.** No crate other than cms and pdf depends on `nacre-core` in this tree, and there is no facade crate yet. The s02 crate `nacre-conformance` is only affected by an addition, as the research notes.

## Findings
- **minor** — `crates/nacre-core/src/test_signer.rs` (behaviour exposed by `crates/nacre-core/src/error.rs` `kind()`): when the caller gives `TestSigner::from_secret` an out-of-range secret, the error reads as `ErrorKind::Signer` ("signer failure"), although `InvalidInput`'s rustdoc describes exactly this case. This is QA finding 1, verified (`docs/qa/s38-error-kind/c4-no-secret-error.txt`). It is test-only code, but it shows how the convention reads to later families: the kind follows the wrapping variant, not the caller's situation. The plan's pivot about `SignerCertificateNotFound` and `Certificate` at signing time is the same issue. Fix: decide in a later story whether signer-side input refusals get their own variant or mapping.
- **minor** — `crates/nacre-core/tests/contract_signer.rs` (`assert_no_secret`): the "raw bytes" check builds its needle with `String::from_utf8_lossy(&[byte; 4])`. For `0xFF` that gives four U+FFFD replacement characters, so the raw-bytes check of the `[0xFF; 32]` case looks for something unrelated to the secret. The hex and byte-list checks still cover that case (bite 3 shows it), and for `0x5A` the raw check ("ZZZZ") is meaningful. Fix: drop the raw check for non-UTF-8 bytes or say why it is there.
- **minor** — `docs/plans/s38-error-kind.md` (tasks 4 and Test strategy): the plan gives 28 `nacre-pdf` variants and 28 table rows. The enum and the test both have 30, which the QA also noticed. The code is right and the plan's count is stale. Fix: correct the count if the plan is touched again.

## Not verified
- The kind meanings (the pivot) were not compared with the DSS verdicts recorded by s02, for example whether signed-attribute format defects should be `InvalidSignature` rather than `InvalidInput`. The record says the same. A person should compare them with the s02 DSS reports once s02 has shipped.
- The convention "every `Error` exposes `kind()`" is not in the Conventions of `AGENTS.local.md`, as the research trap says. That file is outside `Owns`, so this is not a finding against the diff. The lead should add the convention through the pipeline so that stories s06 to s37 inherit it.
- From the QA report's `## Not seen`:
  - Later families applying the convention: outside this diff, and nothing to run yet.
  - A real signer's PIN in error messages: left to s13, and there is no PKCS#11 signer in this tree.
  - A real timestamp authority or revocation source failing: these sit behind the `http` feature as outside services. The QA built such errors from its own sources only.
- The production build and the conformance workflow were not run (deferred to ship and CI).

Review status: complete

Max severity: minor
Ship allowed: yes
