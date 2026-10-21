# Review: s01-workspace-contract

The review found no critical or major defect. The story can ship. There are three minor findings.

Reviewed tree: c1199d931af0a5ecbf66c609d64df11ce278b848
Story: s01-workspace-contract
Fix loop: 0
Scope: `git diff main...story/s01-workspace-contract`
Lenses run: Dependencies (triggered by `Cargo.toml` and `crates/nacre-core/Cargo.toml`, which add `thiserror`, `p256`, `x509-cert`, `sha2` and `der`). Security, Migration and Performance did not run: nothing in the diff triggers them.

## Scope check
- **Inside `Owns`:** every code path in the diff. That is `Cargo.toml`, `rust-toolchain.toml`, `.gitignore`, `.github/workflows/ci.yml` and `crates/nacre-core/**`, all listed in the `Owns` line of `docs/stories.md:17`.
- **Pipeline evidence:** `docs/research/`, `docs/plans/`, `docs/verif/` and `docs/qa/s01-workspace-contract/` are in scope by construction.
- **ADR:** `docs/decisions/0010-core-contract-speaks-der-and-one-error.md` is newly added (status `A`) and the plan names it, so it is in scope. Its status is `accepted`.
- **Other stories:** `git worktree list` shows no other story worktree running, so no other story's `Owns` can overlap.

## What I relied on
- **`po-gate`:** not on PATH. I ran it from `/home/lecrabe/.claude/polype/method/hooks/po-gate.sh`.
  - `verif-current`, `qa-current` and `floor-guard s01-workspace-contract main` all exited 0, silently.
  - I also checked by hand: outside `docs/`, the code of the record's `Tree:` and of both run trees (c089cba…, 3de2802…, 7828aa6…) equals HEAD.
- **Verification record:** `Verification mode: record`, and `docs/verif/s01-workspace-contract.md` is complete. Both checks exited 0 on code equal to HEAD: `cargo test --workspace` and `cargo clippy --workspace --all-targets --all-features -- -D warnings`. I did not rerun them.
  - Its "Not proven here" section: the CI workflow has only been parsed and its discovery step replayed locally; `cargo fmt --all --check` is not a `po-run` row.
- **QA:** the story's Surface is `endpoint`, so it goes to QA. The report's `Tree:` b81b719… equals HEAD outside `docs/`, its status is complete and it is committed.
- **E2E and build:** the project has no `E2E` command (`—`). The build is left to ship (`ship-if-route`); no routing or manifest change calls for it here.

## Bite proof
Each rule was disabled, only its own test file was run, then the file was restored and confirmed with `git diff --exit-code`.

| Rule disabled | Change | Tests run | Failed |
| --- | --- | --- | --- |
| Digest-length guard (`test_signer.rs`) | `if false && digest.len() != expected` | `contract_signer` | 1 of 2 (`wrong_digest_length_is_refused`) |
| A passed report has no sub-indication (`report.rs`) | `passed()` sets `sub_indication: Some(NoPoe)` | `report` | 1 of 2 (`passed_carries_no_sub_indication`) |
| Error source travels with the error (`error.rs`) | dropped `#[source]` on `Timestamp` | `contract_objects` | 1 of 1 |

Every disabled rule failed a test. The working tree was clean afterwards (`git diff --exit-code` and `git status --porcelain` both empty).

## Other checks
- **Tests:** 5 tests against a budget of 25, with no excess. `floor-guard` exit 0: no check was made easier to pass. None of the six kinds of test that prove nothing is present: the stubs in `contract_objects.rs` do not reproduce the rule under test.
- **Plan tasks 1 to 7:** all present. The only deviation is the first finding below.
- **Run interdicts:**
  - The grep for `std::fs|net`, `SystemTime`, `from_now`, `println`, `eprintln` and `unsafe` finds only the `forbid` line.
  - `cargo tree -p nacre-core -e normal --depth 1` shows `thiserror` alone.
  - `TestSigner` has no `Debug` or `Display`.
  - The root `Cargo.toml` holds only `[workspace]` and `[workspace.lints.clippy]`.
  - No `Cargo.lock`, `clippy.toml`, `rustfmt.toml` or `fuzz/` is committed.
  - No `cms`, `x509-tsp` or `ureq` dependency.
- **Values:** digest lengths 32, 48 and 64 are right for SHA-256, SHA-384 and SHA-512. The certificate validity is fixed by constants (2026-01-01 to 2036-01-01) and never read from the clock. The main-indication URNs follow the EN 319 102-1 pattern.
- **Neighbours:** none. The repository had no code before this story, so nothing else calls what it changed.

## Findings
- **minor** — `crates/nacre-core/Cargo.toml:15-17,20`: an optional normal dependency `sha2` (`default-features = false, features = ["oid"]`) is added to the `test-signer` feature. Plan task 2 lists `sha2` only as a dev-dependency and sets `test-signer = ["dep:p256", "dep:x509-cert"]`. The inline comment gives a reason (the certificate builder needs the SHA-256 OID), and default features still pull `thiserror` alone, so nothing leaks. But the plan does not name it, and the Dependencies lens counts that as a finding. Fix: name it in the plan or in the record.
- **minor** — `crates/nacre-core/src/test_signer.rs:33,81-83`, QA Finding 1 (verified, evidence `docs/qa/s01-workspace-contract/c4-test-signer-error.txt`). An invalid secret such as `[0u8; 32]` or `[0xFF; 32]` is refused, as it should be. But the error reads `the signer failed` with source `signature error`, which names neither the secret nor the key, and suggests a signing failure although nothing was signed. The reach is small because `TestSigner` exists for tests only.
- **minor** — Dependencies lens: the research (`docs/research/s01-workspace-contract.md`, "Verified interfaces") gives each new crate's version and MSRV. It does not record that their build scripts were read; `thiserror` 2, for one, ships a `build.rs`. All dependencies are new, so there is no changelog between versions to read. Fix: add one line to the research or record saying the build scripts were looked at.

## Not verified
- **Patelle untouched** (run interdict). My `git -C /home/lecrabe/dev/atoll/patelle status` was refused by po-bounds, because it runs outside the story worktree and outside the temp dir. I did not reach it another way. A person should run `git -C /home/lecrabe/dev/atoll/patelle status --porcelain` (expect empty) and `git -C /home/lecrabe/dev/atoll/patelle rev-parse --short story/s01-sign-decision` (expect `4ed5c64`).
- **Criterion 1 in CI** (QA Not seen): both jobs of `.github/workflows/ci.yml` going green on GitHub Actions. That is a remote service, and only the discovery step was replayed locally. The no-argument `rustup toolchain install` also depends on the runner's rustup being 1.28 or newer. A person should check that both jobs are green on the pull request.
- **Criterion 5, the fuzz loop** (QA Not seen): `cargo +nightly fuzz list` and `fuzz run -- -max_total_time=60`. No `crates/*/fuzz/` exists yet, and neither nightly nor `cargo-fuzz` is installed here. s03 exercises it first, and must also confirm that its `fuzz/Cargo.toml` declares its own `[workspace]`, which the frozen root manifest relies on.
- **Sub-indication list and the 16 `SignatureProfile` values against DSS 6.5.1.** I could not open the DSS source; I relied on the research's reading of `SubIndication.java` and `SignatureProfile.java`. The test compares against a list copied from DSS, not against DSS itself. A person should diff the list against `dss-enumerations` at tag `6.5.1`, or s18 confirms it against the judge.
- **Not checked by me at all:** the statement in the `Cargo.toml` comment that no `p256` feature enables the SHA-256 OID, and the formatting result. Proving the first would have meant editing a file, which goes beyond the single bite-proof exception. `cargo fmt --check` is not a `po-run` row; the QA transcript `c1-checks-pass.txt` shows it passing.

Max severity: minor
Ship allowed: yes

# Review — s01-workspace-contract

[Story](../stories.md) · [Plan](../plans/s01-workspace-contract.md) · [Verification](../verif/s01-workspace-contract.md)

Diff reviewed: `git diff main...story/s01-workspace-contract`, in a context that did not write it. Findings rated critical, major or minor.

Review status: complete
Fix loop: 1
Reviewed tree: c1199d931af0a5ecbf66c609d64df11ce278b848

The review found no critical or major defect, so the story can ship. There are three minor findings. The code is the same as at Fix loop 0: the tree was taken again before answering and has not moved.

## When blocked
- Failure cause: none, the review is complete
- Missing: none
- Required adaptation: none
- Next action: none

## Ownership
I listed the diff with `git diff --name-only main...story/s01-workspace-contract` and held each path against `Owns` (`docs/stories.md:17`).
- [x] **Every path inside `Owns`.** The code paths are `Cargo.toml`, `rust-toolchain.toml`, `.gitignore`, `.github/workflows/ci.yml` and `crates/nacre-core/**`, and all are inside `Owns`.
  - The story's own evidence is in scope by construction: `docs/research/`, `docs/plans/`, `docs/verif/` and `docs/qa/s01-workspace-contract/`.
  - `docs/decisions/0010-core-contract-speaks-der-and-one-error.md` is added (status `A`) and the plan names it, so it is in scope too. Its status is `accepted`.
- [x] **Outside `Owns`:** none.
- [x] **Inside another running story's `Owns`:** none. `git worktree list` shows only main and this worktree.
- [x] **No `Owns` line:** not the case.

## Evidence reused
- [x] **`po-gate verif-current s01-workspace-contract` exits 0, so the record is reused.**
  - `po-gate` is not on PATH, so I ran it as `/home/lecrabe/.claude/polype/method/hooks/po-gate.sh`.
  - With `Verification mode: record`, `docs/verif/s01-workspace-contract.md` is complete. `cargo test --workspace` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` both exited 0 on code equal to this tree outside `docs/`, so I did not rerun them.
  - Its "Not proven here" says two things. First, the CI workflow was only parsed and its discovery step replayed locally. Second, `cargo fmt --all --check` is not a `po-run` row.
- [x] **`po-gate qa-current s01-workspace-contract` exits 0.** The story's Surface is `endpoint`, so it goes to QA under `QA stage: surfaces`.
  - The report is complete and committed, and its `Tree:` (b81b719…) equals the code.
  - Its single **verified** finding is carried to Findings below.
- **Other commands:** the project has no `E2E` command (`—`). The build is left to ship (`Build stage: ship-if-route`).

## Plan
- [x] **Tasks 1 to 7 are all present.** The one gap is the `sha2` optional dependency (first finding below).
- [x] **Each run interdict checked:**
  - **Diff limited to the listed paths plus pipeline evidence:** holds. `README.md`, `AGENTS*.md`, `docs/architecture.md` and `docs/stories.md` are untouched.
  - **No `Cargo.lock`, `clippy.toml`, `rustfmt.toml` or `fuzz/` tracked:** holds (`git ls-files` shows none).
  - **Root `Cargo.toml`:** holds only `[workspace]` and `[workspace.lints.clippy]`.
  - **`default = []`:** holds. Default features pull `thiserror` alone, since `p256`, `x509-cert` and `sha2` are optional and only `test-signer` enables them.
  - **The grep for `std::(fs|net)`, `SystemTime`, `from_now`, `println`, `eprintln` and `unsafe`:** finds only the `forbid` line.
  - **No `cms`, `x509-tsp` or `ureq`:** holds.
  - **`TestSigner` has no `Debug` or `Display`:** holds. The QA transcript `c4-test-signer-debug-error.txt` confirms it.
  - **No per-enum-value or per-pair tests:** holds.
  - **Patelle untouched:** not verifiable from here (see Not verified).

## References
- [x] **Every import, call, API and configuration key opened and confirmed.**
  - `CertificateBuilder::new`, `Builder::build::<_, DerSignature>`, `cabf::Root::new`, `PrehashSigner<DerSignature>` and `SubjectPublicKeyInfoOwned::from_key` were confirmed by the research and by a clean clippy and test run on this tree.
  - I checked the `Cargo.toml:16` comment "no p256 feature enables the OID of SHA-256" against the `p256-0.14.0` manifest in the cargo registry. It holds: p256 declares `sha2` with `default-features = false` and no feature of p256 adds `sha2/oid`. That makes the optional `sha2` dependency necessary.
- [x] **No value that only looks right:**
  - Digest lengths 32, 48 and 64 are correct for SHA-256, SHA-384 and SHA-512.
  - The certificate validity (2026-01-01 to 2036-01-01) comes from constants, never from the clock.
  - The indication and sub-indication URNs follow `urn:etsi:019102:mainindication:*` and `urn:etsi:019102:subindication:*`.
  - The 25 sub-indications match the research's reading of DSS 6.5.1. The check against DSS itself is in Not verified.

## Rules
- [x] **`AGENTS.md` conventions respected:**
  - edition 2024 and `rust-version = "1.97"`, with MSRV at stable 1.99 minus two;
  - `forbid(unsafe_code)`;
  - the four clippy denials through workspace lints, with test files allowing them;
  - one `thiserror` enum;
  - no logging and no clock.
- [x] **No accepted ADR contradicted.** The code follows ADR-0010: DER bytes at the boundary, object-safe traits, one `Error` with boxed `#[source]`. It also respects ADR-0003 (workspace layout, no `[workspace.dependencies]`, `Cargo.lock` ignored), ADR-0004 (versions 0.14, 0.3 and 0.8) and ADR-0008.

## Tests
- [x] **Floor:** `po-gate floor-guard s01-workspace-contract main` exits 0, so nothing was lowered.
- [x] **Assertions and empty test shapes:** the assertions pin criteria 2, 3, 4 and 6. None of the six empty test shapes is present.
  - The stubs in `contract_objects.rs` do not reproduce the rule they test: the source-chain assertion depends on the real `Error`.
  - `signature_verifies_with_chain_key` decodes the real certificate and verifies with strict `Signature::from_der`.
- [x] **Test budget:** 5 tests against a budget of 25.
- [x] **Bite.** Each rule was disabled in turn, only its test files were run, then the file was restored and confirmed:
  - **Digest-length guard** (`test_signer.rs`, `if false && digest.len() != expected`): `--test contract_signer` gives 1 of 2 failed (`wrong_digest_length_is_refused`). Undone, `git diff --exit-code` clean.
  - **Error source transport** (`error.rs`, `#[source]` dropped on `Timestamp`): `--test contract_objects` gives 1 of 1 failed. Undone, `git diff --exit-code` clean.
  - **DER signature output** (`test_signer.rs`, returns raw `r||s` via `Signature::to_bytes`): `--test contract_signer --test contract_objects` gives 1 of 3 failed (`signature_verifies_with_chain_key`). Undone, `git diff --exit-code` clean.
  - `git status --porcelain` afterwards shows only the untracked `docs/reviews/s01-workspace-contract.md` that was already there.
- [x] **Tests made useless by the story:** none. The repository had no code before this story.

## Neighbours
- [x] **No other callers.** The repository had no code before this story (ADR-0002), so nothing else calls what it adds.

## Lenses
Lenses run:
- **Dependencies**, triggered by `crates/nacre-core/Cargo.toml`, which adds `thiserror`, `p256`, `x509-cert`, `sha2` and `der`.
- Security, Migration and Performance did not run: nothing in the diff triggers them.

- [x] Each lens finding is graded and listed under Findings.

## Findings
- minor — crates/nacre-core/Cargo.toml:16-17,21 — An optional normal dependency `sha2` (`default-features = false, features = ["oid"]`) was added and switched on by `test-signer`, which the plan does not name.
  Plan task 2 lists `sha2` only as a dev-dependency and sets `test-signer = ["dep:p256", "dep:x509-cert"]`. The dependency is needed: I confirmed in the p256 0.14.0 manifest that no p256 feature enables `sha2/oid`. Default features still pull `thiserror` alone. But the Dependencies lens counts a dependency the plan never names as a finding. Fix: name it in the plan, or in the record.
- minor — crates/nacre-core/src/test_signer.rs:33,81-83 — An invalid secret gives an error that does not say what was wrong (QA finding 1, verified, evidence `docs/qa/s01-workspace-contract/c4-test-signer-error.txt`).
  `[0u8; 32]` or `[0xFF; 32]` is correctly refused, but the error reads "the signer failed" with source "signature error". That names neither the secret nor the key, and suggests a signing failure although nothing was signed. The reach is small because `TestSigner` is test-only.
- minor — docs/research/s01-workspace-contract.md:45-48 — No record says the build scripts of the new dependencies were read.
  The research gives each new crate's version and MSRV, but nothing more. `thiserror` 2.0.21 ships a 195-line `build.rs`. I read it: it probes rustc through `RUSTC`/`RUSTC_WRAPPER` and writes into `OUT_DIR`, which is the usual feature probe. All dependencies are new, so there is no changelog between versions to read. Fix: add one line to the research or the record.

## Not verified
- **Patelle untouched** (run interdict). This needs a git command in `/home/lecrabe/dev/atoll/patelle`, outside the story worktree and the temp dir. po-bounds refused that command in the previous review, so I did not try it again or reach it another way. A person should run:
  - `git -C /home/lecrabe/dev/atoll/patelle status --porcelain` (expect empty);
  - `git -C /home/lecrabe/dev/atoll/patelle rev-parse --short story/s01-sign-decision` (expect `4ed5c64`).
- **Criterion 1 in CI** (QA Not seen): both jobs of `.github/workflows/ci.yml` going green on GitHub Actions. That is a remote service; only the discovery step was replayed locally. The no-argument `rustup toolchain install` also needs rustup 1.28 or newer on the runner. A person should check both jobs are green on the pull request.
- **Criterion 5, the fuzz loop** (QA Not seen): `cargo +nightly fuzz list` and `fuzz run <target> -- -max_total_time=60`. No `crates/*/fuzz/` exists yet, the run happens on GitHub Actions, and neither nightly nor `cargo-fuzz` is installed here.
  - s03 exercises this loop first.
  - s03 must also confirm that its `fuzz/Cargo.toml` declares its own `[workspace]`: the frozen root manifest (`members = ["crates/*"]`) relies on it.
- **Sub-indication list and the 16 `SignatureProfile` values against DSS 6.5.1 itself.** I relied on the research's reading of `SubIndication.java` and `SignatureProfile.java`; the test compares against a list copied from DSS, not against DSS. A person should diff the list against `dss-enumerations` at tag 6.5.1, or s18 confirms it against the judge.
- **Formatting:** `cargo fmt --all --check` is not a `po-run` row and I did not run it. The QA transcript `c1-checks-pass.txt` shows it passing, and the CI `check` job runs it on the pull request.

Max severity: minor
Ship allowed: yes
