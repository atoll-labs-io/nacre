# Review — s13-pkcs11-signer

[Story](../stories.md) · [Plan](../plans/s13-pkcs11-signer.md) · [Verification](../verif/s13-pkcs11-signer.md)

Diff reviewed: `git diff main...story/s13-pkcs11-signer`, in a context that did not write it. Findings rated critical, major or minor.

Review status: complete
Fix loop: 0
Reviewed tree: ae594f5e11116e1760bc3e152275dd2a70c222fe

## When blocked
- Failure cause: none
- Missing: none
- Required adaptation: none
- Next action: none

## Ownership
I listed the changed files with `git diff --name-only main...story/s13-pkcs11-signer`. Owns: `crates/nacre-pkcs11/`.
- [x] Every path inside `Owns`. The 12 files under `crates/nacre-pkcs11/` are covered. The story's own research, plan, verif and QA files are in scope because the pipeline makes them. `docs/decisions/0013-raw-c-sign-for-per-signature-pin.md` (status A) is in scope because the plan names `ADR-0013` (see the minor finding about that sentence).
- [x] Nothing outside `Owns`.
- [x] Nothing inside another running story's `Owns`. s07, s09 and s14 each own their own crate, with no overlap.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s13-pkcs11-signer` exited 0. With `Verification mode: record`, I reused the record: `cargo test --workspace` exited 0, and `cargo clippy --workspace --all-targets --all-features -- -D warnings` exited 0. I did not rerun either. I read its "Not proven here" section.
- [x] `po-gate qa-current s13-pkcs11-signer` exited 0 (Surface `endpoint`, `QA stage: surfaces`). QA's verified Finding 1 is carried to Findings below.

## Plan
- [x] Tasks 1–8 are all present, and there is no change outside them.
- [x] I checked the run interdicts one by one:
  - The diff touches only `crates/nacre-pkcs11/` and `docs/`.
  - `unsafe` appears only in `src/raw.rs`, plus the `deny` line in `lib.rs`. There is no `unsafe` or `set_var` in `tests/` or `examples/`.
  - `raw.rs` reads the fields `C_GetFunctionList` and `C_Sign` and calls no method of `cryptoki_sys::Pkcs11`.
  - There is no git dependency and no `[workspace.dependencies]`. None of `yubikey`, `secrecy`, `tempfile`, `rsa` or `log` is a direct dependency. `Cargo.lock` is not added.
  - No login is retried by the code itself (but see the major finding below on what a module may do).
  - There is no print or logger in `src/`. `Pin` derives nothing, and no error variant carries a path, label or PIN.
  - `ykcs11` does not appear in `tests/`.
  - Patelle is untouched, and there is no fuzz target.

## References
- [x] I checked the cryptoki 0.12.1 source in the registry:
  - `Session::handle` and `Session::login` exist. `login` passes `expose_secret().as_ptr()` with no copy, so no PIN copy outlives `AuthPin`.
  - `Session` is `Send` and `!Sync`, which makes `Pkcs11Signer` `!Sync`. No concurrent `C_Sign` can run on one session.
  - `Pkcs11` has no `Drop` that finalizes, so a second signer's context cannot finalize the first one.
  - `nacre_core::Signer` has no `Sync` bound.
- [x] Values I checked:
  - `P256_PARAMS` is the right DER of 1.2.840.10045.3.1.7.
  - `DIGEST_INFO_SHA256` matches RFC 8017 §9.2 note 1. The RSA test also proves it independently, through the token's own `Sha256RsaPkcs` verify.
  - The priority in `pin_state` follows the plan.

## The unsafe contract (ADR-0013), read closely
- `Module::load` loads the same path as the cryptoki context, so `dlopen` hands back the already-loaded instance, with no second initializer. `Pkcs11Signer::open` uses `config.module` for both, in the same call.
- A null or failing function list, and a missing `C_Sign`, both map to `ModuleUnavailable`.
- The function pointer has the same type as `CK_FUNCTION_LIST::C_Sign`; if it didn't, the code would not compile.
- Struct fields drop in declaration order, so `reauth` (the `Module`) drops after `session` and `context`. The mapped library outlives every use.
- The session handle comes from the `Session` the signer owns, which keeps its own `Pkcs11` clone alive.
- `pData` is cast to `*mut` but `C_Sign` only reads it, and it is never empty (32 or 51 bytes).
- The output buffer is sized from the module's own length answer, and `truncate` can never grow it.
- The length query with a null output keeps the operation active, as PKCS#11 specifies.

I found no unsoundness. As for any FFI, memory safety rests on the module honouring `*pulSignatureLen`.

## Rules
- [x] The `AGENTS.md` conventions are respected: `deny(unsafe_code)` plus an allow in `raw.rs` (the allowed relaxation for `nacre-pkcs11`), edition 2024, rust 1.97, thiserror, no clock read in judging code, `zeroize` for the PIN.
- [x] ADR-0005 and ADR-0013 are honoured in substance. There is one wording gap in ADR-0013 (minor finding).

## Tests
- [x] Floor: `po-gate floor-guard s13-pkcs11-signer main` exited 0, so nothing was lowered.
- [x] None of the six empty test shapes. The wrong-PIN test logs out the setup session first, so the PIN really is checked. The RSA test uses the token as an independent judge. The child-process harness asserts `1 passed`, which rules out a misspelt test name.
- [x] 9 automated tests, within the `Test budget` of 25.
- [x] Baseline: `cargo test -p nacre-pkcs11 --test softhsm -- --ignored` gave 5 passed (SoftHSM 2.7.0).
- [x] Bite 1: I skipped the `ContextSpecific` login in the always-authenticate path of `src/signer.rs`. 1 test failed (`always_authenticate_key_signs_twice`). Undone; `git diff --exit-code` was clean.
- [x] Bite 2: I replaced `info.user_pin_count_low()` with `false` in `login` (`src/signer.rs:203`). 1 test failed (`wrong_pin_reports_the_token_state_without_the_pin`). Undone; `git diff --exit-code` was clean.
- [x] No existing test was made useless; this is a new crate.

I also ran a throwaway probe test (since deleted, and its build artefacts removed; `git status` is clean). It is described in the second finding.

## Neighbours
- [x] The crate is new, with no existing callers. The root `Cargo.toml` (`members = ["crates/*"]`) picks it up unchanged.

## Lenses
Lenses run: dependencies — triggered by the new manifest `crates/nacre-pkcs11/Cargo.toml`, which adds `cryptoki`, `cryptoki-sys`, `zeroize`, `p256` and `thiserror`.
- [x] Each lens finding is graded and listed under Findings.

## Findings
- major — crates/nacre-pkcs11/src/signer.rs:187 — A wrong PIN still opens a signer when another signer of the process is logged in to the same token. This is QA Finding 1, status verified, reproduced in `docs/qa/s13-pkcs11-signer/c3-wrong-pin-second-signer.txt`.
  `CKR_USER_ALREADY_LOGGED_IN` is accepted for `UserType::User` without checking the PIN, so `open` succeeds and the signer signs. Criterion 3 ("un PIN faux rend une erreur … aucune signature") fails in that case. The rustdoc of `open` and the crate doc say so, which contains the defect but does not lift it. The criterion was not reworded to exclude this case.
  I grade it major rather than QA's minor: it breaks a stated acceptance criterion, and it is what makes the next finding reachable.
  Fix: refuse `UserAlreadyLoggedIn` (or track and refuse a second signer per module and token), or reword criterion 3 on purpose.
- major — crates/nacre-pkcs11/src/signer.rs:116-126 — After the token refuses the context-specific login, the signer keeps the same refused PIN and nothing stops it from being presented again on the next `sign_digest`.
  The crate doc promises "a refused PIN is never tried again". Today that holds only because SoftHSM leaves the `C_SignInit` operation active after a failed `C_Login`. My probe (two signers, the second opened with a wrong PIN on an always-authenticate key, then three `sign_digest` calls) showed:
  - the first call returns `WrongPin(CountLow)`;
  - the next calls fail at `C_SignInit` with `CKR_OPERATION_ACTIVE` and never reach `C_Login`.
  A module that ends the operation on a failed context login would get the refused PIN again at every signature, and burn the counter of a real PIV slot until it locks. Whether `libykcs11` behaves that way is not verified.
  Fix: after a `WrongPin` in the reauth path, clear or poison `reauth` (or the whole signer), so a refused PIN is structurally never sent twice.
- minor — docs/decisions/0013-raw-c-sign-for-per-signature-pin.md:24 — The ADR says "the rest of `nacre-pkcs11` keeps `#![forbid(unsafe_code)]` everywhere but `raw.rs`". The code has `#![deny(unsafe_code)]` crate-wide (`src/lib.rs:2`), which any module could override with `allow`; it has to, since `forbid` cannot be lifted in one module.
  The guarantee is enforced by review and the plan's grep interdict, not by the compiler as the ADR text implies. The ADR is accepted and its body cannot change, so the next ADR that touches it (or the one that replaces `raw.rs`) should state `deny` plus the single allow.
- minor — docs/plans/s13-pkcs11-signer.md:10 — The plan says "The reserved ADR-0013 is not used", yet the diff adds ADR-0013 as accepted and `lib.rs` and `raw.rs` cite it. The plan was not updated after the owner's decision, so the plan and the shipped evidence disagree.
- minor — docs/verif/s13-pkcs11-signer.md — Dependencies lens: neither the record nor the research says that the build scripts of the new dependencies were checked. I read `cryptoki-sys` 0.5.0's `build.rs`: it does nothing without the `generate-bindings` feature, which is not enabled. So there is no defect, only a gap in the record.

## Not verified
- **CI conformance job.** I did not see `conformance.yml` running the five SoftHSM tests on Ubuntu's SoftHSM 2.6.1, whose context-specific login support is unproven. A person should read the job log of the PR.
- **DSS verdict.** `softhsm_signature_is_pades_baseline_b` was not run by me: the driver said not to start the bench, and the record says it was never run. QA saw `PAdES-BASELINE-B` locally (`c2-dss-pades-b.txt`). Its CI run is not seen (QA `## Not seen`).
- **`FinalTry` and `Locked`.** These are never raised by SoftHSM. Only the unit mapping covers them (QA `## Not seen`); real hardware would show them.
- **PIN zeroization in memory.** It is not observable safely. I checked the types: `Zeroizing<String>`, and an `AuthPin` built per login and passed to `C_Login` without a copy (QA `## Not seen`).
- **Criterion 5, the manual YubiKey run** (PIV 9c, `libykcs11`). It is the person's run; `MANUAL.md` still says "not run", and no hardware was touched (QA `## Not seen`).
  - That run should also check how `libykcs11` handles a refused context-specific PIN: does the operation stay active? (second major finding). This must be tested with care: it costs PIN tries.
- **3.0 modules.** cryptoki loads modules through `C_GetInterface` when present, while `raw.rs` uses `C_GetFunctionList`. Both normally expose the same `C_Sign`, but this was not checked on a 3.0-only module.
- **Other platforms.** Only Linux `dlopen` was reasoned about; the loader's same-instance behaviour on Windows and macOS was not checked.
- **E2E and build.** E2E: the project has none (`E2E: —`). Production build: deferred to ship (`Build stage: ship-if-route`).

Max severity: major
Ship allowed: yes

# Review — s13-pkcs11-signer

Review status: blocked
Fix loop: 1
Reviewed tree: fcb0b500e2430d972712ceb4b9ea1b5e6a239611

## When blocked
- Failure cause: `po-gate qa-current s13-pkcs11-signer` exited 1 with "po-gate: the code of s13-pkcs11-signer changed after its QA walk; the report no longer matches HEAD — /po-qa s13-pkcs11-signer". `docs/qa/s13-pkcs11-signer/report.md` holds `Tree: 59805574f8e5c1ba9f108531cea98b0309370c4c`; fix run 1 (bc6436e) changed `crates/nacre-pkcs11/src/{error,lib,pin,signer}.rs` and `tests/{softhsm.rs,support/mod.rs}` after that walk.
- Missing: a QA report whose `Tree:` matches the committed code outside `docs/`.
- Required adaptation: QA walks the fixed code again; QA's case `c3-wrong-pin-second-signer` should now end with `Error::AlreadyLoggedIn`.
- Next action: `/po-qa s13-pkcs11-signer`, then `/po-review s13-pkcs11-signer`.

## Checked anyway on fix run 1
- `po-gate verif-current` exit 0; `po-gate floor-guard` exit 0; SoftHSM suite 7 passed locally.
- Both earlier majors resolved, each guard biting: `login` back to `Ok(())` fails `second_signer_of_a_logged_in_token_is_refused`; always putting the PIN back fails `refused_context_pin_is_never_sent_again`. Undone, `git diff --exit-code` clean.
- Earlier minors on the plan sentence and the record's build-script note are fixed.

## Findings
- minor — docs/decisions/0013-raw-c-sign-for-per-signature-pin.md:24 — The ADR says the rest of the crate "keeps `#![forbid(unsafe_code)]` everywhere but `raw.rs`"; the code has `#![deny(unsafe_code)]` crate-wide (`crates/nacre-pkcs11/src/lib.rs:2`), liftable by `allow`. The ADR is accepted; the next ADR touching it should say "`deny` plus a single allow".

## Not verified
- QA of the fixed code (the block); the CI conformance job on Ubuntu's SoftHSM 2.6.1; the DSS verdict in CI; `FinalTry`/`Locked`; PIN zeroization in memory; the person's YubiKey run (which should also show how `libykcs11` treats a refused context-specific login, at the cost of PIN tries); PKCS#11 3.0-only modules and non-Linux loaders.

Max severity: minor
Ship allowed: no

---

# Review — s13-pkcs11-signer

[Story](../stories.md) · [Plan](../plans/s13-pkcs11-signer.md) · [Verification](../verif/s13-pkcs11-signer.md)

Diff reviewed: `git diff main...story/s13-pkcs11-signer`, in a context that did not write it. Findings rated critical, major or minor.

Review status: complete
Fix loop: 1
Reviewed tree: 36e4a5564f3462834b3861ece3ad1ca092c7f0d9

## When blocked
- Failure cause: none
- Missing: none
- Required adaptation: none
- Next action: none

## Ownership
I listed the changed files with `git diff --name-status main...story/s13-pkcs11-signer`. Owns: `crates/nacre-pkcs11/`.
- [x] Every path is inside `Owns`. The 12 files under `crates/nacre-pkcs11/` are covered. The story's own research, plan, verif, review and `docs/qa/s13-pkcs11-signer/` files are pipeline evidence. `docs/decisions/0013-raw-c-sign-for-per-signature-pin.md` is added (status A) and the plan names it, so it is in scope too.
- [x] Nothing is outside `Owns`.
- [x] Nothing falls inside another running story's `Owns`. The running worktrees are s07 (`crates/nacre-tsp/`, `docs/security/attacks/tsp.md`), s09 (`crates/nacre-revocation/`, `docs/security/attacks/revocation.md`) and s15 (`crates/nacre-validate/`, `docs/security/attacks/pades.md`). None of them overlaps.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s13-pkcs11-signer` exited 0. Under `Verification mode: record`, I reused its passing runs of `cargo test --workspace` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` and did not run them again. I read its "Not proven here" section.
- [x] `po-gate qa-current s13-pkcs11-signer` exited 0. The second QA walk (commit 9aa983f, `Tree: fcb0b500…`) covers the code after fix run 1. It has no findings, so none is carried over. Its `## Not seen` items are listed under Not verified below.
- [x] The block in the previous review (QA out of date) is lifted.

## Plan
- [x] Tasks 1–8 and the fix-run paragraph are all implemented. Fix run 1 (bc6436e) adds:
  - `Error::AlreadyLoggedIn`, returned when `login` meets `UserAlreadyLoggedIn` for `UserType::User` (`src/signer.rs:207-209`);
  - `Error::PinRefused` and `Reauth { pin: Cell<Option<Pin>>, module }`: the PIN is taken out, and put back only when the result is not `WrongPin` (`src/signer.rs:128-145`);
  - the two tests the plan names, which brings the total to 11.
- [x] Run interdicts, checked again:
  - `unsafe` appears only in `src/raw.rs`, plus the `deny` line.
  - No `set_var` or `ykcs11` in `tests/`.
  - No print in `src/`.
  - The manifest has no git dependency, no `[workspace.dependencies]`, and none of the forbidden crates.
  - No login is retried.

## References
- [x] `Cell<Option<Pin>>`: `take` and `set` exist for non-`Copy` types. The signer was already `!Sync` because of `Session`, so `Cell` changes nothing there. `Pin` is moved, never cloned. A refused PIN is dropped, which zeroizes it through `Zeroizing`.
- [x] Every refusal code (`PinIncorrect`, `PinInvalid`, `PinLenRange`, `PinLocked`, `PinExpired`) maps to `WrongPin`, so each of them drops the reauth PIN. Other errors (for example `OperationActive` from `sign_init`) keep the PIN, which matches the documented contract: "drop it and open a new one".
- [x] The unsafe contract of `raw.rs` and ADR-0013 is unchanged since the previous review.

## Rules
- [x] The `AGENTS.md` conventions hold: edition 2024 and rust 1.97, `thiserror`, both new variants mapped in `kind()` and in the mapping test, no PIN, label or path in either message.

## Tests
- [x] Floor: `po-gate floor-guard s13-pkcs11-signer main` exited 0.
- [x] None of the six kinds of test that prove nothing. `change_pin` runs from a session that does not log in, so the signer's login state stays a real precondition.
- [x] 11 automated tests, within the `Test budget` of 25.
- [x] Baseline: `cargo test -p nacre-pkcs11 --test softhsm -- --ignored` gave 7 passed (SoftHSM 2.7.0).
- [x] Bite 1: I replaced the `!matches!(ready, Err(Error::WrongPin(_)))` guard (`src/signer.rs:142`) with `true`. 1 test failed: `refused_context_pin_is_never_sent_again`. Undone with `git checkout --`; `git diff --exit-code` was clean.
- [x] Bite 2: I made `UserAlreadyLoggedIn` return `Ok(())` again (`src/signer.rs:208`). 1 test failed: `second_signer_of_a_logged_in_token_is_refused`. Undone; `git diff --exit-code` was clean.

## Neighbours
- [x] This is a new crate with no callers in the repository. The root `Cargo.toml` is unchanged.

## Lenses
Lenses run: dependencies — set off by the new manifest `crates/nacre-pkcs11/Cargo.toml`, which adds `cryptoki`, `cryptoki-sys`, `zeroize`, `p256` and `thiserror`. The plan's `## Reuse` gives a reason for each. The record now says the `cryptoki-sys` build script was read.
- [x] The lens added no new finding.

## Findings
- minor — docs/decisions/0013-raw-c-sign-for-per-signature-pin.md:24 — The ADR says the rest of the crate "keeps `#![forbid(unsafe_code)]` everywhere but `raw.rs`". The code has `#![deny(unsafe_code)]` for the whole crate (`crates/nacre-pkcs11/src/lib.rs:2`), and any module can lift that with `allow`. So the guarantee rests on review and the plan's grep, not on the compiler. The ADR is accepted and its body cannot change, so the next ADR that touches it should say "`deny` plus a single allow".
- minor — docs/plans/s13-pkcs11-signer.md (## Done when) — The plan still says "the five SoftHSM tests", but the fix run brought the count to seven. The stale line contradicts the plan's own fix-run paragraph.
- minor — crates/nacre-pkcs11/tests/softhsm.rs (`refused_context_pin_is_never_sent_again`) — On SoftHSM, the test shows that the signer answers `PinRefused`. It cannot show that the PIN never reaches the token, because without the guard SoftHSM stops at `C_SignInit` (`OperationActive`). The test bites the guard, but the property it is named after is only argued, on a module that ends the operation. The test comment and the record say so honestly; no fix is needed beyond the person's hardware run.

## Not verified
- **CI conformance job.** I did not see `conformance.yml` run the seven SoftHSM tests on Ubuntu's SoftHSM 2.6.1, whose context-specific login support is unproven (QA `## Not seen`). A person should read the PR's job log.
- **DSS verdict in CI.** QA saw `PAdES-BASELINE-B` locally (`c2-dss-pades-b.txt`). I did not start the bench, and the record says the test was compiled but not run. The CI run is not seen (QA `## Not seen`).
- **`FinalTry` and `Locked` on a real token.** SoftHSM raises only "count low", so only the unit mapping covers these states (QA `## Not seen`).
- **Whether a refused context-specific PIN reaches the token again.** The surface shows only `PinRefused`, and SoftHSM exposes no try counter (QA `## Not seen`). The guard's code and bite 1 cover the signer's side.
- **PIN zeroization in memory.** It cannot be observed safely; I checked the types only (QA `## Not seen`).
- **Criterion 5, the manual YubiKey run** (PIV 9c, `libykcs11`). It belongs to the person, and `MANUAL.md` still reads "not run" (QA `## Not seen`). That run should also observe how `libykcs11` handles a refused context login, which costs PIN tries.
- **Criterion 4 of `docs/stories.md`.** The lead was to reword it per the plan. It is outside this diff, and I did not check it.
- **PKCS#11 3.0-only modules** (cryptoki may load through `C_GetInterface`, while `raw.rs` uses `C_GetFunctionList`), and loaders on Windows and macOS. Not checked.
- **E2E and build.** The project has no E2E command (`E2E: —`). The production build is left to ship (`Build stage: ship-if-route`; no routing in a library).

Max severity: minor
Ship allowed: yes
