# Review — s15-validate-revisions

Fix loop: 0
Reviewed tree: 3467896570fa08280fa15ca86abef1750d3192c9
Review status: complete
Lenses run: none. No Security, Migration, Dependencies or Performance trigger appeared in the diff's paths: no manifest or lockfile changed, and nothing touches auth, routes or a server.

## Scope
Every path in `git diff --name-only main...story/s15-validate-revisions` falls under `Owns` (`crates/nacre-validate/`, `crates/nacre-pdf/`, `docs/security/attacks/pades.md`) or is this story's own evidence (research, plan, verif, qa). Two other lanes are open, s07 (`crates/nacre-tsp/`, `docs/security/attacks/tsp.md`) and s09 (`crates/nacre-revocation/`, `docs/security/attacks/revocation.md`). Neither is merged into `main` and neither overlaps this diff.

## What I relied on
- `po-gate verif-current s15-validate-revisions`: exit 0. Under `Verification mode: record`, the record's `cargo test --workspace` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` (both exit 0) cover this code, so I did not rerun them.
- `po-gate qa-current s15-validate-revisions`: exit 0. The story goes to QA (`Surface: endpoint`, `QA stage: surfaces`). The QA report's one verified finding is carried over below.
- `po-gate floor-guard s15-validate-revisions main`: exit 0, nothing lowered. It printed locale and null-byte warnings while reading the binary PDFs.
- Test count: 17 new tests, within `Test budget: 25`.
- The project has no `E2E` command (`—`). The build is left to ship (`Build stage: ship-if-route`; no route or manifest changed).

## Bite proofs
Each change was undone with `git checkout --` and confirmed with `git diff --exit-code`. The worktree is clean.
1. SSA guard turned off (`if false && certified && visible(..)`, `revisions.rs:259`): 1 test fails (`ssa_visible_signature_is_rejected`).
2. FieldMDP lock check turned off (`revisions.rs:329`): 1 test fails (`locked_field_fill_is_not_allowed`).
3. Orphan-referrer check turned off (`revisions.rs:476-478`, the loop that removes new objects referenced by objects no rule accepted): 0 tests fail across `attacks` and `validate`.
4. Inert/live split flipped, so that anything reachable through `/DSS` counts as inert (`live.retain(|id| !dss.contains(id))` in place of `revisions.rs:119`): 0 tests fail.

## Findings
- **major** — `crates/nacre-pdf/src/document.rs` `Document::doc_mdp_level`, called once per revision state by `crates/nacre-validate/src/revisions.rs:101`. The function goes through `Document::follow` (`document.rs:239-247`), and each `follow` builds a new `Resolver` with a full `max_total_decoded` budget and an empty object-stream cache. Inside the `/Reference` loop, every entry costs one fresh `follow`, and the loop goes on past every entry whose method is not DocMDP. So a hostile file can list the same reference many times, pointing to an object inside an object stream that inflates to up to 32 MB, and that stream is decoded again for each entry, in each of up to 65 states. No valid CMS is needed: `qualify` runs once `signed_bytes` passes. This is exactly the cost trap research fact 1 named, and this story moves it from the signing path into `validate`, which reads hostile input. Potential impact: CPU time grows with the number of `/Reference` entries, from a small input. I confirmed this by reading the code only; no hostile file was built or timed (see Not verified). Fix: read DocMDP through one shared `Resolver` (or from the state's `reachable()` map) and cap the `/Reference` entries.
- **major** — `crates/nacre-validate/src/revisions.rs:465-478`. The rule that a new object must have every referrer accepted (plan task 5) is not tested: removing it fails no test (bite 3). Without it, a fill under DocMDP 2/3 whose `/AP` points to an object the signed page already referenced while it was free would be accepted. That is a shadow late-definition attack through a form fill. Fix: add a corpus case and a rejecting test.
- **major** — `crates/nacre-validate/src/revisions.rs:105-119`. The "too loose" case of the plan's own pivot (an object reachable both through `/DSS` and from a page) has no test: flipping the split fails nothing (bite 4). The current code is right when read, but nothing guards it. The plan asked for this exact bite, and QA lists the case under Not seen. Fix: add a corpus file where a page references a DSS stream that a later revision changes, plus a rejecting test.
- **major** — `crates/nacre-validate/src/validate.rs:66-84` together with `revisions.rs:258-261`. This is QA finding 1, verified. In `ssa-visible-signature.pdf`, the attacker's own signature `Sneaky` comes back `INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND` with `defect: None`, exactly like a sound signature. The certification signature does fail as the story asks. But the crate's own rule says a visible new signature under DocMDP is refused, and nothing on the signature that broke that rule says so. An application that shows each signature on its own shows the sneaky one with no warning. Once s16 judges chains, it could read as valid. Fix: give the signature added in a refused revision a defect of its own, then check against DSS in s18/s19.
- **minor** — `crates/nacre-validate/src/revisions.rs:107-119` and `:483-493`. `INERT_KEYS` and the Locked-flag tolerance (`SIGN_KEYS` includes `/F`) are pyHanko-specific widenings. They are commented, but no test exercises them besides the pyHanko fixtures. Style only, noted for s19's foreign corpus.

## Not verified
- **The CPU cost of the first finding.** I did not build or time a hostile file. Someone should forge one (a `/Reference` array repeating one reference into a deflate-bomb object stream, after a revision that follows a signature), time `validate` on it, and add a `hostile.rs` case. The cargo-fuzz target `crates/nacre-validate/fuzz/` was not run here either; the record says the CI `fuzz` job runs it.
- **DSS parity** of the verdicts and of the `TOTAL_FAILED / FORMAT_FAILURE` mapping for a refused revision. No bench ran (record, "Not proven here"); s18/s19 compare.
- **Criterion 4 on Nacre's own B-LTA output.** s12 has not shipped, so only pyHanko's file was checked (QA Not seen). s12 has to rerun `lta_dss_and_timestamp_are_allowed` on its own output.
- **The `Unreadable` verdict**, never reached by QA: no file was found that parses whole while one of its earlier states does not (QA Not seen).
- **Files from signers other than pyHanko** (Acrobat and others): none in the corpus (QA Not seen). s19's foreign corpus covers this.
- **The "too loose" DSS/page case**: no corpus file holds it (QA Not seen; see the third finding).
- **A visible new signature or document-timestamp widget on an uncertified document** is accepted by design (the plan refuses it only under DocMDP), and a document timestamp's own integrity is never judged (s14 leaves timestamps out of the result). So an appearance overlay added that way is reported as an allowed revision. Someone should decide whether that residual risk needs a story.
- **Forge determinism**: the forge was not rerun twice and compared; I relied on the record's statement.

Max severity: major
Ship allowed: yes

---

# Review — s15-validate-revisions

Fix loop: 1
Reviewed tree: 25db6f7cfdb7e09eef2685f374103ce1faae1943
Review status: complete
Lenses run: none. No path in the diff names auth, routes, a server, a migration or a lockfile, and no `Cargo.toml` changed (the only "lock" match is the corpus file `fieldmdp-locked-fill.pdf`). No added or bumped dependency appears in the diff.

## Scope
Every path in `git diff --name-only main...story/s15-validate-revisions` falls under `Owns` (`crates/nacre-validate/`, `crates/nacre-pdf/`, `docs/security/attacks/pades.md`) or is this story's own evidence (research, plan, verif, qa). The other open lanes are s08 (`crates/nacre-pades/`) and s10 (`crates/nacre-revocation/`, `docs/security/attacks/revocation.md`). Both sit at `main` with no commits, and neither overlaps this diff. `story/s15-validate-revisions` is not an ancestor of `main` (exit 1).

## What I relied on
- `po-gate verif-current s15-validate-revisions`: exit 0. Under `Verification mode: record`, the record's runs on this code of `cargo test --workspace` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` both exited 0, so I did not rerun them.
- `po-gate qa-current s15-validate-revisions`: exit 0. The story goes to QA (`Surface: endpoint`, `QA stage: surfaces`). The QA walk was redone on the fix tree, and its one verified finding is carried over below.
- `po-gate floor-guard s15-validate-revisions main`: exit 0, so no check was weakened. Its only other output was null-byte warnings from reading the binary PDFs.
- Test count: the plan's 17 plus 3 from the fix run, 20 in all, within `Test budget: 25`.
- The project has no `E2E` command (`—`). The build is left to ship (`Build stage: ship-if-route`; no route or manifest changed).
- The new corpus files' SHA-256 values match their `tests/corpus/README.md` rows. I checked `shadow-dss-page.pdf`, `shadow-fill-late-definition.pdf` and `ssa-visible-signature.pdf`.

## Previous review's findings
- **DocMDP cost:** fixed. `Document::doc_mdp_level` (`crates/nacre-pdf/src/document.rs:161-222`) now reads through one shared `Resolver` and refuses more than 32 `/Reference` entries (`limits.rs:32`). `doc_mdp_references_over_the_cap_are_refused` covers the cap.
- **Orphan-referrer rule untested:** fixed. Bite 1 below now fails a test.
- **DSS/page split untested:** fixed. Bite 2 below now fails a test.
- **Sneaky signature reported as sound:** fixed with `Defect::AddedByRevisionNotAllowed`. Bite 3 below fails a test. The fix reaches further than the SSA case, though (first finding).

## Bite proofs
After each change I ran only `cargo test -p nacre-validate --no-fail-fast --test attacks --test validate`, restored the file with `git checkout --` and confirmed it with `git diff --exit-code`. The worktree is clean; the only untracked file is the previous review.
1. Orphan-referrer removal turned off (`revisions.rs:477`, `self.accepted.remove(&id)` replaced by `let _ = id`): 1 test fails (`shadow_fill_late_definition_is_rejected`).
2. Inert/live split flipped (`revisions.rs:119`, `live.retain(|id| !dss.contains(id))`): 1 test fails (`shadow_dss_page_is_rejected`).
3. Added-by defect turned off (`validate.rs:80`, filter forced to false): 1 test fails (`ssa_visible_signature_is_rejected`).

## Findings
- **major** — `crates/nacre-validate/src/validate.rs:76-88` (fix commit `6762208`). `AddedByRevisionNotAllowed` fires whenever the revision that added a signature is refused for an earlier signature, for any reason, not only for the SSA. Take an uncertified document signed by Alice, then filled and signed by Bob in one incremental update (the usual Acrobat or pyHanko save). Under the plan, a fill without DocMDP is refused (task 5), so Alice's signature fails, as intended. Now Bob's signature also ends `TOTAL_FAILED / FORMAT_FAILURE`, although nothing changed after the bytes he signed: an honest later signature is reported broken. EN 319 102-1 and DSS judge each signature on its own signed data and later revisions, so this is a verdict divergence that the plan's "Open questions" divergences do not list, and that no ADR records. It fails closed, so nothing is silently accepted. I found this by reading only; no such file is in the corpus. Fix: limit the added-by defect to the case it was meant for: a new signature widget refused by the SSA rule, or a signature under DocMDP 1. Add a corpus case where a legitimate second signer sits in a revision refused for another reason, or else record the stricter reading as a deliberate divergence in `docs/security/attacks/pades.md` and have a person decide.
- **minor** — `crates/nacre-validate/src/revisions.rs:53-63` (QA finding 1, verified, graded minor by QA and here). A revision made `Unreadable` by the new 32-reference DocMDP cap reports `changed=[]`. The revision after it also becomes `Unreadable`, because `previous` is `None`. The user gets no object to look at, which falls short of criterion 1's "avec les objets qu'elle change". The attack is still refused (`RevisionNotAllowed`). Evidence: `/home/lecrabe/dev/atoll/nacre/.worktrees/s15-validate-revisions/docs/qa/s15-validate-revisions/c1-later-revisions-qualified-error.txt`.
- **minor** — `crates/nacre-validate/src/revisions.rs:20-24` and `:483-493` (carried over from loop 0). `INERT_KEYS` (`/Metadata`) and the Locked-flag tolerance in `SIGN_KEYS` are pyHanko-specific widenings that only the pyHanko fixtures exercise. Note it for s19's foreign corpus.

## Not verified
- **The first finding was not run.** I did not forge an uncertified file filled and signed in one revision after a first signature. To cover it, a person should add that case to `forge_pades_attacks.rs` and look at Bob's `defect`.
- **The CPU bound of the shared-resolver DocMDP reading was not timed** (the record says so too). The cap is tested; the claim that each object stream is decoded only once was established by reading only. To cover it, time `validate` on a `/Reference` array of 32 entries pointing into a deflate-bomb object stream.
- **The fuzz target was not run.** I did not run `crates/nacre-validate/fuzz/`; the record says CI's `fuzz` job runs it.
- **No DSS parity check.** Nobody compared the verdicts with DSS, including the `TOTAL_FAILED / FORMAT_FAILURE` mapping for `RevisionNotAllowed` and `AddedByRevisionNotAllowed`. No bench ran; s18/s19 compare.
- **Criterion 4 on Nacre's own B-LTA output** (QA Not seen): s12 has not shipped, so only pyHanko's LTA file was checked. s12 has to rerun `lta_dss_and_timestamp_are_allowed` on its own output.
- **Files from signers other than pyHanko**, Acrobat and others (QA Not seen): none is in the corpus. s19's foreign corpus covers this.
- **An `Unreadable` revision caused by a state that fails to parse or walk** (QA Not seen): every broken input was refused whole by `Document::parse`. The only `Unreadable` QA reached comes from the DocMDP cap.
- **Signatures added on uncertified documents are not judged.** A visible new signature or document-timestamp widget on an uncertified document is accepted by design, and a document timestamp's own integrity is never judged. An appearance overlay added that way reads as an allowed revision. A person should decide whether that needs a story.
- **Forge determinism:** I did not rerun the forge; I relied on the record's statement that two runs gave identical hashes.

Max severity: major
Ship allowed: yes

---

# Review — s15-validate-revisions

Fix loop: 2
Reviewed tree: 5fd394cf54776a773fe3a67c08b5bcec5d497ee1
Review status: complete
Lenses run: none. No path in the diff names auth, routes, a server, a migration or a lockfile. No `Cargo.toml` changed, and the diff adds, removes or bumps no dependency.

## Scope
Every path in `git diff --name-only main...story/s15-validate-revisions` is either:
- under `Owns` (`crates/nacre-validate/`, `crates/nacre-pdf/`, `docs/security/attacks/pades.md`), or
- this story's own evidence (research, plan, verif, qa).

The only other open lane is s10 (`.worktrees/s10-revocation-ocsp`, owning `crates/nacre-revocation/` and `docs/security/attacks/revocation.md`). It does not overlap this diff. Since this branch split off, `main` has gained s07, s08, s09 and s13; none of them touches `nacre-pdf`, `nacre-validate` or `pades.md`. `story/s15-validate-revisions` is not an ancestor of `main` (exit 1). The untracked `docs/reviews/s15-validate-revisions.md` holds the earlier reviews; it is expected during a fix run.

## What I relied on
- **Verification record:** `po-gate verif-current s15-validate-revisions` exited 0. Under `Verification mode: record`, the record's runs on this code both exited 0:
  - `cargo test --workspace`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`

  I did not rerun them. I read its "Not proven here" section.
- **QA:** `po-gate qa-current s15-validate-revisions` exited 0. The story goes to QA (`Surface: endpoint`, `QA stage: surfaces`). The walk was redone on fix commit `1ce518b`. Its report has no findings on this tree, and the previous walk's `changed=[]` finding no longer reproduces.
- **Floor guard:** `po-gate floor-guard s15-validate-revisions main` exited 0, so no check was weakened. Its only other output was null-byte warnings from the binary PDFs.
- **Test count:** 23 tests added, 0 removed. That is within `Test budget: 25` (the plan's 17, plus 3 per fix run).
- **New corpus files:** the SHA-256 of the three files the fix run added match their `tests/corpus/README.md` rows:
  - `fill-and-second-signature.pdf`
  - `certified-p1-second-signature.pdf`
  - `docmdp-reference-cap.pdf`
- **Not run here:** the project has no `E2E` command (`—`). The build is left to ship (`Build stage: ship-if-route`; no route or manifest changed).

## Previous review's findings
- **The added-by defect reached honest second signers (major):** fixed. `AddedByRevisionNotAllowed` now needs the signature's own `/V` to be in `Qualified::refused_signatures`, which only the SSA rule and the DocMDP 1 rule fill (`revisions.rs:290-296`, `:340-343`). `second_signer_beside_a_refused_fill_is_judged_alone` covers the honest second signer and `signature_added_under_p1_is_refused_with_its_revision` covers the refused one (bite 1). Narrowing the rule reopened a gap for one shape of SSA (first finding).
- **Unreadable revision listing no objects (minor):** fixed. `revision_over_the_docmdp_cap_lists_its_objects` asserts `changed = [catalog, hostile]`, and bite 3 confirms the test guards it.
- **pyHanko-specific widenings (minor):** still open (third finding).

## Bite proofs
After each change I ran only `cargo test -p nacre-validate --no-fail-fast --test attacks --test validate` (37 tests, all green before any change). I restored the file with `git checkout --` and confirmed it with `git diff --exit-code`. The worktree is clean.
1. **Refused-signature filter turned off** (`validate.rs:83`, `.filter(|q| false && …)`): 2 tests fail, `ssa_visible_signature_is_rejected` and `signature_added_under_p1_is_refused_with_its_revision`.
2. **Unreadable permission read as "not certified" instead of `/P 1`** (`revisions.rs:118`, `(None, false)` in place of `(Some(1), false)`): **0 tests fail.**
3. **Unreadable branch turned off** (`revisions.rs:193`, `if false && …`): 1 test fails, `revision_over_the_docmdp_cap_lists_its_objects`.

## Probe (throwaway clone `/tmp/tmp.clZKItHXFy/nacre`, same tree)
I copied the forge into an example `probe.rs` and ran it on a document certified at DocMDP `/P 2`:

| Case | Certification signature | Sneaky signature |
| --- | --- | --- |
| Corpus SSA (merged widget, one revision) | `TOTAL_FAILED`, `RevisionNotAllowed` | `TOTAL_FAILED`, `AddedByRevisionNotAllowed` |
| Same SSA, field and visible widget as separate objects (`/FT /Sig /Kids [w]`, widget with `/Parent`) | `TOTAL_FAILED`, `RevisionNotAllowed` | `Indeterminate`, `defect=None` |
| Two steps: one revision adds an empty visible signature field, the next signs it | `TOTAL_FAILED` (first revision `NotAllowed`, second `Allowed([Signature])`) | `Indeterminate`, `defect=None` |

## Findings
- **major** — `crates/nacre-validate/src/revisions.rs:283-299` together with `crates/nacre-validate/src/validate.rs:80-84` (fix commit `1ce518b`). An attacker's visible signature on a certified document again carries no defect when it is added in one of two shapes the code does not record as refused:
  - **Non-merged field.** The field and its visible widget are separate objects. `signatures()` only looks at merged widgets (`/FT /Sig` together with `/Subtype /Widget`), so nothing lands in `refused_signatures`. Under fix 1 the broad added-by rule caught this shape; fix 2's narrowing lost it.
  - **Two steps.** One revision adds an empty visible signature field, and the next revision signs it. The visible check only covers new widgets, and the second revision is `Allowed([Signature])`. No fix run ever covered this shape.

  In both shapes the certification signature still fails, so criterion 3 holds and nothing reaches `TOTAL_PASSED`. But the sneaky signature reads exactly like a sound one (`Indeterminate`, no defect). That is the defect the loop-0 review graded major, now reached through these two shapes (probe above). Once s16 judges chains, it could read as valid.

  Fix:
  - Record a signature as refused when the widget it adds, merged or not, is visible under DocMDP.
  - Apply the SSA visible-widget check to an empty signature field added after certification when it is later signed, or else record that reading as a deliberate divergence in `docs/security/attacks/pades.md`.
  - Add one corpus case and one rejecting test for each shape.
- **minor** — `crates/nacre-validate/src/revisions.rs:115-119`. The rule that an unreadable DocMDP permission counts as `/P 1` for the revisions after it is stated in `pades.md` and in the record, but no test guards it (bite 2: 0 tests fail). The only corpus file that reaches it, `docmdp-reference-cap.pdf`, follows the capped revision with an empty revision, which is `Allowed([])` under either reading. QA checked it by hand only. The impact is limited: the signature that the unreadable revision follows already fails. Without the rule, though, a signature added after that revision would read as sound instead of `AddedByRevisionNotAllowed`. Fix: append a fill or an approval signature after the capped revision in the forged case, and assert that it is refused.
- **minor** — `crates/nacre-validate/src/revisions.rs:20-24` and `:531-541` (carried over from loops 0 and 1). `INERT_KEYS` (`/Metadata`) and the Locked-flag tolerance in `SIGN_KEYS` widen the rules for pyHanko, and only the pyHanko fixtures exercise them. To be checked with s19's foreign corpus.

## Not verified
- **The fix-1 behaviour on the non-merged shape** comes from reading the code of `6762208` only, not from a run. The probe ran on the current tree only.
- **DSS parity, never checked.** Nobody compared the verdicts with DSS: the second-signer reading that `pades.md` attributes to EN 319 102-1, the verdicts on the two SSA shapes above, and the `TOTAL_FAILED / FORMAT_FAILURE` mapping for `RevisionNotAllowed` and `AddedByRevisionNotAllowed`. No bench ran (the record's "Not proven here" says so too). s18 and s19 have to compare.
- **The fuzz target was not run.** I did not run `crates/nacre-validate/fuzz/`; the record says CI's `fuzz` job runs it.
- **The CPU bound of the shared-resolver DocMDP reading was not timed.** The 32-entry cap is tested; the claim that each object stream is decoded once was established by reading only. A person should time `validate` on 32 `/Reference` entries pointing into a deflate-bomb object stream.
- **Criterion 4 on Nacre's own B-LTA output** (QA Not seen). s12 has not shipped, so only pyHanko's LTA file was checked. s12 has to rerun `lta_dss_and_timestamp_are_allowed` on its own output.
- **Files from signers other than pyHanko**, Acrobat and others (QA Not seen). None is in the corpus; s19's foreign corpus covers this.
- **An `Unreadable` revision caused by a state that fails to parse or walk** (QA Not seen). Every broken input tried was refused whole by `Document::parse`; the only `Unreadable` reached comes from the DocMDP cap.
- **Signatures on uncertified documents.** A visible new signature or document-timestamp widget on an uncertified document is accepted by design, and a document timestamp's own integrity is never judged. An appearance overlay added that way reads as an allowed revision. A person should decide whether that needs a story.
- **Forge determinism.** I did not rerun the forge; I relied on the record's statement that two runs gave identical hashes.

Max severity: major
Ship allowed: yes

---

# Review — s15-validate-revisions

Fix loop: 3
Reviewed tree: c4f35c82debd1576483bc7dc05a68b0c2e04a262
Review status: complete
Lenses run: none. No path in the diff names auth, routes, a server, a migration or a lockfile. No `Cargo.toml` changed, and the diff adds, removes or bumps no dependency.

## Scope
Every path in `git diff --name-only main...story/s15-validate-revisions` is one of two kinds:
- under `Owns` (`crates/nacre-validate/`, `crates/nacre-pdf/`, `docs/security/attacks/pades.md`);
- this story's own evidence (research, plan, verif, qa).

The only other open lane is s39 (`.worktrees/s39-error-kind-from-sources`). It owns `crates/nacre-core/`, parts of `nacre-tsp`, `nacre-revocation`, `nacre-cms/src/error.rs` and `nacre-pades`, so it does not overlap this diff.

Since the merge base `eb3852b`, `main` has gained s07 through s13. None of them touches `nacre-pdf`, `nacre-validate` or `pades.md`.

`merge-base --is-ancestor story/s15-validate-revisions main` exits 1, so the branch is not merged. The untracked `docs/reviews/s15-validate-revisions.md` holds the earlier reviews; it is expected during a fix run.

## What I relied on
- **Verification record:** `po-gate verif-current s15-validate-revisions` exited 0. Under `Verification mode: record`, the last runs of `cargo test --workspace` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` on this code both exited 0, so I did not rerun them. I read the record's "Not proven here" section.
- **QA:** `po-gate qa-current s15-validate-revisions` exited 0. The story goes to QA (`Surface: endpoint`, `QA stage: surfaces`). The walk was redone on fix commit `4d08296` and reports no findings on this tree.
- **Floor guard:** `po-gate floor-guard s15-validate-revisions main` exited 0, so no check was weakened. It also printed locale and null-byte warnings from the binary PDFs.
- **Test count:** the diff adds 25 `#[test]` and removes none. That is exactly `Test budget: 25`; one more test would need a sentence in the plan.
- **Corpus hashes:** the SHA-256 values of `ssa-split-widget.pdf`, `ssa-empty-field-signed.pdf` and the rebuilt `docmdp-reference-cap.pdf` match their `tests/corpus/README.md` rows.
- **Not run here:** the project has no `E2E` command (`—`). The build is left to ship (`Build stage: ship-if-route`; no route or manifest changed).

## Previous review's findings
- **SSA through a non-merged field or in two steps (major):** fixed for both shapes.
  - `shows_on_certified_page` (`revisions.rs:379-391`) now also checks the widget kids of a field.
  - The existing-field loop (`revisions.rs:341-345`) refuses a visible signature whose field is not in `certified_fields`.
  - Bites A and B below fail one test each.
  - The exemption for fields that already existed at certification leaves one shape open (first finding).
- **Unreadable permission read as `/P 1` was untested (minor):** fixed. `docmdp-reference-cap.pdf` now ends with the signature `Late`, and bite D fails `revision_over_the_docmdp_cap_lists_its_objects`.
- **pyHanko-specific widenings (minor):** still open (third finding).

## Bite proofs
For each bite I ran only `cargo test -p nacre-validate --no-fail-fast --test attacks --test validate` (25 + 14 tests, all green before any change). Then I restored the file with `git checkout --` and confirmed it with `git diff --exit-code`. The worktree is clean apart from the untracked earlier review.

| Bite | Change | Tests that fail |
| --- | --- | --- |
| A | kids branch of `shows_on_certified_page` turned off (`revisions.rs:386`, `false && …`) | 1: `ssa_split_widget_is_rejected` |
| B | refusal in the existing-field loop turned off (`revisions.rs:342`, `if false && …`) | 1: `ssa_empty_field_signed_is_rejected` |
| C | `certified_fields` exemption removed (`revisions.rs:342`, `if self.shows_on_certified_page(field)`) | **0** |
| D | unreadable permission read as uncertified (`revisions.rs:125`, `(None, false)`) | 1: `revision_over_the_docmdp_cap_lists_its_objects` |

## Probe (throwaway clone `/tmp/tmp.Et5Bxyeqqj/nacre`, same tree `c4f35c8…`)
I copied the forge into an example `probe.rs`. Both cases start from `with_text_field(UNSIGNED)`, add an empty signature field and then certify at `/P 2`.

| Case | Certification signature | Later signature |
| --- | --- | --- |
| Honest: the empty field is visible (`/Rect [72 650 400 700]`) when certified, and is signed later with no other change | `Indeterminate`, no defect, `Allowed([Signature])` | `Approver`: `Indeterminate`, `defect=None` |
| Attack: the empty field is invisible (`/Rect [0 0 0 0]`) when certified. The signing revision sets `/V`, enlarges `/Rect` to `[72 650 400 700]` and adds an overlay `/AP` | `TOTAL_FAILED / FORMAT_FAILURE`, `RevisionNotAllowed`, objects 10, 13, 14 refused | `Sneaky`: `Indeterminate`, `defect=None` |

## Findings
- **major** — `crates/nacre-validate/src/revisions.rs:341-345` (fix commit `4d08296`), with `qualify` at `:61-69`. The SSA exemption depends on whether the field existed in the certified state, not on whether it was visible there. An attacker takes a certified document that holds an invisible empty signature field. In the signing revision, the attacker makes that field visible: a new `/Rect`, an overlay `/AP`, or a change to an indirect `/Rect` array or a kid widget. Because `certified_with` is true, `refuse_signature` is skipped. The field then fails `only_keys_differ`, and the certification fails, so criterion 3 still holds and nothing reaches `TOTAL_PASSED`. But the sneaky signature reads exactly like a sound one: `Indeterminate`, no defect (probe above). This is the same defect the loop-0 and loop-2 reviews graded major, reached through a third shape. Once s16 judges chains, it could read as valid.
  - Fix: exempt only a field whose widget was already visible in the certified state. Equivalently, refuse the signature when the signing revision changes the visibility or the `/Rect` of its field or its widgets.
  - Add the corpus case above with a rejecting test, or record this reading as a deliberate divergence in `docs/security/attacks/pades.md`. Either way the test budget is spent, so the plan has to justify the extra test.
- **minor** — `crates/nacre-validate/src/revisions.rs:341-342`. No test exercises the accepting side of the new exemption: signing a visible field that already existed in the certified state. Bite C fails nothing.
  - The current code is right: the honest probe case gives `Allowed([Signature])`.
  - A regression would fail closed, but it would refuse the common certify-then-approve workflow with a prepared visible field, and nothing would catch it.
  - `signing_a_certified_p3_document_is_allowed` does not reach this path: `nacre_pades::sign` adds a new field instead of signing `signature-test2`.
  - Fix: assert `Allowed([Signature])` on a certified document whose visible empty field is signed later. That is the honest probe case, and it can share a fixture with the first finding's case.
- **minor** — `crates/nacre-validate/src/revisions.rs:20-24` and `:577-587`, carried over from loops 0 to 2. `INERT_KEYS` (`/Metadata`) and the Locked-flag tolerance in `SIGN_KEYS` / `locks_only` widen the rules for pyHanko, and only the pyHanko fixtures exercise them. To be checked with s19's foreign corpus.

## Not verified
- **The first finding's variants beyond the probed shape.** I ran only the "enlarged `/Rect` plus overlay `/AP`" shape. The indirect-`/Rect`-array shape and the kid-widget shape come from reading the code only. A person or the fix run should add one of them to `forge_pades_attacks.rs`.
- **No DSS parity check.** Nobody compared the verdicts with DSS: the three SSA shapes, the second-signer reading, and the `TOTAL_FAILED / FORMAT_FAILURE` mapping for `RevisionNotAllowed` and `AddedByRevisionNotAllowed`. No bench ran (the record's "Not proven here" says so too). s18 and s19 have to compare.
- **Criterion 4 on Nacre's own B-LTA output** (QA Not seen). Only pyHanko's LTA file was checked. s12 has since landed on `main` (`fd3124a`), but this branch is based before it. After the ship rebases onto `main`, a person should run `validate` on an s12 B-LTA output and check that both later revisions come out `Allowed`.
- **Files from signers other than pyHanko**, Acrobat and others (QA Not seen). None is in the corpus; s19's foreign corpus covers this.
- **An `Unreadable` revision caused by a state that fails to parse or walk** (QA Not seen). Every broken input tried was refused whole by `Document::parse`; the only `Unreadable` reached comes from the DocMDP cap.
- **An SSA built with a new key or a new CMS** (QA Not seen). The QA scenario program has no signer. My probe used the forge's fixed test key only.
- **The fuzz target was not run.** I did not run `crates/nacre-validate/fuzz/`; the record says CI's `fuzz` job runs it.
- **The CPU bound of the shared-resolver DocMDP reading was not timed.** The 32-entry cap is tested; the claim that each object stream is decoded once rests on reading only. A person should time `validate` on 32 `/Reference` entries pointing into a deflate-bomb object stream.
- **Signatures on uncertified documents.** A visible new signature or document-timestamp widget on an uncertified document is accepted by design, and a document timestamp's own integrity is never judged. An appearance overlay added that way reads as an allowed revision. A person should decide whether that needs a story.
- **Forge determinism.** I did not rerun the forge twice; I relied on the record's statement and on the three hashes matching the README.

Max severity: major
Ship allowed: yes
