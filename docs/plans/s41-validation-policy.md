---
validated: yes
---
# Plan — s41-validation-policy

[Story](../stories.md) · [Research](../research/s41-validation-policy.md)

Branch `story/s41-validation-policy`. Read `docs/research/s41-validation-policy.md` first, its switch table especially; this plan builds on it without repeating it. The design is [ADR-0026](../decisions/0026-runtime-validation-policy.md) (accepted, the person's choice of 2026-10-23).

## Story
`ValidationPolicy` holds one switch per rule that only Nacre applies. `strict()` turns them all on and is the default of `validate`, `validate_with_anchors` and `validate_with_revocation`. `dss()` turns them all off and gives DSS 6.5.1's verdict on each divergence the s18 spike found (AC1, AC2). Both presets apply the `/M` before `notBefore` rule (AC3). Under `strict()`, the 24 h window drops only "not revoked" data (AC4). There is one conformance test per switch (AC5), and `docs/security/attacks/` says which policy leaves each attack open (AC6).

The lead corrects the story text in `docs/stories.md`, which lies outside `Owns`, as the research says:
- AC1 has 8 switches, not 5. Three are added: unusable signatures listed, validity before revocation, malformed extensions judged.
- AC2: an out-of-range certificate gives `CERTIFICATE_CHAIN_GENERAL_FAILURE` when no data covers it, and `OUT_OF_BOUNDS_NOT_REVOKED` when the data says "not revoked".
- AC1: `nacre-pdf` already reports the trailing data (`Error::TrailingData { offset }`). `validate` judges the prefix, and `crates/nacre-pdf/` stays unchanged.

## Reuse

| New code | Rung that holds | Why each rung above fails |
| --- | --- | --- |
| Trailing-data handling | `nacre_pdf::Error::TrailingData { offset }` (`xref.rs:146-166`) and `Document::parse` on `pdf.get(..offset)` | — |
| `ValidationPolicy` | new code, a struct of `bool`s | nothing in the repository holds validation options |
| Gating each rule | the existing rule functions (`signed_bytes`, `qualify`/`Judge::sneaky`, `chain::judge`, `judge_path`), each given its flag | — |
| Revocation reason | `CrlStatus::Revoked { reason }`, `OcspStatus::Revoked { reason }`, `CrlReason::CertificateHold` | — |
| `/M` date parser | new code, about 40 lines, built on `der::DateTime::new` for range checks | no PDF date parser in the workspace; `nacre-pades` only writes dates (`sign.rs:194`) |
| Repeated-extension check | `Certificate::from_der` and `tbs_certificate().extensions()` | — |
| Bench cases | `tests/support/forge.rs` (`issue`, `crl`, `signed`, `with_dss`, `ChainSigner`) and `tests/conformance.rs` (`confront`, `forged`, `RevokingSource`), extended | — |

## Tasks
1. [x] **The policy and its entry point.** New `src/policy.rs`: `#[non_exhaustive] #[derive(Debug, Clone, Copy, PartialEq, Eq)] pub struct ValidationPolicy` with eight `pub bool` fields, one per row of ADR-0026's table, plus `strict()` (all `true`), `dss()` (all `false`) and `Default` = `strict()`. The rustdoc of `dss()` opens with the warning the story's notes ask for, and names the attacks it reopens.
   - New `pub fn validate_with_policy(pdf, anchors, at, source, policy: &ValidationPolicy)`; `validate_with` takes the policy.
   - `validate`, `validate_with_anchors` and `validate_with_revocation` pass `&ValidationPolicy::strict()`.
   - Re-export it from `lib.rs`.
   - Test: none of its own. Every existing test goes through the three old entry points, so making them default to anything but `strict()` turns `tests/attacks.rs` red.
2. [x] **Later revisions and sneaky signatures.**
   - `Qualified` keeps the SSA refusals (`sneaky`, `revisions.rs:414`) in a new `sneaky_signatures` list, apart from the DocMDP 1 ones (`:479`). `qualify(pdf, doc, first, sneaky: bool)` skips `Judge::sneaky` when `sneaky` is false.
   - In `validate_with` (`validate.rs:214-229`):
     - `added_by` comes from `refused_signatures` only when `refuse_later_revisions` is on, and from `sneaky_signatures` only when `refuse_sneaky_signatures` is on;
     - `refused` is `None` when `refuse_later_revisions` is off.
   - `signed_bytes` skips `ByteRangeNotWholeFile` (`:419-421`) when `refuse_later_revisions` is off; the end stays `c + d` and maps to no revision.
   - `later_revisions` stays listed in every case.
   - Test (`tests/policy.rs`, new), on committed files, each run under `strict()` (its strict verdict) and under `strict()` with one switch off (no defect, `INDETERMINATE` / `NO_CERTIFICATE_CHAIN_FOUND`):
     - (a) `isa-appended-revision.pdf` and `byterange-not-whole-file.pdf`, with `refuse_later_revisions` off; `later_revisions` still non-empty for the first;
     - (b) `ssa-visible-signature.pdf`, with `refuse_sneaky_signatures` off: both fields sound.
3. [x] **Trailing data and unusable signatures** in `validate_with`:
   - On `Err(nacre_pdf::Error::TrailingData { offset })` with `refuse_trailing_data` off, parse `pdf.get(..offset)` and judge that slice throughout: hashing and the `ByteRangeOutsideFile` bound use it.
   - With `list_unusable_signatures` off, drop the results whose defect is `ContentsMissing`, `ContentsNotDer` or `ByteRangeMalformed`, the three defects of the 7 `usf-*` files. No other defect is dropped (research, open questions).
   - Tests:
     - (c) `isa-no-xref.pdf`: `Err(TrailingData)` under `strict()`; with the switch off, one signature, no defect, `NO_CERTIFICATE_CHAIN_FOUND`;
     - (d) `usf-contents-missing.pdf` and `usf-contents-zeros.pdf`: one result under `strict()`, none with the switch off; `byterange-overlap.pdf` stays listed and `TOTAL_FAILED` with the switch off.
4. [x] **Signer key usage and malformed extensions.**
   - `build_path` takes a `rules` argument (two `bool`s: key usage and validity). `chain::judge` skips the depth-0 EKU and `keyUsage` checks (`chain.rs:448-465`) for `Purpose::Signing` when `judge_signer_key_usage` is off. `Purpose::Timestamping` is judged as today.
   - `build_chain` keeps the strict rules.
   - With `judge_malformed_extensions` off, any certificate of a verified signature's CMS `certificates` that repeats an extension OID makes `validate_with` return the new `Error::MalformedCertificate`, kind `InvalidInput`. Add its row to `every_variant_has_its_kind` (`error.rs:42-60`).
   - Tests, with the chain corpus root at 2026-10-22, as `with_chain_root` does (`attacks.rs:312-322`):
     - (e) `chain-key-usage.pdf` and `chain-extended-key-usage.pdf`: `CHAIN_CONSTRAINTS_FAILURE` under `strict()`; with the switch off, the path is kept in `chain` and the result is `RevocationDefect::Missing` (`CERTIFICATE_CHAIN_GENERAL_FAILURE`);
     - (f) `chain-malformed-extension.pdf`: a `MalformedExtension` verdict under `strict()`, `Err(MalformedCertificate)` with the switch off.
5. [x] **Validity after revocation.** With `judge_validity_before_revocation` off:
   - the walk does not judge validity (`chain.rs:424-429`);
   - `Context::judge` runs `judge_path` on the path it found. `Missing` and `Revoked` keep their reports. When revocation passes, the first certificate below the anchor that is out of range at `time` gives a new `Defect::OutOfRangeNotRevoked(ChainDefect)` (holding `Expired` or `NotYetValid`). Its report is `INDETERMINATE` / `OUT_OF_BOUNDS_NOT_REVOKED`, and the path stays in `chain`.
   - The signer only. The TSA path in `proven_time` is unchanged.
   - Test (g), two cases of one rule:
     - `chain-expired.pdf` (no data): `OUT_OF_BOUNDS_NO_POE` under `strict()`, `CERTIFICATE_CHAIN_GENERAL_FAILURE` with the switch off;
     - a forged signer of `tests/revocation.rs`'s `Pki`, expired at the control date, with a "not revoked" CRL in `/DSS`: `OUT_OF_BOUNDS_NOT_REVOKED` with the switch off.
   - `forge::issue_valid(…, not_before, not_after)` is added, and `issue` calls it.
6. [x] **Freshness.**
   - With `require_fresh_revocation` off, `issued_from` is `None` (`validate.rs:304-306`).
   - Under `strict()`, `judge_path` (`revocation.rs:212-216`) no longer drops a verdict issued before `issued_from` when it says "revoked" with a reason other than `certificateHold`. `Verdict` gains `hold: bool`, set from the CRL or OCSP reason in `Item::verdict`. The `notBefore` filter stays for every item.
   - Tests:
     - (h) the scenario of `old_crl_does_not_pass_a_signature_without_poe` (`tests/revocation.rs:460`) with the switch off: `TOTAL_PASSED`;
     - (i) AC4: B-B, a CRL issued more than 24 h before the control date that revokes the signer (`keyCompromise`) → `REVOKED_NO_POE` under `strict()`; the same CRL with reason `certificateHold` → `CERTIFICATE_CHAIN_GENERAL_FAILURE`. `forge::crl` gains a reason argument, or a sibling helper.
7. [x] **`/M` before `notBefore`** (both presets).
   - New private `src/date.rs`: `fn pdf_date(&[u8]) -> Option<SystemTime>` for `D:YYYY[MM[DD[HH[mm[SS[Z|±HH'mm']]]]]]`. Missing fields take their defaults (month and day 1, 0 elsewhere), and the input is at most 32 bytes. Anything else is `None` and the rule does not apply.
   - `check` reads `/M` from the signature dictionary into `Signed.claimed_time`.
   - In `Context::judge`, once chain and revocation passed (and after task 5's out-of-range check), a `claimed_time` before the signer's `notBefore` gives the new `Defect::ClaimedTimeBeforeCertificate`: `INDETERMINATE` / `SIG_CONSTRAINTS_FAILURE`, with the path kept.
   - Tests:
     - (j) a `Pki` signer issued with `notBefore` 2026-10-23, signed with `forge::signed` (`/M` 2026-10-22), judged at a control date after that `notBefore` with a CRL issued after it, under `strict()` and under `dss()` → `SIG_CONSTRAINTS_FAILURE`;
     - (k) a unit table in `date.rs`: `D:20261022080000Z`, `D:20261022100000+02'00'`, `D:2026` → the expected instants; `D:20261340`, a 40-byte string and `20261022` (no `D:`) → `None`.
8. [x] **Conformance, one test per switch plus the `/M` rule** (`tests/conformance.rs`, `#[ignore = "conformance"]`, run by `conformance.yml`).
   - `confront` takes the policy. A sibling asserts the DSS signature count, and another accepts a DSS error.
   - Each test judges one file twice: DSS's verdict = Nacre under `dss()`, and the strict verdict under `strict()`. The files:
     - revisions: a bench B plus an appended revision setting a JavaScript `/OpenAction` (l37): `TOTAL_PASSED` vs `TOTAL_FAILED`;
     - SSA: `ssa-visible-signature.pdf` → `NO_CERTIFICATE_CHAIN_FOUND` for both fields vs `TOTAL_FAILED`;
     - trailing data: `isa-no-xref.pdf` → `NO_CERTIFICATE_CHAIN_FOUND` vs `Err`;
     - USF: `usf-contents-missing.pdf` → 0 signatures vs 1;
     - key usage: a forged `keyCertSign`-only leaf under the bench intermediate (c42) with its CRL in `/DSS` → `TOTAL_PASSED` vs `CHAIN_CONSTRAINTS_FAILURE`;
     - validity: a forged signer already expired, no data (c40) → `CERTIFICATE_CHAIN_GENERAL_FAILURE` vs `OUT_OF_BOUNDS_NO_POE`;
     - malformed: a forged leaf repeating `keyUsage` under the bench intermediate → DSS and Nacre `dss()` both errors vs a `MalformedExtension` verdict;
     - freshness: a forged CDP-less signer, B-B, a "not revoked" CRL issued 25 h ago in `/DSS` → `TOTAL_PASSED` vs `CERTIFICATE_CHAIN_GENERAL_FAILURE`;
     - `/M`: a forged signer whose `notBefore` follows `/M` → `SIG_CONSTRAINTS_FAILURE` under both.
   - The forged leaves need an extensions override in `forge.rs` (key usage, EKU, a repeated extension).
   - Run them on the bench (`conformance/README.md`), then stop it. A DSS verdict other than the one written here stops the task: report it to the lead, do not adjust the expectation.
9. [x] **Rustdoc and fuzzing.**
   - `lib.rs:1-38`, `validate.rs:81-147`, the docs of `report.rs` and the new variants describe the policy, the default and each switch.
   - The fuzz target (`fuzz/fuzz_targets/validate.rs`) also calls `validate_with_policy(data, anchors(), at, None, &ValidationPolicy::dss())`.
   - No test of its own; clippy and `cargo test` cover the doc links.
10. [x] **`docs/security/attacks/`.**
    - `pades.md`, `cms.md` and `revocation.md` gain, on each attack row, the closing rule and the policy that leaves it open: "ouverte sous `dss()`", or "aucune".
    - Drop the stale "jusqu'à s17" and "tant que … (s17)" mentions (`pades.md:79-80`, `cms.md:24`), and rewrite `pades.md:82` and `cms.md:49` with the DSS verdicts now known.
    - Add s17's revocation attacks to `revocation.md`, each with its test in `crates/nacre-validate/tests/revocation.rs`:
      - CRL of a forged key: `crl_signed_by_another_key_is_ignored`;
      - CRL issued before `notBefore`: `crl_before_not_before_is_ignored`;
      - invalid `/DSS`: `chain_dss_junk_does_not_hide_the_chain`, in `attacks.rs`;
      - stale CRL: `expired_crl_still_counts`, and the 24 h case `old_crl_does_not_pass_a_signature_without_poe`.
    - Review against the table of ADR-0026: each switch appears at least once.

## Scene viewpoints
—

## Run interdicts
- The diff stays empty outside `crates/nacre-validate/`, `docs/security/attacks/`, this plan, the research and ADR-0026. In particular, `crates/nacre-pdf/`, `crates/nacre-core/`, `crates/nacre-conformance/`, `crates/nacre-revocation/`, `.github/`, `conformance/` and `docs/stories.md` stay untouched.
- Under `strict()`, every existing test passes unchanged except the rows task 4 adds to `every_variant_has_its_kind`. No assertion of `tests/attacks.rs`, `tests/chain.rs`, `tests/validate.rs` or `tests/revocation.rs` is edited.
- `FRESHNESS_TOLERANCE` (`revocation.rs:27`) is unchanged, and so is the `None` passed for the TSA path (`validate.rs:363`, s42's job).
- `build_chain`'s public behaviour, and `ChainDefect::report` / `RevocationDefect::report`, are unchanged.
- No new dependency, no `[workspace.dependencies]`, no `Cargo.lock`, no `cms` or `x509-tsp` crate.
- No public TSA, no online DSS demo, no `NACRE_DSS_URL` other than local. Never stop `patelle-dss`, never touch `omniroute`, and leave the bench down at the end.
- No level computation and no campaign: that is s18.

## The pivot
That DSS's behaviour on the spike's single files generalises into eight switches, each of which reaches DSS's verdict by turning off one Nacre rule. Ways it could be wrong:
- **The USF rule is too narrow or too wide.** Only three defects were observed unlisted. Compare `NotASignatureDictionary` and `UnsupportedSubFilter` against DSS when s18's campaign meets them.
- **The out-of-range order.** "Revocation first" was observed with no data and with "not revoked", never with "revoked". Check task 5 against c26 and c40 on the bench.
- **The repeated-extension error.** It was observed on a CMS leaf only. A repeated extension in `/DSS` or in a token certificate may also crash DSS, or may not; s18's campaign will show it.
- Check that `strict()` changed nothing but AC3 and AC4: the existing suite is the evidence (run interdict 2).

## Files touched
- `crates/nacre-validate/src/{policy.rs, date.rs, lib.rs, validate.rs, revisions.rs, chain.rs, revocation.rs, report.rs, error.rs}`
- `crates/nacre-validate/tests/{policy.rs, conformance.rs, revocation.rs, support/forge.rs}`
- `crates/nacre-validate/fuzz/fuzz_targets/validate.rs`
- `docs/security/attacks/{pades.md, cms.md, revocation.md}`
- `docs/decisions/0026-runtime-validation-policy.md`

## Test strategy
Every rule lives at the service layer (`nacre-validate`); there is no adapter. 20 new tests, within the budget of 25:
- **11 unit tests**, (a) to (k): one per switch (8), the AC4 refinement (1), the `/M` rule (1), and the date parser (1). Each one runs a file under `strict()` and under `strict()` minus one switch, so it fails if that switch's guard is removed or inverted.
- **9 conformance tests** (task 8): AC5 asks for one per switch, plus `/M`.

The two lists check the same switches at two layers. The unit tests run on every `cargo test`. The conformance tests need the bench and run only with `--ignored`, so they alone prove the verdict is DSS's. Unit tests use committed files and `Pki` forges. Bench cases are forged at run time. `every_variant_has_its_kind` gains one row and no test.

The full suite and clippy run once, at the end, through `po-run --story s41-validation-policy`; the conformance tests run on the bench at execute, and in CI. Visual checks: none (`Surface: endpoint`).

## Done when
- `validate_with_policy` exists. Every existing test is green under the default `strict()`. Each switch has its unit test and its conformance test, and DSS agrees with Nacre under `dss()` on all nine bench cases.
- `docs/security/attacks/` names, for each attack, the policy that leaves it open.
- `cargo test --workspace` and clippy are green through `po-run`, and a review has no open critical finding.
- One commit, landed through a pull request.
