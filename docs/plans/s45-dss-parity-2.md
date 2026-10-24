---
validated: yes
---
# Plan — s45-dss-parity-2

[Story](../stories.md) · [Research](../research/s45-dss-parity-2.md)

Branch `story/s45-dss-parity-2`. Read `docs/research/s45-dss-parity-2.md` first, its spike table especially; this plan builds on it without repeating it. The switches and their names are settled by ADR-0029 (accepted, written by this lane); no choice waits for a person.

## Story
- AC1: tenth switch `refuse_misplaced_xref`, on in `strict()`. Off, `startxref-off-by-one.pdf` is read through a `nacre-pdf` read option and gives no signature, as DSS; on, it stays refused.
- AC2: under `dss()`, a missing or non-name `/SubFilter` is verified as DSS does (`TOTAL_PASSED`, no level), by the ninth switch; refused under `strict()`.
- AC3: eleventh switch `ignore_expired_certs_on_crl`, on in `strict()`. Off, a CRL issued after the covered certificate's `notAfter` counts when its `expiredCertsOnCRL` is at or before that `notAfter`; on, it is dropped as today.
- AC4: both presets: revocation data issued by a CA out of its validity at the control date → `INDETERMINATE` / `REVOCATION_OUT_OF_BOUNDS_NO_POE`. Without a proof of existence, `strict()` keeps `OUT_OF_BOUNDS_NO_POE` from its validity switch, which fires first (research, structuring facts).
- AC5: both presets: a CA below the anchor without `subjectKeyIdentifier` → `INDETERMINATE` / `CERTIFICATE_CHAIN_GENERAL_FAILURE`; `chain/` regenerated with SKI on its CAs.
- AC6: ADR-0029 adds both switches to ADR-0027's table; the isolation tests list eleven switches and the catalogue names them.
- AC7: one conformance test per shape: DSS's verdict under `dss()`, the strict one under `strict()`.

## Reuse

| New code | Rung that holds | Why each rung above fails |
| --- | --- | --- |
| Two switches | `ValidationPolicy` fields, `strict()`, `dss()` (`crates/nacre-validate/src/policy.rs:14-111`) | — |
| `nacre-pdf` read option | new `ReadOptions` in `nacre-pdf`, passed down to `read_section` (`src/xref.rs:168-179`) | `parse_with` is `pub(crate)` and takes `Limits` only (`document.rs:41`); no reader option exists |
| Whitespace skip | `Parser::skip_whitespace` (`src/parse.rs`, used at `xref.rs:102`) | — |
| `expiredCertsOnCRL` date | `x509_cert::crl::CertificateList` and `der::asn1::GeneralizedTime` on the CRL's DER (both dependencies already) | `nacre_revocation::Crl` exposes no extension, and `crates/nacre-revocation/` is outside `Owns` |
| Issuer validity | `in_validity` (`src/chain.rs:514-528`) | — |
| `REVOCATION_OUT_OF_BOUNDS_NO_POE` | `SubIndication::RevocationOutOfBoundsNoPoe` (`nacre-core/src/report.rs:84`) | — |
| SKI check | `x509_cert::ext::pkix::SubjectKeyIdentifier`, read as in `Node::read` (`chain.rs:285-290`) | — |
| Forging | `tests/support/forge.rs` (`issue_with`, `crl`, `patch`, `with_dss`), extended; spike 3's `resign` and `crl_expired_certs` (`/home/lecrabe/.claude/jobs/4fb763d0/tmp/s18-spike3/src/bin/forge3.rs:44-60`, `:116-127`) as sketches | — |
| Misplaced-xref attack file | `examples/forge_chain_attacks.rs`, which already writes `attacks/chain-*` from `chain-cms.pdf` | — |

## Tasks
1. [x] **`nacre-pdf` read option.**
   - `pub struct ReadOptions { pub misplaced_xref: bool }`, `#[non_exhaustive]`, `Default` all `false`, exported from `src/lib.rs`. `Document::parse_with_options(bytes, &ReadOptions)`. `parse` stays `parse_with_options(bytes, &ReadOptions::default())`, so every current caller is unchanged.
   - With `misplaced_xref`, `read_section` skips whitespace from a section offset (stated by `startxref` or `/Prev`) when neither `xref` nor an object header is there. It then requires one of them, or `NotAnXrefSection` as today. Object entries are never moved.
   - The `Revision::startxref` of such a section is the offset where it was found. `group_revisions` and the loop check key on that offset, so `update()` writes a `/Prev` a strict reader follows (`revision.rs:406`).
   - Rustdoc of `lib.rs:9-19` names this one opt-in tolerance. The hostile row of `tests/corpus/README.md:39` says "refused; read with `ReadOptions::misplaced_xref`". The `parse` fuzz target also parses with the option on.
   - Tests in a new `tests/options.rs`:
     - (a) the hostile file reads with the option: one revision, `startxref` 565, `end` the file's length, no signature field;
     - (b) with the option, `refusals::xref_entry_pointing_elsewhere()` is still refused, and so is a `startxref` landing on a non-whitespace byte (the hostile file patched to `562`, the `j` of `endobj`).

   `tests/refusals.rs` and `tests/hostile.rs` stay unchanged.
2. [x] **The two switches, the read option, and the ninth switch's reach.**
   - `refuse_misplaced_xref` and `ignore_expired_certs_on_crl` become the tenth and eleventh fields: on in `strict()`, off in `dss()`, with rustdoc. The `dss()` warning (`policy.rs:89-97`) adds "a cross-reference section found only by skipping whitespace" and "a CRL issued after a certificate expired, trusted on its `expiredCertsOnCRL`". `refuse_unsupported_sub_filters`'s rustdoc (`:63-70`) drops "refused either way".
   - `validate_with` builds `ReadOptions { misplaced_xref: !policy.refuse_misplaced_xref }` and uses it for both parses (`validate.rs:146-154`). `qualify` passes it to `State::read` (`revisions.rs:149`).
   - In `signed_bytes` (`validate.rs:505-509`), with `refuse_unsupported_sub_filters` off, any `/SubFilter` passes, missing or not a name included. On, only a name in `SUB_FILTERS` passes. `Defect::UnsupportedSubFilter`'s rustdoc (`report.rs:89-92`) follows.
   - Tests in `tests/policy.rs`:
     - (a) `misplaced_xref_switch`: the hostile file of `nacre-pdf` (`include_bytes!("../../nacre-pdf/tests/corpus/hostile/startxref-off-by-one.pdf")`) gives `Error::Pdf(NotAnXrefSection)` under `strict()`, and `Ok` with no signature with the switch off;
     - (b) `missing_sub_filter_switch`: `custom_signed` patched to drop `/SubFilter`, then to `/SubFilter 7`, each re-signed by a new `forge::resign`, is `UnsupportedSubFilter` under `strict()`, and `sound` with the switch off.
3. [x] **`expiredCertsOnCRL`** (`src/revocation.rs`).
   - `Item::read` keeps, for a CRL, the `GeneralizedTime` of its `2.5.29.60` extension, read from the DER through `x509_cert::crl::CertificateList`; an unreadable value counts as absent.
   - `Verdict` carries it. The filter (`:235-239`) also keeps a verdict issued after `notAfter` when the switch is off and that date is at or before `notAfter`; the `notBefore` bound and freshness stay.
   - `judge_path` receives the switch from both callers (`validate.rs:357`, `:448`).
   - New `forge::crl_with_expired_certs_on_crl(issuer, key, this_update, next_update, from)`.
   - Test `expired_certs_on_crl_switch` in `tests/revocation.rs`: a `Pki` signer expired at 09:00, stamped at 08:00, with a `/DSS` holding the intermediate's CRL of 10:00 whose `expiredCertsOnCRL` is 2026-01-01 (s1).
     - Under `strict()`: `Missing`, `CERTIFICATE_CHAIN_GENERAL_FAILURE`.
     - Switch off: `TOTAL_PASSED`.
     - Switch off, `expiredCertsOnCRL` after the `notAfter`: `Missing`.
4. [x] **Revocation data from a CA out of validity, under both presets.**
   - `RevocationDefect::IssuerOutOfBounds { depth }`, `depth` being the certificate whose data that CA issued. `report()` gives `INDETERMINATE` / `REVOCATION_OUT_OF_BOUNDS_NO_POE`; it is one more row of `every_revocation_defect_has_its_report`.
   - `judge_path` takes `issuers_at: Option<SystemTime>`. Once every pair passed `Missing` and `Revoked`, it checks with `in_validity`, at `issuers_at`, each issuer of a pair that is not the path's last certificate (the anchor).
   - `Context::judge` passes `Some(self.at)`. `proven_time` passes `None`: its path is already valid at `self.at`. `judge_path`'s rustdoc says both; group its new arguments in a small struct if clippy's argument count requires it.
   - Test `issuer_out_of_validity_is_revocation_out_of_bounds` in `tests/revocation.rs`, with a CA under the `Pki` root valid until 2026-10-22T12:00, judged on 2026-10-23, its signer's CRL and the root's both of 10:00:
     - a B-T stamped at 08:00 gives `REVOCATION_OUT_OF_BOUNDS_NO_POE` under `strict()` and `dss()` (p06b);
     - the same B under `dss()` gives it too, not `OUT_OF_BOUNDS_NOT_REVOKED` (p06d);
     - a root CRL of 13:00, after the CA's `notAfter`, gives `Missing { depth: 1 }` (p06).
5. [x] **A CA without `subjectKeyIdentifier`, under both presets.**
   - `Defect::CaKeyIdentifierMissing { depth }` gives `INDETERMINATE` / `CERTIFICATE_CHAIN_GENERAL_FAILURE` through `after_chain`, with the path kept. It is mapped in `defective` (`report.rs:187-232`).
   - It is judged in `after_revocation`, after the validity loop (`validate.rs:400-404`) and before `/M` (`:409`). It covers each certificate of depth 1 up to, not including, the anchor.
   - In `forge.rs`, `Role::Ca` gains a SKI (SHA-256 of the key, first 20 bytes), and `Extensions::WithoutKeyIdentifier` leaves it out.
   - Test `ca_without_key_identifier_is_a_general_failure` in `tests/revocation.rs`:
     - a sound B-T under a SKI-less intermediate gives the defect under both presets, path kept (r-cases, s4 with data);
     - the same signer revoked gives `REVOKED_NO_POE` (s3);
     - with no `/M`, the defect again, not `SIG_CONSTRAINTS_FAILURE` (s2).
6. [x] **Corpus regeneration.**
   - In `examples/forge_chain_attacks.rs`, `Profile` writes a SKI when `ca` is true (`:280-292`). Its output gains `attacks/xref-misplaced-startxref.pdf`: `chain-cms.pdf` plus an empty update (`xref`, `trailer` with `/Prev`), whose `startxref` names the `\n` before that `xref` (the research's probe file).
   - Run `cargo run -p nacre-validate --example forge_chain_attacks -- crates/nacre-validate/tests/corpus`, then update every hash and add the new row in `tests/corpus/README.md:72-105`.
   - Rerun `tests/chain.rs`, `tests/attacks.rs`, `tests/validate.rs` and `tests/revocation.rs`, unchanged; they must stay green.
7. [x] **Isolation and catalogue** (AC6).
   - `SWITCHES` in `tests/policy.rs:256-282` lists eleven.
   - `docs/security/attacks/pades.md`:
     - the contract paragraph (`:24`) cites ADR-0029;
     - check 2 of the order list says the ninth switch also covers a missing `/SubFilter`;
     - the row `subfilter-unsupported.pdf` (`:42`) says the same;
     - a new row for `xref-misplaced-startxref.pdf`, cell `` `dss()` (`refuse_misplaced_xref`) ``, with its test from task 2 (a).
   - `revocation.md` (`:84-97`): the intro and two rows, ECOC (`` `dss()` (`ignore_expired_certs_on_crl`) ``) and the expired issuer (`aucune`).
   - `cms.md` (`:22-51`): the rule text and a row for the SKI-less CA (`aucune`), each with its test.
   - Run `tests/policy.rs`. Both isolation tests must pass; the new file must change under `refuse_misplaced_xref` alone and open under `dss()`.
8. [x] **Conformance tests** in `tests/conformance.rs`, one per shape, forged at run time like s43's:
   - `misplaced_xref_policy`: the hostile file, 0 signatures in DSS and under `dss()`, and `Err` under `strict()`. Then `xref-misplaced-startxref.pdf`, `NO_CHAIN` once in DSS and under `dss()`, and `Err` under `strict()`.
   - `missing_sub_filter_policy`: p03, p04 and p04b (bench signer, `/M`, `chain_crls`, re-signed). `PASSED` in DSS and under `dss()`, `FORMAT` under `strict()`.
   - `expired_certs_on_crl_policy`: p09 gives `OUT_OF_BOUNDS_NOT_REVOKED` under `dss()` and `OUT_OF_BOUNDS_NO_POE` under `strict()`. s1 gives `PASSED` under `dss()` and `GENERAL_FAILURE` under `strict()`.
   - `issuer_out_of_validity_policy`: the CA is forged with SKI under `bench_key("root")`. p06b gives `REVOCATION_OUT_OF_BOUNDS_NO_POE` under both presets. p06d gives it under `dss()`, and `OUT_OF_BOUNDS_NO_POE` under `strict()`.
   - `ca_without_key_identifier_policy`: s4 with fresh `/DSS` CRLs for the SKI-less CA and the root. `GENERAL_FAILURE` in DSS and under both presets.

   Start the bench (`conformance/README.md`), run `cargo test -p nacre-validate --all-features --test conformance -- --ignored`, then `podman compose -f conformance/compose.yaml down`.
9. [x] **ADR links and rustdoc.**
   - ADR-0027's frontmatter gets `superseded-by: [0029]`; its status and body stay.
   - The crate docs `src/lib.rs:42-56` and the `validate_with_policy` docs (`validate.rs:115-127`) name the two switches and the two rules of tasks 4 and 5.
   - The `Defect` and `RevocationDefect` docs cover the new variants.

## Scene viewpoints
—

## Run interdicts
- The diff is empty outside `crates/nacre-validate/`, `crates/nacre-pdf/`, `docs/security/attacks/` and these files:
  - `docs/decisions/0027-unsupported-sub-filter-switch.md`, frontmatter only;
  - `docs/decisions/0029-misplaced-xref-and-expired-certs-on-crl-switches.md`;
  - this plan and the research.

  In particular, `crates/nacre-revocation/`, `crates/nacre-core/`, `crates/nacre-conformance/`, `crates/nacre-pades/`, `conformance/`, `.github/`, `docs/stories.md` and ADR-0026 and ADR-0028 stay untouched.
- `Document::parse` keeps its behaviour, and `nacre-pades` never sets `ReadOptions`. `crates/nacre-pdf/tests/refusals.rs` and `tests/hostile.rs` end with an empty diff.
- `strict()` keeps every verdict it gives today, except where it gets stricter: the expired-issuer shapes with a proof of existence (task 4) and the SKI-less CA (task 5). Every existing test passes unchanged, except the corpus hashes and one new row of `every_revocation_defect_has_its_report`.
- Out of scope: no level is computed (`report.level()` stays `None`), document timestamps stay ignored, and neither `FRESHNESS_TOLERANCE` nor the TSA path's rules change (s18, s42, s44).
- No new dependency, no `[workspace.dependencies]`, no `Cargo.lock`, no `cms` or `x509-tsp` crate.
- No public TSA, no online DSS demo, no `NACRE_DSS_URL` other than local. Never stop `patelle-dss`, never touch `omniroute`, and leave the bench down at the end.

## The pivot
Each new verdict follows the order DSS showed: `Missing` / `Revoked`, then the issuer's validity at the control date, then (under `dss()`) each certificate's validity, then the CA's SKI, then `/M`. Ways it could be wrong:
- **Reducing "issuer of the revocation data" to the CA of the pair.** That holds for every CRL (`crl.rs:109-121`) and for an OCSP response signed by the CA, as on the bench. It is laxer than DSS for a delegated responder expired at the control date, which nobody forged. Compare with DSS once s18's campaign meets one.
- **SKI judged below the anchor only, and on the signer's path only.** A SKI-less trust anchor and a timestamp authority's chain were not observed. Since bench CAs all carry SKI, the conformance tests cannot tell.
- **The whitespace-only tolerance** matches the corpus, and only the corpus. DSS also reads offsets into non-whitespace (probe +1, −5), so a file like that would split the campaign; ADR-0029 records it.

## Files touched
- `crates/nacre-pdf/`:
  - `src/{lib.rs, document.rs, xref.rs}`;
  - `tests/options.rs`;
  - `tests/corpus/README.md`;
  - `fuzz/fuzz_targets/parse.rs`.
- `crates/nacre-validate/`:
  - `src/{policy.rs, validate.rs, revisions.rs, revocation.rs, report.rs, lib.rs}`;
  - `tests/{policy.rs, revocation.rs, conformance.rs, support/forge.rs}`;
  - `examples/forge_chain_attacks.rs`;
  - `tests/corpus/chain/*`, `tests/corpus/attacks/chain-*.pdf` and `xref-misplaced-startxref.pdf`, and `tests/corpus/README.md`.
- `docs/security/attacks/{pades.md, revocation.md, cms.md}`.
- `docs/decisions/0027-unsupported-sub-filter-switch.md`, frontmatter only.

## Test strategy
The rules live at the service layer: `nacre-validate`, and `nacre-pdf` for the read option. There is no adapter. New automated tests, 12 within the budget of 25:

| Task | Tests | Bites when |
| --- | --- | --- |
| 1 | 2 | (a) the skip is removed; (b) the skip moves object entries or crosses non-whitespace |
| 2 | 2 | the option is not passed from the policy; a missing `/SubFilter` is refused with the switch off |
| 3 | 1 | ECOC is ignored when off, honoured when on, or honoured past `notAfter` |
| 4 | 1 | the issuer check is dropped, judged at the best-signature-time, or placed before `Missing` |
| 5 | 1 | the SKI check is dropped, or placed before revocation or after `/M` |
| 8 | 5 | DSS's verdict per shape, under `--ignored` on the bench |

Changed, not new: one row of `every_revocation_defect_has_its_report`, `SWITCHES`, and the hashes of the corpus README.

Rerun as they stand: the isolation tests (`each_switch_changes_only_what_the_catalog_names`, `dss_opens_only_what_the_catalog_marks`), which now cover eleven switches and the new attack file.

Each task's tests run alone after it. The full suite and clippy run once at the end, through `po-run --story s45-dss-parity-2` (`cargo test --workspace`, then the `Typecheck` command). Visual checks: none (`Surface: endpoint`).

## Done when
- AC1 to AC7 hold: the conformance tests of task 8 pass on the bench, and the bench is stopped afterwards.
- `cargo test --workspace` and clippy pass through `po-run`.
- The review leaves no open critical finding.
- The story lands as one commit through a pull request.
