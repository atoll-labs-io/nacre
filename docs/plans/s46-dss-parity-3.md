---
validated: yes
---
# Plan — s46-dss-parity-3

[Story](../stories.md) · [Research](../research/s46-dss-parity-3.md)

Branch `story/s46-dss-parity-3`. Read `docs/research/s46-dss-parity-3.md` first, its spike table especially; this plan builds on it without repeating it. Both choices are settled by ADR-0030 (accepted, written by this lane on the person's decision, `docs/decisions-log.md:110`); no choice waits for a person.

## Story
- AC1: on a timestamp authority's path, a CA below the anchor without SKI takes any proof of existence from its token, under both presets (k1).
- AC2: a twelfth switch `judge_issuer_of_revoked_data`, on in `strict()`. Off, the issuer-validity rule skips a certificate whose deciding data says "revoked" (v3), and v5 keeps its verdict. On, nothing changes.
- AC3: a delegated OCSP responder valid at `producedAt` and out of validity at the control date gives `REVOCATION_OUT_OF_BOUNDS_NO_POE`, under both presets. On e2 itself, a B-B with 3-day-old data, `strict()` keeps `CERTIFICATE_CHAIN_GENERAL_FAILURE` from its freshness switch, which drops the response first (research, structuring facts). `nacre-revocation` exposes the delegate.
- AC4: `ignore_expired_certs_on_crl` also covers OCSP `archiveCutoff`. Off, the response counts as DSS counts it (e4, e5); on, it is dropped.
- AC5: ADR-0030 supersedes ADR-0029's table. `SWITCHES` lists twelve, and the catalogue names the twelfth and the widened eleventh.
- AC6: one conformance test per family: DSS's verdict under `dss()`, the strict one under `strict()`.

## Reuse

| New code | Rung that holds | Why each rung above fails |
| --- | --- | --- |
| Twelfth switch | `ValidationPolicy` fields, `strict()`, `dss()` (`crates/nacre-validate/src/policy.rs:16-129`) | — |
| SKI check on TSA paths | the loop of `after_revocation` (`validate.rs:428-435`), extracted into a helper | — |
| Deciding verdict per pair, revoked skip | `Verdict` and the `latest` reduce of `judge_path` (`revocation.rs:136-144`, `:287-291`) | — |
| Delegate validity | `in_validity` (`chain.rs:514-527`) or the same comparison on a stored window | — |
| `OcspResponse::delegated_responder` | `delegate()` and `responder_key` (`crates/nacre-revocation/src/ocsp/response.rs:211-281`), returning the certificate too | `nacre-validate` cannot see `certs` or the authorization; re-deciding it there would duplicate RFC 6960 §4.2.2.2 |
| `OcspResponse::archive_cutoff` | `single()` (`response.rs:194-206`) and `der::asn1::GeneralizedTime`, as `expired_certs_on_crl` reads its CRL twin (`nacre-validate/src/revocation.rs:122-134`) | `singleExtensions` is private to `nacre-revocation` |
| `archiveCutoff` gate | `Verdict::expired_from` and the `within` closure (`revocation.rs:142`, `:281-286`), unchanged | — |
| OCSP forging in tests | `crates/nacre-revocation/src/ocsp/asn1.rs` included by `#[path]` as `examples/forge_ocsp_attacks.rs:16-18` does; `CertID` read back from `OcspRequest::new(…).to_der()` (`request.rs:28-35`) | openssl stamps `producedAt` now; the `CertID` route needs no `sha1` dev-dependency |
| Delegate certificate in tests | `forge::issue_with` with a new `Role::OcspResponder` (EKU `id-kp-OCSPSigning`, `id-pkix-ocsp-nocheck`), as spike `forge5.rs:150-171` builds one | — |
| `/OCSPs` in `/DSS` | `forge::with_dss` (`tests/support/forge.rs:509-528`) generalised with an `ocsps` list | — |
| Bench cases | `forged_ca`, `forged_signer`, `crl_at`, `confront_signatures` (`tests/conformance.rs`); spike `forge4.rs`, `forge5.rs` as sketches | — |

## Tasks
1. [x] **`nacre-revocation`: two accessors** (`src/ocsp/response.rs`).
   - `pub fn delegated_responder(&self, issuer: &[u8]) -> Result<Option<Vec<u8>>, Error>` returns the DER of the delegate that `status` would accept: same `names`/`delegate()` checks, validity at `producedAt` included. It returns `None` when the `ResponderID` names the issuer, and `Err(UnauthorizedResponder)` when nobody qualifies. `delegate()` returns the certificate's DER with its key, so the two cannot diverge.
   - `pub fn archive_cutoff(&self, certificate: &[u8], issuer: &[u8]) -> Result<Option<SystemTime>, Error>` returns the `1.3.6.1.5.5.7.48.1.6` extension of the single response `single()` finds. A missing or undecodable value gives `Ok(None)`.
   - The crate rustdoc (`src/lib.rs:13-25`) names both. `status` is unchanged.
   - Test `delegate_and_archive_cutoff_are_exposed` in `tests/ocsp_status.rs`:
     - `corpus/ocsp-openssl/delegated-good.der` gives `Some(responder.der)`;
     - `good.der` gives `None`;
     - `archive_cutoff` on `good.der` gives `Ok(None)`.

     The `Some` path of `archive_cutoff` bites in task 6.
2. [x] **Forging helpers** (`crates/nacre-validate/tests/support/forge.rs`, and `der` in `[dev-dependencies]` gains `derive`).
   - `Role::OcspResponder`, with key usage `digitalSignature`, EKU `1.3.6.1.5.5.7.3.9` and `ocsp-nocheck` `1.3.6.1.5.5.7.48.1.5`.
   - `ocsp(certificate, issuer, key, responder, embed: Option<&Certificate>, produced: Time, revoked: Option<Time>, archive_cutoff: Option<Time>) -> Vec<u8>`. It is ECDSA P-256 over the `tbsResponseData` DER, with `nextUpdate` `produced` + 7 days, as the spike's `forge5.rs:221-237`. The `CertID` comes from `OcspRequest::new`, decoded with `asn1::OcspRequest`. Group the arguments in a struct if clippy's argument count requires it.
   - `with_dss` gains an `ocsps` sibling (`with_dss_ocsps(pdf, certs, crls, ocsps)`, `with_dss` calling it with none).

   No test of its own: tasks 5, 6 and 8 use them.
3. [x] **A: SKI on timestamp paths, under both presets** (`validate.rs`).
   - The loop at `:428-435` becomes `fn ca_without_key_identifier(path: &CertificatePath) -> Option<usize>`, the depth of the first CA below the anchor (depth ≥ 1) without SKI. `after_revocation` maps it to `Defect::CaKeyIdentifierMissing`, as today.
   - `proven_time` returns `None` when it finds one on the TSA path, right after `build_path`.
   - `proven_time`'s rustdoc and the `docs/security/attacks/cms.md` rule text (`:26`) name it.
   - Test `tsa_ca_without_key_identifier_proves_no_time` in `tests/revocation.rs`. A `Pki` signer is stamped at 08:00 by a TSA under a CA issued by the root `WithoutKeyIdentifier`, the token carrying `[tsa, ca]`. The `/DSS` holds the CA's CRL (TSA not revoked), the root's CRL and the intermediate's CRL revoking the signer at 09:00.
     - Both presets give `REVOKED_NO_POE` and `best_signature_time == None`.
     - Control: the same with a CA that has SKI gives `TOTAL_PASSED` with the stamp time. Without it, a fixture that broke the TSA path some other way would pass for the wrong reason.
4. [x] **B: the twelfth switch** (`policy.rs`, `revocation.rs`, `validate.rs`).
   - `pub judge_issuer_of_revoked_data: bool`: `true` in `strict()`, `false` in `dss()`. Its rustdoc follows ADR-0030, and the `dss()` warning (`policy.rs:104-111`) adds "revocation data saying revoked, trusted from a CA or responder out of its validity".
   - `judge_path` takes `policy: &ValidationPolicy` in place of `expired_certs_on_crl: bool`, from both callers (`validate.rs:371-379`, `:479-487`). It keeps each pair's deciding `Verdict`.
   - In the issuer pass, a depth whose verdict has `revoked.is_some()` is skipped when the switch is off. Such a revocation is always after `time`, since an earlier one returned `Revoked`. The skip covers that depth's CA and, after task 5, its delegate.
   - Test `issuer_of_revoked_data_switch` in `tests/revocation.rs`, built like `issuer_out_of_validity_is_revocation_out_of_bounds` (`:854-918`): a CA under the root valid until 2026-10-22T12:00, a B-T stamped at 08:00, control date 2026-10-23.
     - v3: the CA's CRL of 10:00 revokes the signer at 09:00. `strict()` gives `IssuerOutOfBounds { depth: 0 }`; `strict()` with the switch off gives `TOTAL_PASSED`.
     - v5: the root's CRL revokes the CA at 09:00, and the CA's CRL is "good". Switch off, still `IssuerOutOfBounds { depth: 0 }`.
5. [x] **C: a delegated responder judged at the control date, under both presets** (`revocation.rs`).
   - `Item::verdict` calls `delegated_responder` and stores the delegate's validity in `Verdict` as `responder: Option<(SystemTime, SystemTime)>`, keeping `Copy`. An unreadable delegate DER drops the item, as an unreadable response is dropped.
   - The issuer pass also requires that window to hold `issuers_at` at every depth, including a delegate of the anchor; otherwise `IssuerOutOfBounds { depth }`. Task 4's switch-off skip applies to it too. `proven_time` passes `issuers_at = None`, so a TSA path is unchanged.
   - Test `delegated_responder_out_of_validity` in `tests/revocation.rs`: a `Pki` B-T stamped at 08:00. The `/DSS` holds the intermediate's and root's CRLs of 10:00, plus a "good" OCSP response on the signer produced at 11:00 (it outranks the CRL), signed by a delegate of the intermediate, embedded.
     - With the delegate valid until 2026-10-22T12:00, both presets give `IssuerOutOfBounds { depth: 0 }`.
     - With the delegate valid until 2036, `TOTAL_PASSED` (e3-like control).
6. [x] **D: `archiveCutoff` under the eleventh switch** (`revocation.rs`, `policy.rs`).
   - `Item::verdict` sets `expired_from` for an OCSP response from `archive_cutoff`. The `within` gate stays as it is.
   - The rustdoc of `ignore_expired_certs_on_crl` and `judge_path` names both extensions, and the `dss()` warning adds "or an OCSP response trusted on its `archiveCutoff`".
   - Test `archive_cutoff_switch` in `tests/revocation.rs`, the OCSP twin of `expired_certs_on_crl_switch` (`:795-852`). The signer expires at 09:00 and is stamped at 08:00. The `/DSS` holds an intermediate-signed OCSP response of 10:00 with `archiveCutoff` 2026-01-01, plus the intermediate's and root's CRLs (the intermediate's covers the TSA).
     - `strict()` gives `Missing { depth: 0 }`, and switch off `TOTAL_PASSED`.
     - Switch off with `archiveCutoff` 2026-10-22T09:30 gives `Missing { depth: 0 }`.
7. [x] **Isolation, catalogue, ADR link, docs.**
   - `SWITCHES` (`tests/policy.rs:317`) lists twelve, adding `judge_issuer_of_revoked_data`.
   - `docs/security/attacks/revocation.md`:
     - the "Jugement" intro (`:86`) covers `archiveCutoff`, the exemption and the delegate;
     - row `:98` covers OCSP `archiveCutoff`;
     - new rows: v3 (`` `dss()` (`judge_issuer_of_revoked_data`) ``), the expired delegate (`aucune`), each with its tests;
     - check 4 of the OCSP list (`:54`) and the "Hors de ce fichier" note (`:108`) say the delegate is now judged at the control date by `nacre-validate`, its own revocation still not.
   - `docs/security/attacks/cms.md`: a row for the SKI-less CA on a TSA path (`aucune`).
   - No cell may backtick a file of `tests/corpus/attacks/` (the contract of `pades.md:24`).
   - ADR-0029 frontmatter: `superseded-by: [0030]`; status and body unchanged.
   - Rustdoc: `nacre-validate/src/lib.rs:53-62` and `validate_with_policy` (`validate.rs:115-139`) name ADR-0030, the twelfth switch and the two rules of tasks 3 and 5.
   - Run `tests/policy.rs` as it stands; both isolation tests must pass.
8. [x] **Conformance tests** in `tests/conformance.rs`, one per family, forged at run time from the spike:
   - `tsa_ca_without_key_identifier_policy` (k1): `REVOKED_NO_POE` in DSS and under both presets.
   - `issuer_of_revoked_data_policy` (v3, v5):
     - v3 gives `PASSED` in DSS and under `dss()`, `REVOCATION_OUT_OF_BOUNDS_NO_POE` under `strict()`;
     - v5 gives `REVOCATION_OUT_OF_BOUNDS_NO_POE` in DSS and under both presets.
   - `delegated_responder_policy` (e2, e3):
     - e2 gives `REVOCATION_OUT_OF_BOUNDS_NO_POE` in DSS and under `dss()`, `GENERAL_FAILURE` under `strict()`;
     - e3 gives `PASSED` in DSS and under `dss()`.
   - `archive_cutoff_policy` (e4, e5):
     - e4 gives `OUT_OF_BOUNDS_NOT_REVOKED` in DSS and under `dss()`, `OUT_OF_BOUNDS_NO_POE` under `strict()`;
     - e5 gives `PASSED` in DSS and under `dss()`, `GENERAL_FAILURE` under `strict()`.

   Start the bench (`conformance/README.md`), run `cargo test -p nacre-validate --all-features --test conformance -- --ignored`, then `podman compose -f conformance/compose.yaml down`. A DSS verdict that differs from the spike's stops the run and goes to the lead.

## Scene viewpoints
—

## Run interdicts
- The diff is empty outside these paths:
  - `crates/nacre-validate/` and `docs/security/attacks/`;
  - `crates/nacre-revocation/src/ocsp/response.rs`, `crates/nacre-revocation/src/lib.rs` and `crates/nacre-revocation/tests/ocsp_status.rs`;
  - `docs/decisions/0029-…md`, frontmatter `superseded-by` only;
  - ADR-0030, the research and this plan. The implementer does not change ADR-0030's decision.

  In particular, these stay untouched: `crates/nacre-pdf/`, `crates/nacre-core/`, `crates/nacre-conformance/`, `crates/nacre-pades/`, `conformance/`, `.github/`, `docs/stories.md`, and the bodies of ADR-0026 to ADR-0029.
- `OcspResponse::status` and `Crl::status` keep their behaviour. `crates/nacre-revocation/tests/{attacks.rs, ocsp_attacks.rs, hostile.rs}` and their corpora end with an empty diff.
- `strict()` keeps every verdict it gives today, except where it gets stricter (tasks 3 and 5). Every existing test passes unchanged; `SWITCHES` is the only edit to an existing test.
- Out of scope: no level is computed (`report.level()` stays `None`), document timestamps stay ignored, and `FRESHNESS_TOLERANCE` and xref reading do not change (s18, s47, s42, s44). No attack file is added to `tests/corpus/attacks/`.
- No new dependency in either crate. No `[workspace.dependencies]`, no `Cargo.lock`, no `cms` or `x509-tsp` crate. The only manifest edit is `derive` on `nacre-validate`'s dev `der`.
- No public TSA, no online DSS demo, no `NACRE_DSS_URL` other than local. Never stop `patelle-dss`, never touch `omniroute`, and leave the bench down at the end.

## The pivot
Everything rests on one reading of DSS's revocation-acceptance rule: **the issuer of a pair's deciding data** is its CA or its delegated responder. It must be within its validity at the control date, unless the data says "revoked" and the twelfth switch is off. Ways it could be wrong:
- **The exemption's scope.** It was seen on a signer revoked after its proof of existence by an expired CA (v3), with v5 as the control. It was not seen on a revoked CA at depth > 0, on a `certificateHold`, or on data from a delegate. The plan skips the whole depth, CA and delegate alike. Compare with DSS once s18's campaign forges one.
- **Delegates judged at every depth, the anchor's included.** Only an intermediate's delegate was forged (e2, e3). DSS skips only trusted certificates, and a delegate is not one, but no case shows it.
- **`archiveCutoff` read only from the matching `singleExtensions`, non-critical.** A responder placing it in `responseExtensions`, or marking it critical, is refused or ignored. DSS (BouncyCastle) may read it elsewhere; e4/e5 only show the RFC placement.

## Files touched
- `crates/nacre-revocation/`: `src/ocsp/response.rs`, `src/lib.rs` and `tests/ocsp_status.rs`.
- `crates/nacre-validate/`:
  - `src/{policy.rs, revocation.rs, validate.rs, lib.rs}`;
  - `tests/{revocation.rs, policy.rs, conformance.rs, support/forge.rs}`;
  - `Cargo.toml` (dev `der` features).
- `docs/security/attacks/{revocation.md, cms.md}`.
- `docs/decisions/0029-misplaced-xref-and-expired-certs-on-crl-switches.md`, frontmatter only.
- Already written by the planner: `docs/decisions/0030-issuer-of-revoked-data-switch-and-archive-cutoff.md` and the research.

## Test strategy
The rules live at the service layer: `nacre-validate` for the judging, and `nacre-revocation` for the two accessors. There is no adapter. 9 new automated tests, within the budget of 25:

| Task | Tests | Bites when |
| --- | --- | --- |
| 1 | 1 | the accessor returns the wrong certificate, or one for an issuer-signed response |
| 3 | 1 | the SKI check is left out of `proven_time` (the control proves the fixture gives a time otherwise) |
| 4 | 1 | the skip is missing, applies with the switch on, or skips depths whose data is "good" (v5) |
| 5 | 1 | the delegate's validity is not checked at the control date, or is checked at `producedAt` only |
| 6 | 1 | `archiveCutoff` is ignored when off, honoured when on, or honoured past `notAfter`; it also bites on `archive_cutoff` returning `None` |
| 8 | 4 | DSS's verdict per family, under `--ignored` on the bench |

Changed, not new: `SWITCHES`. Rerun as they stand: `each_switch_changes_only_what_the_catalog_names` and `dss_opens_only_what_the_catalog_marks`. They do not bite on switches 11 and 12, since no attack file has their shapes; the bite is in the tests of tasks 4 and 6.

Each task's tests run alone after it. The full suite and clippy run once at the end, through `po-run --story s46-dss-parity-3`: `cargo test --workspace`, then the `Typecheck` command.

Visual checks: none (`Surface: endpoint`).

## Done when
- AC1 to AC6 hold, and the conformance tests of task 8 pass on the bench, which is stopped afterwards.
- `cargo test --workspace` and clippy pass through `po-run`.
- The review leaves no open critical finding.
- The story lands as one commit through a pull request.
