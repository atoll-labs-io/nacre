---
validated: yes
---
# Plan — s18-validate-level

[Story](../stories.md) · [Research](../research/s18-validate-level.md)

Branch `story/s18-validate-level`. Read `docs/research/s18-validate-level.md` first, its spike tables especially; this plan builds on it without repeating it.

## Technical choice (settled)
Spike 5 found two `dss()` divergences that only a new switch settles without making `strict()` laxer. On 2026-10-24 the person chose, so that `strict()` does not get laxer (`docs/decisions-log.md`; ADR-0031, `accepted`):
- **the anchor's delegated OCSP responder** (a6–a8): **R1**, a thirteenth switch `judge_anchor_delegated_responder`, on in `strict()`, off in `dss()`. Turned down: R2, the twelfth switch widened; R3, following DSS under both presets;
- **critical OCSP extensions** (c2–c6, u1–u3): **C1**, a fourteenth switch `refuse_critical_ocsp_extensions`, on in `strict()`, off in `dss()`. Turned down: C3, following DSS under both presets; C2, the eleventh switch widened to `archiveCutoff`, which leaves u1 and u2 apart.

Tasks 6 and 7 implement R1 and C1. The lead widened `Owns` to `crates/nacre-revocation/`, `docs/security/attacks/` and ADR-0030's file; complexity is 5. The third family, a `certificateHold` before the proof (H), is a DSS rule under both presets, so it is task 5 and needs no choice.

## Story
- AC1: the s06, s08, s11 and s12 files give `PAdES-BASELINE-B`, `-T`, `-LT` and `-LTA` with `TOTAL_PASSED`, under both policies.
- AC2: the level follows ADR-0025's rule (accepted).
  - ESS `signingCertificate` v1 or v2 is required.
  - `signingTime`, or no `/M`, gives PAdES-BES.
  - CMS revocation data does not count.
- AC3: a valid document timestamp is a proof of existence for `best_signature_time`. An invalid one proves nothing and leaves the level as it is.
- AC4: `conformance/campaign/` runs under `dss()` on every corpus. Indication, sub-indication, level and signature count are identical to DSS, and a single difference fails the campaign.
- AC5: under `strict()`, each difference is named by the strict rule that explains it; an unexplained one fails.
- AC6: DSS's XML reports are kept.

The story note now names the three families of spike 5 and both switches (`docs/stories.md`, lead, 2026-10-24).

## Reuse

| New code | Rung that holds | Why each rung above fails |
| --- | --- | --- |
| Level types | `SignatureLevel`, `SignatureForm`, `SignatureProfile`, `ValidationReport::*(…, level)` (`crates/nacre-core/src/report.rs:94-177`) | — |
| Setting the level | a `pub(crate) fn with_level` rebuilding the report from `indication()` and `sub_indication()` | `ValidationReport` has no setter, and `nacre-core` is outside `Owns` |
| Level rule, `src/level.rs` | new code | nothing reads a level from a file; `nacre_conformance::level` only parses DSS's name |
| Signed attributes | `SignerInfo::signed_attrs`, `SignedAttributes::attributes()` (`crates/nacre-cms/src/model.rs:201`, `:351`) | — |
| Issuer walk for coverage | `Node`, `signed_by` (`src/chain.rs:269`, `:541`), made `pub(crate)` | — |
| "Is this pair covered" | `RevocationPool` and its cached `verdict` (`src/revocation.rs:169-220`) | — |
| Document-timestamp proof | `signed_bytes`, `nacre_tsp::verify_token` (`crates/nacre-tsp/src/token.rs:71`), and `proven_time` (`src/validate.rs:455-485`) taking certificates and an imprint | — |
| `/DSS` before a revision | `Dss::read` on `Document::parse_with_options(pdf.get(..end)?, …)`, as `revisions.rs:150` does | — |
| Hold verdict | `Verdict::hold` (`revocation.rs:151`) and `SubIndication::TryLater` (`nacre-core/src/report.rs:87`) | — |
| Anchor-responder skip | the issuer pass of `judge_path` (`revocation.rs:319-342`) | — |
| Reading a status whatever the criticality | `OcspResponse::status` (`crates/nacre-revocation/src/ocsp/response.rs:143-192`) split around its `critical` calls (`:156-157`) | `status` must keep refusing (`tests/ocsp_attacks.rs:96-103`), and `nacre-validate` cannot reparse the response |
| OCSP builder in tests | `forge::ocsp` (`tests/support/forge.rs:322`), given a reason and critical extensions | — |
| Field names from DSS's JSON | `serde_json = "1"`, a new **dev**-dependency (ADR-0009; already in `nacre-conformance`) | `SignatureVerdict` has no field name, and `nacre-conformance` is outside `Owns` |
| Strict explanations | `SWITCHES` (`tests/policy.rs:317`), moved to `tests/support/mod.rs` | a hand-written table from defect to switch would drift |
| `conformance/campaign/run.sh` | a few lines of `sh` | AC4 names `conformance/campaign/` as the launcher |
| Bench cases | `tests/support/forge.rs`, extended; the spike bins `forge`..`forge10` are working sketches (`/home/lecrabe/.claude/jobs/4fb763d0/tmp/s18-spike3/src/bin/`) | — |

## Tasks
1. [x] **Forging helpers**, in `tests/support/forge.rs`:
   - `document_timestamp(pdf, tsa)`, as `crates/nacre-pades/src/archive.rs:16` does;
   - `signed_with`, with options for `/SubFilter`, `/M` (absent allowed), `signingTime`, the ESS attribute (v2, v1 or none), CMS CRLs and a TSA. It builds the `SignerInfo` from `SignedAttributes::from_attributes`, since `sign_detached` always writes ESS v2 (`nacre-cms/src/sign.rs:86-93`);
   - `ocsp` (`:322`) gains a revocation reason, and `archiveCutoff` or another extension placed in the single or the response extensions, critical or not.

   No test of its own: the tasks below use them.
2. [x] **Form, B, BES and T**: a new `src/level.rs`, with `fn level(…) -> Option<SignatureLevel>`. It runs for **every** listed signature, defective ones included, from its dictionary, its CMS (`SignedData::from_der`, unverified) and the later revisions.
   - The form comes from `/SubFilter`, as ADR-0025 says. A missing or unreadable CMS gives `None`.
   - PAdES without ESS (`…16.2.12` or `…16.2.47`) gives `None`. PAdES with `signingTime`, or with no readable `/M`, gives `ExtendedBes`. PKCS7 never gives BES (l15, n12, p05b).
   - T comes from a signature-timestamp attribute or from a document timestamp in a later revision, valid or not. PKCS7 climbs the same way.
   - `validate_with` applies `with_level` to each result.
   - `/DSS` is read with or without anchors (`validate.rs:233-237`).

   Tests, in a new `tests/level.rs`:
   - (a) a table on committed files:
     - `chain/chain-cms.pdf` gives PAdES B;
     - `attacks/byterange-overlap.pdf` gives B with `TOTAL_FAILED`;
     - `signed-twice-pyhanko.pdf` gives PKCS7-T twice;
     - `signed-lta-pyhanko.pdf` gives LTA, once task 3 lands;
     - `attacks/subfilter-unsupported.pdf` gives `None` under `dss()`;
   - (b) `signingTime` gives `ExtendedBes`, and PKCS7 with `signingTime` gives PKCS7-B;
   - (c) no ESS gives `None`, and ESS v1 gives B;
   - (d) B followed by a document timestamp gives T.
3. [x] **LT and LTA**, by ADR-0025's rule.
   - The chains to cover:
     - the signer's;
     - every signature timestamp's;
     - every document timestamp's in a revision before the last `/DSS`;
     - with no signature timestamp, that of the first document timestamp after the signature.
   - Each chain is walked through the CMS, token and `/DSS` certificates, by name and verified signature. The walk stops at a self-signed certificate, with at most 8 pairs.
   - A pair is covered when a pool built from the final `/DSS` `/CRLs` and `/OCSPs` alone gives it a verdict, expired or not. That pool reads OCSP as the policy says (task 7). One pool serves the file.
   - LTA: a later document timestamp whose preceding revision's `/DSS` gives LT by the same rule.

   Tests, offline with `Pki` (`tests/revocation.rs`):
   - (a) T + `/DSS` without the intermediate's CRL gives T, and with it LT;
   - (b) the same CRLs in CMS `crls` and no `/DSS` give T;
   - (c) B + `/DSS` covering the signer only + a document timestamp gives T (r1); covering its TSA too gives LTA (r2).
4. [x] **Document timestamps as proof of existence (AC3).** A document timestamp in a revision after the signature (at most 16) counts towards the best-signature-time when all of these hold:
   - its `/ByteRange` passes `signed_bytes`, with `ETSI.RFC3161` allowed for this caller alone;
   - `proven_time`, generalised to a token, its certificates and an imprint, accepts it over the SHA-256 of its signed bytes. That includes s46's SKI rule (`validate.rs:479-481`).

   The best-signature-time is the earliest such time. Tests:
   - B + a valid document timestamp, signer revoked after its `genTime`, gives `TOTAL_PASSED` with that `genTime` (n13, k4);
   - the same with the imprint zeroed gives `REVOKED_NO_POE`.
5. [x] **H — a hold before the proof gives `TRY_LATER`, under both presets** (a DSS rule, ADR-0026).
   - `RevocationDefect::OnHold { depth, date }` reports `INDETERMINATE` / `TRY_LATER` at any depth.
   - `judge_path` returns it instead of `Revoked` when the deciding verdict is a hold dated at or before `time` (`revocation.rs:312-316`).
   - `every_revocation_defect_has_its_report` (`:353`) gains its row.

   Test in `tests/revocation.rs`: a hold before the stamp on the signer, and one on the intermediate, give `TRY_LATER` under both presets (h2, h11b).
6. [x] **R — the thirteenth switch** (choice R1).
   - `ValidationPolicy::judge_anchor_delegated_responder`, on in `strict()` and off in `dss()`, with its rustdoc.
   - Off, the responder check (`revocation.rs:336-340`) skips a depth whose issuer is the anchor (`depth + 1 == last`).

   Tests:
   - in `tests/policy.rs`, offline: a CA whose only data is a response by an expired root delegate gives `TOTAL_PASSED` under `dss()` and `REVOCATION_OUT_OF_BOUNDS_NO_POE` under `strict()` (a7);
   - `anchor_delegated_responder_policy` in `tests/conformance.rs` (`#[ignore = "conformance"]`), a7 on the bench, beside `delegated_responder_policy`: every switch has its conformance test (`docs/security/attacks/pades.md:24`).
7. [x] **C — the fourteenth switch** (choice C1).
   - `OcspResponse::status_ignoring_critical_extensions(&self, certificate, issuer, at)` does what `status` does without its two `critical` calls. `status` is unchanged.
   - `ValidationPolicy::refuse_critical_ocsp_extensions`, on in `strict()` and off in `dss()`.
   - `RevocationPool::from_der` takes that flag. `Item::verdict` and the source's answer call the new method when it is off.

   Tests:
   - one in `crates/nacre-revocation/tests/ocsp_status.rs`: a response with a critical unknown single extension is refused by `status` and read by the new method;
   - one in `tests/policy.rs`, offline: u1's shape gives `TOTAL_PASSED` under `dss()` and `CERTIFICATE_CHAIN_GENERAL_FAILURE` under `strict()`;
   - `critical_ocsp_extensions_policy` in `tests/conformance.rs` (`#[ignore = "conformance"]`), u1 on the bench.
8. [x] **Existing assertions, switches and docs.**
   - `tests/validate.rs:124` and `:385` assert PAdES B, and the `passed` helper (`tests/revocation.rs:204-210`) drops its `None`.
   - `confront` (`tests/conformance.rs:82-118`) also asserts that Nacre's level equals DSS's, and its doc drops "no level before s18".
   - `SWITCHES` has 14 entries. ADR-0031 is `accepted` (written at plan time); ADR-0030's frontmatter gains `superseded-by: [0031]`, its body untouched.
   - `docs/security/attacks/revocation.md`, in French like the rest of the file:
     - OCSP step 3 (`:53`): under `nacre-validate`, `dss()` reads the response through the new method (`refuse_critical_ocsp_extensions`); `status` still refuses;
     - « Jugement de la révocation » (`:86`): the anchor's delegate is exempt under `dss()` (`judge_anchor_delegated_responder`), and a hold at or before the best-signature-time gives `TRY_LATER` under both presets;
     - three rows in its table (`:88-101`): the hold (task 5, « aucune »), the anchor's delegate (task 6) and the critical extension (task 7), the last two « `dss()` (`<switch>`) », each naming its tests.
   - The rustdoc covers the level, document timestamps and tasks 5–7: `src/lib.rs`, `validate.rs:34-152`, `report.rs:24-34` and `:152-154`, `policy.rs:1-13` and `:112-121`, and `revocation.rs:35-62` and `:242-267`.
9. [x] **Campaign**: `tests/campaign.rs` (`#[ignore = "conformance"]`), plus `conformance/campaign/README.md` and `run.sh`.
   - Cases:
     - every `*.pdf` under `crates/nacre-validate/tests/corpus/`, `crates/nacre-pdf/tests/corpus/{hostile,real}/`, and `conformance/corpus/` once it exists (s19);
     - bench cases forged at run time, one per row of the research's tables: spike 3 (l, c, n, p, q, r, s, t), spike 4 (k, o, e, v) and spike 5 (h, w, a, p, c, u). That includes the lead's five: h1/h4, w1, a7/a8, c1–c6, p4;
     - no x case (s47);
     - root-issued data forged after the bench's `root.crl` (research, traps).
   - Each case goes to DSS once. Nacre judges it with the bench root, `SystemTime::now()` and the bench `Fallback` source, under `dss()` and under `strict()`.
   - Each signature gives one row, matched to DSS by field name in the kept JSON: indication, sub-indication and level. Each file also gives one count. DSS answering an error and Nacre returning `Err` count as agreement; any other pair is a difference.
   - Under `dss()`, any difference fails the test.
   - Under `strict()`, a difference is explained by the smallest set of `SWITCHES` that, turned off from `strict()`, gives DSS's verdict (singles first, then pairs). A difference no such set explains fails the test.
   - Both tables go to `<reports_dir>/campaign-dss.md` and `campaign-strict.md`. `run.sh` runs `cargo test -p nacre-validate --all-features --test campaign -- --ignored` against a started bench. It then copies the tables and the `campaign-*.xml` DSS reports into `conformance/campaign/reports/`.

   Run it on the bench (`conformance/README.md`).
   - A difference under `dss()` is fixed in `nacre-validate` when an existing switch covers its shape or DSS applies the rule under both presets.
   - Any other difference stops the run and goes to the lead.

   Commit `conformance/campaign/reports/` (AC6), then stop the bench with `podman compose -f conformance/compose.yaml down`.

## Scene viewpoints
—

## Run interdicts
- The diff is empty outside these paths:
  - `crates/nacre-validate/` and `conformance/campaign/`;
  - `crates/nacre-revocation/src/ocsp/response.rs` and `crates/nacre-revocation/tests/ocsp_status.rs`, for task 7 only;
  - `docs/security/attacks/revocation.md`, for task 8 only;
  - the research, this plan, ADR-0025, ADR-0031, and the frontmatter link `superseded-by` of ADR-0030.

  In particular, these stay untouched: `crates/nacre-pdf/` (s47), `crates/nacre-conformance/`, `crates/nacre-core/`, `crates/nacre-pades/`, `.github/workflows/`, `conformance/pki/`, `conformance/compose.yaml`, `docs/stories.md`, and the bodies of ADR-0026 to ADR-0030.
- The person chose R1 and C1: tasks 6 and 7 follow them, and no other option is implemented.
- `OcspResponse::status` keeps its behaviour: `critical_single_extension_is_rejected` passes unchanged.
- `strict()` keeps every verdict it gives today, except these:
  - AC3's proof of existence (n13, k4 pass);
  - task 5 (`REVOKED_*_NO_POE` becomes `TRY_LATER` for a hold, same indication).

  `revisions.rs`, `FRESHNESS_TOLERANCE` and both `hostile.rs` keep their behaviour.
- `ChainDefect::report` and `RevocationDefect::report` keep level `None` (`chain.rs:161`, `revocation.rs:53`).
- No case is left out of the campaign, and no difference is allowed under `dss()`.
- No `[workspace.dependencies]`, no `Cargo.lock`, no `cms` or `x509-tsp` crate. `serde_json` goes in `[dev-dependencies]` only.
- No public TSA, no online DSS demo, and no `NACRE_DSS_URL` other than local. Never stop `patelle-dss`, and never touch `omniroute`. The bench is down at the end.

## The pivot
`report.level()` and every `dss()` verdict follow what 189 bench cases and 79 committed files showed of DSS 6.5.1. Ways that could be wrong:
- **R's exemption, from three cases of one shape**: a "good" response about a CA one level below a self-signed root. It was not seen on a revoked CA, nor under a non-self-signed anchor. Compare the campaign's a rows.
- **C's leniency, seen on three OIDs.** DSS may still refuse a critical extension it knows and rejects, such as a nonce mismatch. Compare the u rows, and add one per OID the corpus holds.
- **The bench artefact.** A CRL DSS fetched for one certificate also judges another of the same issuer, which Nacre's per-pair source does not do. A real file whose issuer published a later CRL dropping a revoked serial would differ.
- **LT through a delegated OCSP response**, PKCS7 without ESS, and several document timestamps around several `/DSS` were not observed. Compare `campaign-dss.md` with DSS's `SignatureFormat`.

## Files touched
- `crates/nacre-validate/src/`: `level.rs`, `lib.rs`, `validate.rs`, `report.rs`, `chain.rs`, `revocation.rs` and `policy.rs`; and `crates/nacre-validate/Cargo.toml`.
- `crates/nacre-validate/tests/`: `level.rs`, `campaign.rs`, `policy.rs`, `validate.rs`, `revocation.rs`, `conformance.rs`, and `support/{mod.rs, forge.rs}`.
- `conformance/campaign/`: `README.md`, `run.sh` and `reports/`.
- `docs/decisions/0025-level-is-structural-as-dss.md` and `0031-anchor-responder-and-critical-ocsp-extension-switches.md`; the frontmatter of `0030-…`.
- Task 7: `crates/nacre-revocation/src/ocsp/response.rs` and `crates/nacre-revocation/tests/ocsp_status.rs`.
- Task 8: `docs/security/attacks/revocation.md`.

## Test strategy
The rules live at the service layer: `nacre-validate`, plus `nacre-revocation` for the new reading method. There is no adapter. 16 new automated tests, within the budget of 25:

| Task | Tests | What they are |
| --- | --- | --- |
| 2 | 4 | (a) to (d); the committed-file table counts once |
| 3 | 3 | (a) to (c) |
| 4 | 2 | a valid and an invalid document timestamp; without the imprint check, the second would pass |
| 5 | 1 | hold on the signer and on the CA, both presets |
| 6 | 2 | a7 offline, both presets; a7 on the bench (`conformance.rs`) |
| 7 | 3 | the new method in `nacre-revocation`; u1 offline, both presets; u1 on the bench (`conformance.rs`) |
| 9 | 1 | the campaign, with DSS as the judge |

Changed: the three assertions of task 8, `confront`, and one row of `every_revocation_defect_has_its_report`. Rerun as they stand: `each_switch_changes_only_what_the_catalog_names` and `dss_opens_only_what_the_catalog_marks`. They cover the new switches once they are in `SWITCHES`; the attack corpus holds no case for them, so their catalogue stays as it is.

The campaign and `conformance.rs` (with its two new tests) run only with `--ignored`, on the bench at execute and in CI. The full suite and clippy run once at the end, through `po-run --story s18-validate-level`.

Visual checks: none (`Surface: endpoint`).

## Done when
- The campaign passes under `dss()` with no difference, and under `strict()` with every difference explained. Its reports are committed.
- AC1 holds on the bench's B, T, LT and LTA cases, under both policies.
- Business tests and `cargo test --workspace` are green, and clippy passes, through `po-run`.
- The review leaves no open critical finding.
- The story lands as one commit through a pull request.
