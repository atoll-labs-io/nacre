# Research — s18-validate-level

[Story](../stories.md)

## Structuring facts
- **The story's note "s18 ne les règle pas, elle les vérifie" is false for three more families.** Spike 5 ran on `fe2c586` (s46 landed), on 268 cases. Under `dss()`, 234 match DSS. The 34 that do not:
  - n13, k4: a document timestamp as proof of existence (AC3).
  - x1–x8c: xref recovery (s47; the campaign forges none of them).
  - **H** — a `certificateHold` at or before the best-signature-time. DSS gives `TRY_LATER` at any depth; Nacre gives `REVOKED_NO_POE` or `REVOKED_CA_NO_POE` under both presets (`src/revocation.rs:312-316`). Cases h2, h3, h6, h11b, h13.
  - **R** — the trust anchor's delegated OCSP responder, out of its validity at the control date. DSS gives `TOTAL_PASSED`; Nacre gives `REVOCATION_OUT_OF_BOUNDS_NO_POE` under both presets (`revocation.rs:336-340`, "the anchor's included" at `:260`). Cases a6, a7, a8.
  - **C** — an OCSP response with a critical extension, whatever its OID (archiveCutoff, crlReferences, unknown). DSS reads it; `nacre-revocation` refuses it (`crates/nacre-revocation/src/ocsp/response.rs:156-157`, `crl.rs:154-162`). Cases c2, c4, c5, c6, u1–u3.
  - Five bench artefacts (h5, h9, h10, h11, a4), see the traps.
- **H is a DSS rule; R and C are rules only Nacre applies.**
  - H keeps the same indication, so it goes to both presets (ADR-0026).
  - Following DSS on R or C would make `strict()` laxer, so each needs a switch or the person's choice. ADR-0031 is drafted `proposed`.
  - C also needs `crates/nacre-revocation/`, which is outside `Owns`.
- **The level is structural, and Nacre reports none.** Every report is built with level `None` (`crates/nacre-validate/src/report.rs:162-163`, `:198`, `:211`, `:216-219`, `:226`). Document timestamps are skipped (`src/validate.rs:186-188`).

## Story
The PAdES level under both policies, and the campaign.
- AC1: s06/s08/s11/s12 → B/T/LT/LTA, `TOTAL_PASSED`.
- AC2: the structural rule of ADR-0025 (accepted), ESS v1 included.
- AC3: a valid document timestamp is a proof of existence for `best_signature_time`. An invalid one proves nothing and leaves the level as it is.
- AC4: `conformance/campaign/` runs under `dss()` on every corpus, with no exclusion: `nacre-validate`, `nacre-pdf` hostile and real, `conformance/corpus/` once s19 lands, and bench cases. Indication, sub-indication, level and count are identical in 100 % of cases.
- AC5: under `strict()`, every difference is named by a strict rule; an unexplained one fails.
- AC6: DSS's XML reports are kept.

## Diagnostic — spike 5 (DSS 6.5.1, bench started and stopped 2026-10-24)
Scratch crate `/home/lecrabe/.claude/jobs/4fb763d0/tmp/s18-spike3`, outside the worktree. It holds bins `forge`..`forge10`. Verdicts are in `/home/lecrabe/.claude/jobs/4fb763d0/tmp/s18-run5/*.txt`, compared by `tools/cmp.py` (`cmp.out`).
- Nacre runs `validate_with_policy` with the bench root, `SystemTime::now()` and the bench `Fallback` source (`NACRE_SOURCE=1`). Without the source, every bench file with no `/DSS` reads `CERTIFICATE_CHAIN_GENERAL_FAILURE`.
- Every case of spikes 3 and 4 was re-forged on the fresh bench. Every family s46 shipped (k1, v3, v5, e2, e4, e5, o1–o3) now matches.

**Cases the lead asked for, and the probes around them** (all T are 5 days ago; forged CAs carry SKI and no CDP):

| # | Shape | `dss()` | `strict()` | DSS |
| --- | --- | --- | --- | --- |
| h1 / h4 | signer on hold 4 days ago, after the stamp (CRL / OCSP) | `TOTAL_PASSED` | same | same |
| h2 / h6 | signer on hold 6 days ago, before the stamp (CRL / OCSP) | `REVOKED_NO_POE` | same | **`TRY_LATER`** |
| h3 | B, signer on hold 1 h ago | `REVOKED_NO_POE` | same | **`TRY_LATER`** |
| h11b / h13 | CA on hold by the root 6 days ago (T) / 1 h ago (B), root CRL issued now | `REVOKED_CA_NO_POE` | same | **`TRY_LATER`** |
| h7 / h8 | B, hold then lifted by a later CRL / plain revocation 1 h ago | `TOTAL_PASSED` / `REVOKED_NO_POE` | same | same |
| h9b / h14 | CA revoked by the root 6 / 4 days ago, root CRL issued now | `REVOKED_CA_NO_POE` / `TOTAL_PASSED` | same | same |
| w1 | v3 + v5: signer and CA revoked 4 days ago, CA expired yesterday | `TOTAL_PASSED` | `REVOCATION_OUT_OF_BOUNDS_NO_POE` | `TOTAL_PASSED` |
| w2 / w3 | the same, root says CA good / signer good, CA revoked | `TOTAL_PASSED` / `REVOCATION_OUT_OF_BOUNDS_NO_POE` | `OUT_OF_BOUNDS` ×2 | same as `dss()` |
| a7 / a8 | CA's only data: OCSP by a root delegate expired 1 min ago, produced 3 min ago (T / B) | `REVOCATION_OUT_OF_BOUNDS_NO_POE` | same | **`TOTAL_PASSED`** |
| a6 | B, root delegate expired yesterday, produced 3 days ago | same | `GENERAL_FAILURE` (fresh) | **`TOTAL_PASSED`** |
| a2 / a5 | root delegate valid (controls) | `TOTAL_PASSED` | same | same |
| p4 / p5 | e2 with a proof of existence: intermediate delegate expired since / valid | `REVOCATION_OUT_OF_BOUNDS_NO_POE` / `TOTAL_PASSED` | same | same |
| p3 | the same delegate, expired, says revoked 4 days ago | `TOTAL_PASSED` | `REVOCATION_OUT_OF_BOUNDS_NO_POE` | `TOTAL_PASSED` |
| c0 / c1 / c3 | `archiveCutoff`, signer expired yesterday: single non-critical / response-level non-critical (B, T) | `OUT_OF_BOUNDS_NOT_REVOKED` / `GENERAL_FAILURE` ×2 | — | same as `dss()` |
| c2 / c4 | the same, single and critical (B / T) | `GENERAL_FAILURE` | — | **`OUT_OF_BOUNDS_NOT_REVOKED` / `TOTAL_PASSED`** |
| c5 / c6 / u3 | valid signer, critical `archiveCutoff` in a single or in the response extensions | `GENERAL_FAILURE` | same | **`TOTAL_PASSED`** |
| u1 / u2 | valid signer, critical unknown OID / `crlReferences`, single or response | `GENERAL_FAILURE` | same | **`TOTAL_PASSED`** |
| u*-noncritical / c8 | the same, non-critical; CRL with an unknown non-critical extension | `TOTAL_PASSED` | same | same |
| c7 | CRL with an unknown critical extension | `GENERAL_FAILURE` | same | same |

Hypotheses:
- "DSS gives `TRY_LATER` for a hold at or before the proof": kept by h2, h3, h6, h11b and h13. h1, h4 and h7 tried to refute it: a hold after the stamp, or a lifted one, passes in both.
- "DSS judges an anchor's delegate like an intermediate's": refuted. a7 and a8 pass in DSS, while p4 fails in both. Data newer than the bench's root CRL rules out the artefact below.
- "DSS refuses unknown critical OCSP extensions": refuted by u1. Every critical OCSP extension tried is read, while CRLs keep the rule (c7).
- "DSS skips a CA's revocation before the stamp" (h9, h10): refuted by h9b. The bench artefact below explains it.

**Level cases** (spike 3, re-forged; all `TOTAL_PASSED`):

| # | Structure | DSS |
| --- | --- | --- |
| r1 / r2 | B + `/DSS` (signer chain / + document TSA) + document timestamp | `-T` / `-LTA` |
| r3 | T + `/DSS` covering the signer only | `-T` |
| r4 / r5 | B + document timestamp + `/DSS` (all) / + another document timestamp | `-LT` / `-LTA` |
| r6 | B + document timestamp + `/DSS` (signer only) + document timestamp | `-T` |
| r7 / r8 | T + rogue document timestamp before / after `/DSS` (all) | `-T` / `-LTA` |
| q1 / q2 / q5 / q6 | T, `/DSS` data issued before or after the stamp | `-LT` |
| q3 / q4 | B + `/DSS` + document timestamp now / 2 days ago | `-LTA` |
| t1 / t2 | PKCS7 T + `/DSS` / + document timestamp | `PKCS7-LT` / `PKCS7-LTA` |
| l14, l15, n12, n12b, p05b | PKCS7 with or without `signingTime`, with or without `/M` | `PKCS7-B` |
| l05, l07, l16, n11, p05 | PAdES with `signingTime`, or with no `/M` | `PAdES-BES` |
| n09 / n10 / l36 | ESS v1 / EPES policy / no ESS | `-B` / `-B` / `PDF-NOT-ETSI` |

Kept: ADR-0025's rule fits every row, and every new case above (a2, a5, p4, p5 read `-T`: the TSA's data is fetched, not in the `/DSS`). BES applies to PAdES only.

Formats on the committed corpora: `-B` ×51, `-LTA` ×1, `PKCS7-T` ×2, `PDF-NOT-ETSI` ×1. No format is given for the ten unsigned files and the nine USF files.

## Current code
- `validate_with` (`src/validate.rs:154-292`):
  - parses, with `misplaced_xref` when the switch is off (`:162-172`);
  - lists fields, skipping document timestamps (`:174-190`), then runs `check` (`:198-206`);
  - qualifies the later revisions (`:228-232`);
  - reads `/DSS` only with anchors (`:233-237`);
  - then `Context::judge` (`:311-407`).
- `judge`:
  - builds the tokens (`:320-333`), then one pool from the CMS, token and `/DSS` data (`:336-345`);
  - takes the best-signature-time from signature timestamps only (`:347-350`), then the freshness window (`:354-355`);
  - runs `build_path` (`:363-373`), `judge_path` (`:375-385`) and `after_revocation` (`:413-449`).
- `proven_time` (`:455-485`): the TSA path at `at` under `Rules::STRICT`, `ca_without_key_identifier` (`:490`), then `judge_path(…, None, None, policy)`.
- `signed_bytes` (`:552-589`) refuses any `/SubFilter` outside `SUB_FILTERS` (`:25`) under the ninth switch (`:560-564`). `verify` (`:604-634`) keeps signer, certificates, CRLs, imprint and tokens, and drops the signed attributes.
- `judge_path` (`src/revocation.rs:268-344`):
  - the latest usable item decides each pair (`:279-311`). A revocation at or before `time` is `Revoked` whatever `hold` says (`:312-316`);
  - the issuer pass (`:319-342`) skips "revoked" data when the twelfth switch is off (`:324`). It checks the CA below the anchor (`:328-335`), then any delegated responder, the anchor's included (`:336-340`).
- `Item::verdict` (`:84-129`) calls `OcspResponse::status` (`:102`), which refuses any critical extension (`nacre-revocation/src/ocsp/response.rs:156-157`).
- `ValidationPolicy`: twelve booleans (`src/policy.rs:16-91`), `strict()` (`:95`), `dss()` (`:124`).

## Attachment points
- **Level.** A new `src/level.rs`, called in `validate_with` for every listed signature. A `pub(crate) fn with_level(self, Option<SignatureLevel>)` on `SignatureValidation` rebuilds the report from its own indication and sub-indication (`report.rs:151-243`). The attributes come from `SignerInfo::signed_attrs` (`crates/nacre-cms/src/model.rs:201`, `attributes()` at `:351`), read with `SignedData::from_der` even when the signature fails.
- **Document timestamps.**
  - `is_document_timestamp` (`validate.rs:509`) finds them, and `signed_bytes` gives their bytes, with `ETSI.RFC3161` allowed for that caller alone.
  - `nacre_tsp::verify_token` (`crates/nacre-tsp/src/token.rs:71`) and `proven_time` judge them.
  - `/DSS` before a revision is read by parsing `pdf.get(..end)`, as `revisions.rs:150` does.
- **LT coverage.** `RevocationPool` (`revocation.rs:169-240`) gains a `pub(crate)` query: does any item give a verdict for this pair. The issuer walk uses `Node` and `signed_by` (`chain.rs:269`, `:541`), made `pub(crate)`.
- **H.** `RevocationDefect` (`revocation.rs:36-48`, `#[non_exhaustive]`) gains `OnHold { depth, date }` → `TryLater` (`crates/nacre-core/src/report.rs:87`), returned at `:312-316` when `latest.hold`.
- **R.** The responder check (`revocation.rs:336-340`) skips `depth + 1 == last` with the new switch off.
- **C.** `nacre-revocation` gains a `status` variant that ignores criticality. `Item::verdict` calls it with the new switch off, the flag carried by `RevocationPool`.

## Verified interfaces
- `ValidationReport::{passed, failed, indeterminate}(…, Option<SignatureLevel>)` and `level()`, with no setter (`crates/nacre-core/src/report.rs:143-177`). `SignatureForm::{PAdES, Pkcs7}` (`:94`); `SignatureProfile::{BaselineB…BaselineLta, ExtendedBes}` (`:105-110`); `SignatureLevel { form, profile }` (`:126`).
- `nacre_conformance::level(format)` maps `PKCS7-B…LTA` to `Pkcs7` + `Baseline*`, and `PDF-NOT-ETSI` to `None` (`crates/nacre-conformance/src/report.rs:125-160`). `Dss::validate(name, pdf)` (`client.rs:60`) keeps `<reports_dir>/<name>.json` and `.xml`, under `$CARGO_TARGET_DIR/conformance` (`lib.rs:68`). `SignatureVerdict` carries no field name.
- `tests/policy.rs`: `SWITCHES: [Switch; 12]` (`:317`), used by `each_switch_changes_only_what_the_catalog_names` (`:484`) and `dss_opens_only_what_the_catalog_marks` (`:510`). The catalogue checks every switch name it cites (`:403-416`).
- `forge` (`tests/support/forge.rs`):
  - `Role::OcspResponder` (`:76-82`), `Extensions::WithoutKeyIdentifier` (`:92`), `issue_with` (`:215`);
  - `crl` (`:244`), `crl_with_reasons` (`:259`), `crl_with_expired_certs_on_crl` (`:293`);
  - `ocsp(…, produced, revoked, archive_cutoff)` (`:322`), with no reason and no critical flag;
  - `ChainSigner` (`:398`), `ForgedTsa` (`:424`), `token` (`:444`);
  - `signed` (`:535`), `custom_signed` (`:543`, CMS from `sign_detached`: ESS v2 always, `nacre-cms/src/sign.rs:45-93`);
  - `patch` (`:568`), `resign` (`:583`), `with_dss` (`:613`), `with_dss_ocsps` (`:618`).
- `nacre_pades` writes document timestamps in `archive.rs:16` (`pub(crate)`).
- `confront` (`tests/conformance.rs:82-118`) compares Nacre's indication only, and DSS's level against a fixed profile.

## Traps
- **Bench artefact.** DSS applies a CRL fetched for one certificate to every certificate of the same issuer. Nacre's source answers each pair through that certificate's own CDP.
  - h5, h9, h10, h11: a forged CA, revoked or held in a root CRL older than the bench's `root.crl`. The TSA path makes DSS fetch that newer `root.crl`, and the CA then passes.
  - a4: the same CRL outranks the delegate's response.
  - Forged root-issued data must postdate the bench's `root.crl` (h9b, h11b, a7). The shape stays in the campaign; only the stale-CRL setup is avoided.
- `level() == None` is asserted at `tests/validate.rs:124` (s06 file, now PAdES B) and `:385` (chain corpus, B). The `passed` helper (`tests/revocation.rs:204-210`) serves B and T files alike. `ChainDefect::report` (`chain.rs:161`) and `RevocationDefect::report` (`revocation.rs:53`) stay level-free; `with_level` applies after them.
- `old_revocation_counts_unless_on_hold` (`tests/revocation.rs:582-608`) expects a stale hold to be `Missing`. H leaves that alone: freshness drops the item first.
- `critical_single_extension_is_rejected` (`crates/nacre-revocation/tests/ocsp_attacks.rs:96-103`) pins `status`'s refusal, so C must not change `status`.
- DSS orders signatures differently (`signed-twice-pyhanko`, `ssa-hidden-widget-shown`): match them by field name.
- The bench regenerates its keys at every start, so bench cases are forged at run time and never committed. Forged certificates carry no CDP, and a patched dictionary or trailer is re-signed (`forge::resign`).
- After AC3, n13 and k4 pass under `strict()` too: the freshness window applies only without a proof of existence (`validate.rs:354-355`).
- The coverage walk is bounded: ≤ 8 pairs per chain, ≤ 1 + 16 + 16 chains, against ≤ 256 pool items.
- No migration. About 190 bench cases keep about 5 MB of DSS XML.

## Open questions
- PKCS7 with `signingTime` and a timestamp, and PKCS7 without ESS, were not forged. `sign_detached` always writes ESS v2.
- LT through a delegated OCSP response, a non-self-signed anchor, and several document timestamps around several `/DSS`, beyond r5–r8.
- The bench artefact: should a CRL that the source fetched for one pair join the pool for every pair, as DSS does? This was observed only with an issuer whose later CRL drops a revoked serial.

## Complexity
Story 4 → **5**. The level, AC3 and the campaign are a 4 on their own. Spike 5 adds:
- one DSS rule (H);
- two switches (R, C), waiting for the person;
- a public method in `nacre-revocation`, outside `Owns`.

## Split
At 5, a cut would put H, R and C in a story of their own before s18, as s43, s45 and s46 were. The lead asked for no further split while the plan stays within the test budget. It does: 14 tests out of 25, and 9 tasks. The plan keeps them, ordered so that tasks 5–7 could still leave as one story.
