# Research — s45-dss-parity-2

[Story](../stories.md)

## Structuring facts
- **AC4 holds under `strict()` only where the validity switch does not fire first.** With no proof of existence (p06d, p06e), `strict()` refuses the expired CA during the walk, `OUT_OF_BOUNDS_NO_POE` (`crates/nacre-validate/src/validate.rs:345-355`, `chain.rs:446-450`), before any revocation is read; that verdict stays, explained by `judge_validity_before_revocation`. AC4's strict half is p06b and p06c (a signature timestamp before the CA's expiry), which pass under both presets today (spike 3, `pr.txt`).
- **The issuer rule reduces to "every CA below the anchor is in validity at the control date".** Each CRL of a pair is verified with the pair's issuer (`crates/nacre-revocation/src/crl.rs:109-121`), so the issuer of the deciding item of each certificate is the next certificate of the path. A delegated OCSP responder's certificate is not exposed by `nacre-revocation` (`ocsp/response.rs:211-260`, outside `Owns`): it is judged at `producedAt` there, never at the control date.
- **The SKI rule breaks every forged CA of the tests and the committed chain corpus.** `forge::Role::Ca` certificates carry no `subjectKeyIdentifier` (`tests/support/forge.rs:98-130`), nor do the CAs `examples/forge_chain_attacks.rs:268-292` writes into `tests/corpus/chain/`. `tests/revocation.rs` (`Pki`, `:44-83`) and the isolation tests (`tests/policy.rs:375-459`) judge sound chains through them.
- **DSS repairs a misplaced `startxref` more widely than whitespace.** Probe on the bench, 2026-10-24: a signed file whose last `startxref` is off by −1 (onto `\n`), +1 or −5 lists its signature in DSS; the hostile file lists none. AC1 asks only for the whitespace case.
- **p03/p04 verify in DSS once re-signed.** The kept `p.txt` of spike 3 shows `HASH_FAILURE` (the patch broke the signed bytes); the re-signed `cases-p/p03`, `p04` give `PDF-NOT-ETSI`, `INDETERMINATE` / `NO_CERTIFICATE_CHAIN_FOUND` on today's bench (old keys): the CMS verifies, so with the bench root trusted they are `TOTAL_PASSED` as AC2 says.

## Story
Under `dss()`, DSS 6.5.1's verdict on five shapes of s18's third spike; `strict()` at least as strict.
- AC1: tenth switch `refuse_misplaced_xref` (on in `strict()`); off, `startxref-off-by-one.pdf` is read through a `nacre-pdf` read option and gives no signature; on, it stays refused.
- AC2: under `dss()`, a missing or non-name `/SubFilter` is verified (`TOTAL_PASSED`, no ETSI level) by the ninth switch; refused under `strict()`.
- AC3: eleventh switch (on in `strict()`); off, a CRL issued after the covered certificate's `notAfter` counts when its `expiredCertsOnCRL` reaches that date; on, it is dropped as today.
- AC4: both presets: revocation data signed by a certificate out of validity at the control date → `INDETERMINATE` / `REVOCATION_OUT_OF_BOUNDS_NO_POE`.
- AC5: both presets: a CA certificate without SKI → `INDETERMINATE` / `CERTIFICATE_CHAIN_GENERAL_FAILURE`; `chain/` regenerated with SKI on its CAs.
- AC6: an ADR adds both switches to ADR-0027's table; the isolation tests cover eleven switches and the catalogue names them.
- AC7: one conformance test per shape, DSS's verdict under `dss()`, the strict one under `strict()`.

## Diagnostic — spike 3 and the s45 probe
Spike 3 (`/home/lecrabe/.claude/jobs/4fb763d0/tmp/s18-spike3/`, `forge3`), verdicts `p.txt`, `pr.txt`, `s.txt`, `pdfcorpus.txt`:

| Case | Shape | `dss()` today | `strict()` today | DSS |
| --- | --- | --- | --- | --- |
| hostile | `startxref` on the `\n` before `xref` | `Err(NotAnXrefSection)` | same | 0 signatures |
| p03, p04, p04b | `/SubFilter` missing / `7` / a string, re-signed | `FORMAT_FAILURE` | same | `PDF-NOT-ETSI`, CMS verified |
| p09 | signer expired, B, CRL issued now with ECOC 60 days back | `GENERAL_FAILURE` | `OUT_OF_BOUNDS_NO_POE` | `OUT_OF_BOUNDS_NOT_REVOKED` |
| s1 / s1b | the same with a timestamp 5 days ago / without ECOC | `GENERAL_FAILURE` | `GENERAL_FAILURE` | `TOTAL_PASSED` / `GENERAL_FAILURE` |
| p06 | CA expired yesterday, root CRL for it issued after its expiry, T | `GENERAL_FAILURE` | same | same |
| p06b / p06c | root CRL before the CA's expiry, T / + document timestamp | `TOTAL_PASSED` | same | `REVOCATION_OUT_OF_BOUNDS_NO_POE` |
| p06d / p06e | the same at B / + document timestamp | `OUT_OF_BOUNDS_NOT_REVOKED` | `OUT_OF_BOUNDS_NO_POE` | `REVOCATION_OUT_OF_BOUNDS_NO_POE` |
| s2 / s3 / s4 / s5 | CA without SKI: no `/M` / signer revoked / no data / signer expired | `SIG_CONSTRAINTS` / `REVOKED_NO_POE` / `GENERAL_FAILURE` / `OUT_OF_BOUNDS_NOT_REVOKED` | `GENERAL_FAILURE` / `REVOKED_NO_POE` / `GENERAL_FAILURE` / `OUT_OF_BOUNDS_NO_POE` | `GENERAL_FAILURE` / `REVOKED_NO_POE` / `GENERAL_FAILURE` / `OUT_OF_BOUNDS_NOT_REVOKED` |

DSS's message on p06b: "The current time is not in the validity range of the certificate of the issuer of the revocation information!" (`BBB_XCV_ICTIVRCIRI_ANS`); on s2–s5, `BBB_XCV_ISKIP_ANS`.

Hypotheses, each with its refuting observation:
- "The issuer is judged at the best-signature-time": refuted, p06b fails although the CA was valid at its timestamp.
- "A document timestamp is a proof of existence for that revocation data": refuted by p06c and p06e.
- "The issuer check comes before `Missing`": refuted by p06 (root CRL late → `GENERAL_FAILURE`, not `REVOCATION_OUT_OF_BOUNDS_NO_POE`).
- "The issuer check comes after the validity of the certificates": refuted by p06d under DSS (`REVOCATION_OUT_OF_BOUNDS_NO_POE`, where Nacre's `dss()` gives `OUT_OF_BOUNDS_NOT_REVOKED`). Kept: right after the revocation of every pair passed.
- "The SKI check comes before revocation": refuted by s3 and s4. "After `/M`": refuted by s2. Kept: after revocation and validity, before `/M`.
- "DSS needs SKI on the leaf": refuted, every forged leaf of spikes 1–3 has none (`forge.rs:98-130`) and passes.

Probe of 2026-10-24 (bench started from a scratch copy of `conformance/`, then stopped): `chain/chain-cms.pdf` plus an empty update (`xref` / `trailer`), its `startxref` exact, −1 (onto `\n`), +1 and −5: DSS lists 1 signature, `PAdES-BASELINE-B`, `NO_CERTIFICATE_CHAIN_FOUND`, in all four.

## Current code
- `ValidationPolicy`: nine `pub bool`, `#[non_exhaustive]`; `strict()` all on, `dss()` all off (`src/policy.rs:12-111`). The ninth's rustdoc says a missing or non-name `/SubFilter` is refused either way (`:63-70`).
- `validate_with` (`src/validate.rs:138-274`): `Document::parse(pdf)`, retried on the prefix when trailing data is tolerated (`:146-154`); document timestamps skipped (`:168-170`); `check` → `signed_bytes`, whose `/SubFilter` arm refuses anything but a name, and under the ninth switch anything but `SUB_FILTERS` (`:505-509`).
- `Context::judge` (`:293-381`): pool from CMS, tokens and `/DSS` (`:318-327`); `build_path` at `time` with the policy's validity rule (`:345-355`); `judge_path(&path, &pool, source, time, issued_from)` (`:357`), then `after_revocation` (`:386-419`): validity of each certificate below the anchor when the switch is off (`:400-404`), then `/M` (`:409-418`).
- `proven_time` (`:424-451`): TSA path at `self.at` under `Rules::STRICT`, so every TSA CA is in validity at the control date; `judge_path(…, self.at, None)` (`:448`).
- `src/revocation.rs`: `RevocationDefect { Revoked, Missing }` (`:30-38`) and `report()` (`:43-50`); `Item::read` keeps the parsed `Crl` or `OcspResponse` only (`:58-65`); `Item::verdict` dates a CRL by `thisUpdate` (`:70-100`); `judge_path` (`:206-247`) keeps items issued in `[notBefore, notAfter]` and fresh (`:235-239`).
- `src/chain.rs`: anchors' validity and extensions not judged (`:90-91`); `Node::read` decodes SKI only to narrow the search (`:280-303`); `in_validity` (`:514-528`) is `pub(crate)`.
- `src/report.rs`: `Defect` `#[non_exhaustive]` (`:83-143`); `defective` maps each defect to its report (`:187-232`); `after_chain` keeps the path (`:173-185`).
- `src/revisions.rs:149`: `State::read` re-parses each revision prefix with `Document::parse`.
- `nacre-pdf`: `Document::parse` → `parse_with(input, Limits::DEFAULT)`, `pub(crate)` (`src/document.rs:37-41`); `xref::read` follows `startxref` then `/Prev` through `read_section` (`src/xref.rs:56-87`), which needs `xref` or an object header exactly at the offset (`:168-179`); `group_revisions` keys revisions by the stated offsets (`:89-127`); `Update` writes `/Prev` from `Revision::startxref` (`src/revision.rs:406`). The crate promises no repair (`src/lib.rs:9-10`, `:19`).

## Attachment points
- Switches: `src/policy.rs` (fields, `strict()`, `dss()`, the `dss()` warning `:89-97`); `tests/policy.rs:256-282` (`SWITCHES`).
- Misplaced xref: `nacre-pdf` `read_section` (`xref.rs:168-179`), behind a public read option reaching `xref::read`; `validate.rs:146-154` and `revisions.rs:149` parse with the option the policy gives.
- `/SubFilter`: `signed_bytes` (`validate.rs:505-509`); rustdoc `policy.rs:63-70`, `report.rs:89-92`.
- ECOC: `Item::read` / `Item::verdict` and the filter `revocation.rs:235-239`; the CRL's DER through `x509_cert::crl::CertificateList` (x509-cert is a dependency, `Cargo.toml:20`).
- Issuer rule: end of `judge_path`, a new `RevocationDefect` variant and its `report()` row.
- SKI rule: `after_revocation`, after `:400-404`, before `:409`; a new `Defect` variant mapped in `defective`.
- Catalogue: `docs/security/attacks/pades.md:24` (contract), `:42` (sub-filter row); `revocation.md:84-97`; `cms.md:22-51`.

## Verified interfaces
- `validate_with_policy(pdf, &TrustAnchors, SystemTime, Option<&dyn RevocationSource>, &ValidationPolicy) -> Result<Vec<SignatureValidation>, Error>` (`validate.rs:128-136`).
- `SubIndication::RevocationOutOfBoundsNoPoe` ↔ `"REVOCATION_OUT_OF_BOUNDS_NO_POE"` (`crates/nacre-core/src/report.rs:84`).
- `Crl::status(certificate, issuer, at)` refuses a critical CRL extension (`crl.rs:115`); `expiredCertsOnCRL` is non-critical in the spike's CRLs (`forge3.rs:116-127`).
- Test support: `forge::{issue, issue_valid, issue_with, crl, crl_with_reasons, ChainSigner, ForgedTsa, token, signed, custom_signed, patch, with_dss}` (`tests/support/forge.rs:134-460`), `Stub` (`support/mod.rs:88-110`), `Pki` with `judge_under` (`tests/revocation.rs:32-182`), `strict_without` (`tests/revocation.rs:499`, `tests/policy.rs:37`).
- Conformance helpers: `judged`, `nacre`, `confront_signatures`, `confront_error`, `forged_signer`, `intermediate_crl`, `chain_crls`, `root_crl` (`tests/conformance.rs:54-176`, `:453-491`, `:769-787`); `bench_key("root")` exists (`support/mod.rs:38`).
- Isolation: `verdict()` judges each attack file with the chain root, 2026-10-22 and a `Stub` (`tests/policy.rs:375-411`); `catalog()` requires one row per attack file and only switch names in backticks (`:305-352`).
- `nacre-pdf` refusal test asserts `NotAnXrefSection { offset: 564 }` on the hostile file (`tests/refusals.rs:18-24`); the file's objects sit at their stated offsets, `xref` at 565 (`od`).

## Traps
- **Corpus regeneration**: giving SKI to `Profile::ca` (`examples/forge_chain_attacks.rs:240-252`, `:280-292`) rewrites `chain/root.der`, `intermediate.der`, `impostor-root.der`, every PDF carrying the intermediate and every `attacks/chain-*.pdf`; their hashes live in `tests/corpus/README.md:83-100`. The leaf's bytes stay (no AKI added). The fuzz target includes `chain/root.der` (`fuzz/fuzz_targets/validate.rs:9`).
- `forge::Role::Ca` gaining SKI is required, or every sound case of `tests/revocation.rs` turns `GENERAL_FAILURE`; a CA without SKI then needs an `Extensions` variant.
- `revisions.rs:149` re-parses prefixes strictly: a mixed policy (misplaced xref tolerated, later revisions refused) would otherwise read every prefix as unreadable.
- A leniently read document's `Revision::startxref` must be where the section was found, or `update()` writes a `/Prev` that only a lenient reader follows (`revision.rs:406`); `group_revisions` must then key by the same offset.
- `xref_entry_pointing_elsewhere` (`tests/support/mod.rs:272-274`) must stay refused with the option: it repairs section offsets only, never object entries.
- `dss_opens_only_what_the_catalog_marks` and `each_switch_changes_only_what_the_catalog_names` run over every file of `tests/corpus/attacks/`; a new attack file needs a catalogue row.
- s43 is the latest change to these files (`10584dd`): `data_issued_after_not_after` (`tests/conformance.rs:841-920`) and `data_issued_after_not_after_does_not_count` (`tests/revocation.rs:749-790`) must keep passing; ECOC is off in their CRLs.
- The bench regenerates its keys at every start: conformance cases are forged at run time, without CDP. No migration.

## Open questions
- Does DSS require SKI on a trust anchor? Not observable on the bench (its root carries one, `conformance/pki/openssl.cnf:55`); the plan judges CAs below the anchor, as chain judging does.
- A delegated OCSP responder expired at the control date: not forged; DSS presumably fails it, Nacre would not.
- SKI and ECOC on a timestamp authority's path: not observed; the plan applies the SKI rule to the signer's path only and ECOC wherever revocation is judged under the policy.
- Revoked signer whose CA expired: precedence between `Revoked` and the issuer rule not observed (the plan keeps `Revoked` first, as `Missing`).
- `startxref` off by more than whitespace: DSS repairs it, Nacre refuses it under both presets; not in any corpus, s18's campaign would show it if one were.

## Complexity
Story 4 → **4**. Two switches, two DSS rules in two modules, a `nacre-pdf` read option, a regenerated chain corpus, the catalogue and ADR-0029; no level, no new dependency. Every shape was observed on DSS, so no choice is left open.

## Split
Not needed.
