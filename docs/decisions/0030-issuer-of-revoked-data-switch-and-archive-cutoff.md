---
adr: 0030
title: A twelfth switch, judge_issuer_of_revoked_data, and ignore_expired_certs_on_crl widened to OCSP archiveCutoff
status: accepted
date: 2026-10-24
scope: story s46-dss-parity-3
supersedes: [0029]
superseded-by: []
---

# ADR-0030 — A twelfth switch, `judge_issuer_of_revoked_data`, and `ignore_expired_certs_on_crl` widened to OCSP `archiveCutoff`

## Context and Problem Statement
s18's fourth spike against DSS 6.5.1 (2026-10-24, `docs/research/s46-dss-parity-3.md`) found two more rules that only Nacre applies.
- **Revoked data and its issuer.** Once every certificate passed, `judge_path` requires each CA below the anchor that issued revocation data to be within its validity at the control date, whatever that data said (`crates/nacre-validate/src/revocation.rs:298-306`, ADR-0029). DSS skips that rule when the data says "revoked": case v3 (signature stamped 5 days ago, signer revoked 4 days ago by a CA expired yesterday) gives `TOTAL_PASSED` in DSS and `REVOCATION_OUT_OF_BOUNDS_NO_POE` in Nacre under both presets. Case v5 (the same CA, its data saying "good") gives `REVOCATION_OUT_OF_BOUNDS_NO_POE` in both.
- **OCSP `archiveCutoff`** (RFC 6960 §4.4.4, `1.3.6.1.5.5.7.48.1.6`, a single-response extension). `nacre-validate` drops an OCSP response produced after the covered certificate's `notAfter` (`revocation.rs:281-286`) and reads no `archiveCutoff` (`:85-88`). DSS counts the response when its `archiveCutoff` reaches back to that `notAfter`: case e4 gives `OUT_OF_BOUNDS_NOT_REVOKED`, case e5 `TOTAL_PASSED`; without the extension (e4b) DSS drops it as Nacre does. This is the question `expiredCertsOnCRL` answers for a CRL, which ADR-0029 put behind the eleventh switch.

The person wants 100 % identity with DSS under `dss()` and `strict()` never laxer than today. ADR-0026 makes each rule only Nacre applies a switch, through a new ADR that supersedes the switch table; ADR-0029 holds that table today. This ADR replaces that table only; the rest of ADR-0029 stands.

## Considered Options
For revoked data:
- **A twelfth switch** `judge_issuer_of_revoked_data`, on in `strict()`, off in `dss()`. Off, the issuer rule skips each certificate whose deciding data says "revoked".
- **Follow DSS under both presets**: the issuer rule skips "revoked" data everywhere, with no switch.

For `archiveCutoff`:
- **Widen the eleventh switch** `ignore_expired_certs_on_crl` to cover `archiveCutoff`. Off, an OCSP response produced after the certificate's `notAfter` counts when its `archiveCutoff` is at or before that `notAfter`.
- **A thirteenth switch** `ignore_archive_cutoff`, the OCSP twin of the eleventh.
- **Follow DSS under both presets**: honour `archiveCutoff` everywhere.

## Ranking the options
All five are open source and frugal, and none adds a dependency. Following DSS under both presets makes `strict()` laxer than today on v3 and on e5, against the person's rule. A thirteenth switch keeps `strict()` as it is, but adds a boolean that would never be set apart from the eleventh: `expiredCertsOnCRL` and `archiveCutoff` both say "this issuer keeps the status of certificates expired since this date", and a caller who trusts one has no reason to distrust the other. Rank: **a twelfth switch**, then following DSS for revoked data; **widening the eleventh switch**, then a thirteenth switch, then following DSS for `archiveCutoff`.

## Decision Outcome
Chosen options: **a twelfth switch `judge_issuer_of_revoked_data`** and **the eleventh switch widened to `archiveCutoff`**, decided by the person on 2026-10-24 (`docs/decisions-log.md:110`), because `strict()` must not get laxer than today, and both extensions answer the same question. The eleventh switch keeps its name.

The switches, each on in `strict()` and off in `dss()`, one per rule only Nacre applies:

| Switch | Rule it keeps on | Story |
| --- | --- | --- |
| later revisions | refuse a later revision no rule allows, a DocMDP 1 approval signature, and signed bytes that do not end with a revision | s15, s14 |
| sneaky signatures | refuse a signature that shows an appearance absent at certification | s40 |
| trailing data | refuse a file with data after its last `%%EOF` | s14 |
| unusable signatures listed | list as `TOTAL_FAILED` a field whose `/V` names no dictionary, or whose `/Contents` or `/ByteRange` is unusable | s14, s43 |
| signer key usage | judge the signer's `keyUsage` and `extendedKeyUsage` | s16 |
| validity before revocation | refuse an out-of-range certificate before its revocation is judged (`OUT_OF_BOUNDS_NO_POE`) | s16 |
| malformed extensions judged | give a verdict, not an error, on a certificate of the signature's CMS or of its signature timestamps that repeats an extension | s16, s43 |
| fresh revocation | with no proof of existence, count only "not revoked" data issued within 24 h before the control date | s17 |
| unsupported sub-filters | refuse a `/SubFilter` that is missing, not a name, or neither `/ETSI.CAdES.detached` nor `/adbe.pkcs7.detached` | s14, s43, s45 |
| misplaced xref | refuse a file whose `startxref` or `/Prev` offset lands on whitespace before its cross-reference section | s04, s45 |
| expired certs on CRL ignored | drop a CRL, or an OCSP response, issued after the covered certificate's `notAfter`, even when its `expiredCertsOnCRL`, or its `archiveCutoff`, reaches back to that date | s43, s45, s46 |
| issuer of revoked data judged | require the CA, or the delegated OCSP responder, that issued data saying "revoked" to be within its validity at the control date, as for any other data | s45, s46 |

The rule ADR-0026 states stays: a rule DSS applies and Nacre lacks is no switch, and both presets apply it. s46 adds two of them: a CA below the anchor without `subjectKeyIdentifier` on a timestamp authority's path takes from its token any proof of existence (case k1); a delegated OCSP responder valid at `producedAt` but out of its validity at the control date gives `INDETERMINATE` / `REVOCATION_OUT_OF_BOUNDS_NO_POE` (case e2), as a CA issuing the data does since s45.

### Consequences
- Good, because `strict()` refuses everything it refused before, and `dss()` gives DSS's verdict on v3, e4 and e5.
- Bad, because the eleventh switch's name now says less than it covers; its rustdoc and the catalogue name both extensions.
- Neutral: the exemption was observed on a signer revoked after its proof of existence by an expired CA (v3), not on a revoked CA at depth > 0, a `certificateHold`, or a delegated responder; a DSS upgrade (ADR-0007) reruns each switch's conformance test.
