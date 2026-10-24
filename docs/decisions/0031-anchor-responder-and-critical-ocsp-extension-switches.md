---
adr: 0031
title: A thirteenth switch for the anchor's delegated OCSP responder, a fourteenth for critical OCSP extensions
status: accepted
date: 2026-10-24
scope: story s18-validate-level
supersedes: [0030]
superseded-by: []
---

# ADR-0031 — A thirteenth switch for the anchor's delegated OCSP responder, a fourteenth for critical OCSP extensions

## Context and Problem Statement
s18's fifth spike (2026-10-24, `docs/research/s18-validate-level.md`) ran on the code s46 left. It found two rules that only Nacre applies, both of them under both presets.
- **The anchor's delegated responder.** s46 requires a delegated OCSP responder to be within its validity at the control date, the trust anchor's delegate included (`crates/nacre-validate/src/revocation.rs:336-340`). DSS holds an intermediate's delegate to that rule (cases e2, p4), but not the anchor's: a CA whose only data is a response by a root delegate expired since gives `TOTAL_PASSED` in DSS (a6, a7, a8). Nacre gives `REVOCATION_OUT_OF_BOUNDS_NO_POE`.
- **Critical OCSP extensions.** `nacre-revocation` refuses an OCSP response that carries any critical extension (`crates/nacre-revocation/src/ocsp/response.rs:156-157`). DSS reads it, whether the extension is `archiveCutoff`, `crlReferences` or an unknown OID, and whether it sits in a single response or in the response extensions (c2, c4, c5, c6, u1–u3). For a CRL, DSS refuses an unknown critical extension as Nacre does (c7).

The person wants 100 % identity with DSS under `dss()`, and `strict()` never laxer than today (ADR-0029, ADR-0030). ADR-0026 makes each rule only Nacre applies a switch, through a new ADR that supersedes the switch table. ADR-0030 holds that table today; this ADR replaces the table only.

## Considered Options
For the anchor's delegated responder:
- **R1 — A thirteenth switch** `judge_anchor_delegated_responder`, on in `strict()` and off in `dss()`. Off, the issuer rule skips the responder of data whose issuer is the anchor.
- **R2 — Widen the twelfth switch** `judge_issuer_of_revoked_data` to cover it.
- **R3 — Follow DSS under both presets**: no preset judges the anchor's delegate.

For critical OCSP extensions:
- **C1 — A fourteenth switch** `refuse_critical_ocsp_extensions`, on in `strict()` and off in `dss()`. Off, an OCSP response is read whatever the criticality of its extensions. `nacre-revocation` gains a status method that skips that check; `OcspResponse::status` stays as it is.
- **C2 — Widen the eleventh switch** `ignore_expired_certs_on_crl` to accept a critical `archiveCutoff`.
- **C3 — Follow DSS under both presets**: `nacre-revocation` stops refusing critical OCSP extensions.

## Ranking the options
All six options are open source and frugal, and none adds a dependency.
- **R3 and C3** make `strict()` laxer than today, against the person's rule. Both rules also guard something:
  - an expired responder key may sign backdated responses;
  - an unknown critical extension may restrict what the response says (RFC 5280 §4.2, RFC 6960 §4.4).
- **R2** reuses a switch, but its question differs. The twelfth asks whether to trust an out-of-validity issuer for data that says "revoked". R asks whether to trust the anchor's delegate whatever the data says. A caller has reasons to set them apart.
- **C2** covers `archiveCutoff` alone, so u1 and u2 still diverge and AC4 fails.

Rank:
- the anchor's delegate: **R1**, then R2, then R3;
- critical OCSP extensions: **C1**, then C3, then C2. C2 is last because it does not reach 100 %.

## Decision Outcome
Chosen by the person on 2026-10-24, through `/po-plan s18-validate-level`: **R1** and **C1**, for one reason: `strict()` must not get laxer than today (`docs/decisions-log.md`). R3 and C3 would loosen it; R2 merges two questions a caller may want apart; C2 leaves u1 and u2 apart from DSS.

This ADR replaces ADR-0030's switch table; the rest of ADR-0030 stands. The switches are as follows. Each is on in `strict()` and off in `dss()`, one per rule only Nacre applies.

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
| anchor's delegated responder judged | require a responder the trust anchor delegated to be within its validity at the control date, as an intermediate's is | s18 |
| critical OCSP extensions refused | refuse an OCSP response carrying a critical extension, single or response-level, whatever its OID | s10, s18 |

ADR-0026's rule stays: a rule DSS applies and Nacre lacks is no switch, and both presets apply it. s18 adds one. A `certificateHold` dated at or before the best-signature-time gives `INDETERMINATE` / `TRY_LATER` at any depth, where Nacre gave `REVOKED_NO_POE` or `REVOKED_CA_NO_POE` (cases h2, h3, h6, h11b, h13). The indication is unchanged, so neither preset gets laxer.

### Consequences
- Good, because `strict()` refuses everything it refused before, and `dss()` gives DSS's verdict on a6–a8, c2–c6 and u1–u3.
- Bad, because there are fourteen switches, and `nacre-revocation` exposes a second way to read a status.
- Neutral: the anchor's exemption was seen on a "good" response about a CA one level below a self-signed root, not on a revoked CA nor on a non-self-signed anchor. A DSS upgrade (ADR-0007) reruns the campaign.
