---
adr: 0029
title: A tenth and an eleventh switch, refuse_misplaced_xref and ignore_expired_certs_on_crl, on in strict() and off in dss()
status: accepted
date: 2026-10-24
scope: story s45-dss-parity-2
supersedes: [0027]
superseded-by: [0030]
---

# ADR-0029 — A tenth and an eleventh switch, `refuse_misplaced_xref` and `ignore_expired_certs_on_crl`, on in `strict()` and off in `dss()`

## Context and Problem Statement
s18's third spike against DSS 6.5.1 (2026-10-24) found two rules that only Nacre applies.
- `nacre-pdf` refuses a file whose `startxref` points at the whitespace just before `xref`: `startxref-off-by-one.pdf` of its hostile corpus gives `NotAnXrefSection` (`crates/nacre-pdf/src/xref.rs:174-179`). DSS lists no signature in that file, and still lists the signature of a signed file whose last `startxref` is off by one (probe of s45's research).
- `nacre-validate` drops a CRL issued after the `notAfter` of the certificate it covers, even when the CRL carries `expiredCertsOnCRL` (RFC 5280 §5.2.7, `2.5.29.60`) dated at or before that `notAfter` (`crates/nacre-validate/src/revocation.rs:237`). DSS counts it: cases p09 (`OUT_OF_BOUNDS_NOT_REVOKED`) and s1 (`TOTAL_PASSED`).

The person wants 100 % identity with DSS under `dss()` and `strict()` never laxer than today. ADR-0026 makes each rule only Nacre applies a switch, through a new ADR that supersedes the switch table; ADR-0027 holds that table today. This ADR replaces that table only; the rest of ADR-0027 stands, except its neutral consequence on a missing `/SubFilter`, which DSS has now been seen to read (cases p03, p04, p04b).

## Considered Options
- **Two more switches.** `refuse_misplaced_xref` and `ignore_expired_certs_on_crl`, on in `strict()`, off in `dss()`. Off, `nacre-pdf` reads a section whose stated offset lands on whitespace before `xref` or an object header, through a read option that `nacre-pdf`'s other callers never set; and a CRL issued after a certificate's `notAfter` counts for it when its `expiredCertsOnCRL` is at or before that `notAfter`.
- **Tolerate everywhere.** `nacre-pdf` skips that whitespace for every reader, and `nacre-validate` honours `expiredCertsOnCRL` under both presets, with no switch.
- **Follow DSS under both presets** for `expiredCertsOnCRL` only, keeping a switch for the `startxref`.
- **Leave both refusals**, and keep such files out of the campaign.

## Ranking the options
All four are open source, frugal and add no dependency. The second and third make `strict()` laxer than today: the second makes `nacre-pdf` and `nacre-pades` read a file their hostile corpus says they must refuse, and both make s1 pass under `strict()` where it gives `CERTIFICATE_CHAIN_GENERAL_FAILURE` today. The fourth breaks the person's 100 % with no excluded case. The first keeps `strict()` as it is, gives DSS's verdict under `dss()`, and follows the mechanism ADR-0026 set: one more boolean each, one test per preset. Rank: **two more switches**, then following DSS under both presets for `expiredCertsOnCRL`, then tolerating everywhere, then leaving both refusals.

## Decision Outcome
Chosen option: **two more switches**, decided by the person on 2026-10-24 (`docs/decisions-log.md:106`), because `strict()` must not get laxer than today.

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
| expired certs on CRL ignored | drop a CRL issued after the covered certificate's `notAfter`, even when its `expiredCertsOnCRL` reaches back to that date | s43, s45 |

The rule ADR-0026 states stays: a rule DSS applies and Nacre lacks is no switch, and both presets apply it. s45 adds two of them: revocation data whose issuing CA, below the anchor, is out of its validity at the control date gives `INDETERMINATE` / `REVOCATION_OUT_OF_BOUNDS_NO_POE` (cases p06b to p06e); a CA certificate below the anchor without `subjectKeyIdentifier` gives `INDETERMINATE` / `CERTIFICATE_CHAIN_GENERAL_FAILURE` (cases s2 to s5).

### Consequences
- Good, because `strict()` refuses everything it refused before and refuses two more shapes, and `dss()` gives DSS's verdict on the five shapes of s18's third spike.
- Bad, because under `dss()` a reader tolerance enters `nacre-pdf`, whose crate documentation promised no repair; it stays opt-in, limited to whitespace, and `nacre-pades` never sets it. DSS (PDFBox) repairs wider: a `startxref` one byte past `xref`, or five bytes before it, still lists the signature; Nacre refuses those under both presets, and no corpus holds one.
- Neutral: a DSS upgrade (ADR-0007) reruns each switch's conformance test.
