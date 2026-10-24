---
adr: 0027
title: A ninth switch, refuse_unsupported_sub_filters, on in strict() and off in dss()
status: accepted
date: 2026-10-24
scope: story s43-dss-parity
supersedes: [0026]
superseded-by: [0029]
---

# ADR-0027 — A ninth switch, `refuse_unsupported_sub_filters`, on in `strict()` and off in `dss()`

## Context and Problem Statement
`nacre-validate` refuses a signature whose `/SubFilter` is neither `/ETSI.CAdES.detached` nor `/adbe.pkcs7.detached` (`crates/nacre-validate/src/validate.rs:475-478`), under both presets: `TOTAL_FAILED` / `FORMAT_FAILURE`. DSS 6.5.1 reads the CMS of such a signature and, when it is sound, gives `TOTAL_PASSED` with the format `PDF-NOT-ETSI` (s18 spike, cases n06 `adbe.x509.rsa_sha1` and n07 an unknown name, 2026-10-24). The person wants 100 % identity with DSS under `dss()`, with no case left out of the campaign, and `strict()` never laxer than today. ADR-0026 says a new rule that only Nacre applies becomes a switch through a new ADR that supersedes its table. This ADR replaces that table only; the rest of ADR-0026 stands.

## Considered Options
- **A ninth switch.** `refuse_unsupported_sub_filters`, on in `strict()`, off in `dss()`. Off, any `/SubFilter` name other than `/ETSI.RFC3161` is verified as a detached CMS, like `/adbe.pkcs7.detached`, and gets no ETSI level.
- **DSS's rule under both presets.** Any `/SubFilter` is verified, under `strict()` too.
- **Leave it unfixed** and keep such files out of the campaign.

## Ranking the options
All three are open source, frugal and add no dependency. The second makes `strict()` laxer than today on a refusal only Nacre makes, against ADR-0026's "no preset is laxer" and the story's "`strict()` ne devient jamais plus laxiste". The third breaks the person's 100 % with no excluded case. The first keeps `strict()` as it is, gives DSS's verdict under `dss()`, and follows the mechanism ADR-0026 already set: one more boolean, one more test per preset. Rank: **ninth switch**, then DSS's rule under both presets, then leaving it unfixed.

## Decision Outcome
Chosen option: **a ninth switch**, decided by the person on 2026-10-24 (`docs/decisions-log.md`, s43-dss-parity). `strict()` keeps its refusal, and the campaign of s18 gets DSS's verdict.

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
| unsupported sub-filters | refuse a `/SubFilter` other than `/ETSI.CAdES.detached` and `/adbe.pkcs7.detached` | s14, s43 |

The rule ADR-0026 states stays: a rule DSS applies and Nacre lacks is no switch, and both presets apply it. s43 adds three of them: a missing or unreadable `/M`, a `/M` after the signer's `notAfter` (both `INDETERMINATE` / `SIG_CONSTRAINTS_FAILURE`), and revocation data issued after its certificate's `notAfter`, which no longer counts.

### Consequences
- Good, because `strict()` refuses exactly what it refused before, and `dss()` reads the CMS of an exotic `/SubFilter` as DSS does.
- Bad, because under `dss()` a signature in a form Nacre does not support (an `adbe.x509.rsa_sha1` carrying a CMS) can read as `TOTAL_PASSED`. The rustdoc of `dss()` and `docs/security/attacks/pades.md` say so.
- Neutral: a missing or non-name `/SubFilter` stays refused under both presets; DSS's verdict on it was not observed. A DSS upgrade (ADR-0007) reruns this switch's conformance test.
