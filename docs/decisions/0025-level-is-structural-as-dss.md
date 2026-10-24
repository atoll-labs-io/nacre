---
adr: 0025
title: The reported level is the structural one DSS 6.5.1 gives
status: accepted
date: 2026-10-23
scope: story s18-validate-level
supersedes: []
superseded-by: []
---

# ADR-0025 — The reported level is the structural one DSS 6.5.1 gives

## Context and Problem Statement
`validate` must now report a PAdES level. The s18 spike (`docs/research/s18-validate-level.md`) shows that DSS 6.5.1 reports the level from the structure of the file alone. A token with a wrong imprint or an untrusted TSA leaves `PAdES-BASELINE-T`, and a broken document timestamp leaves `-LTA` (issue #125). A first wording of the story wanted an invalid timestamp to drop the level it carries, and also wanted the level identical to DSS's (brief, success metric 2). The two cannot both hold.

## Considered Options
- **A — Structural level, as DSS.** `report.level()` is the level the file's structure reaches, computed with DSS's rules: form from `/SubFilter`, `PAdES-BES` for a `signingTime` or a missing `/M`, T from a signature or document timestamp, LT from `/DSS` revocation data covering the signer's and the signature timestamps' chains, LTA from a document timestamp over that `/DSS`. The proof of time stays in `best_signature_time`. The campaign compares indication, sub-indication and level exactly, and a closed register declares where Nacre is stricter.
- **B — Proven level.** Each element counts for the level only if it verifies: a timestamp with a valid imprint, chain and revocation for T, verifying `/DSS` data for LT, a valid document timestamp for LTA. Every file where this differs from DSS becomes a declared divergence, a whole class of them (#125).
- **C — Both.** `report.level()` follows A for the comparison with DSS, and a second field, `SignatureValidation::proven_level`, follows B. Both wordings hold, at the cost of a second public rule set.

## Ranking the options
All three options are open source, use the same hardware and scale the same way. They differ on the fourth criterion, easy for an AI to handle. A has one rule set and one oracle, DSS, which the bench already runs. C carries two rule sets and has no oracle for the second one. B has no oracle for its own rule (the EN 319 102-1 text is not in the repository), and it diverges from DSS by design. Next comes the brief's metric 2: A meets it, C meets it for `report`, and B misses it. Rank: **A, C, B**.

## Decision Outcome
Chosen option: **A**, decided by the person on 2026-10-23 (`docs/decisions-log.md`). It is the only option that the brief's metric and the bench can check end to end, and the proof of time it leaves out is already reported in `best_signature_time`. The person also required 100 % identity with DSS, with no excluded case. Option A's register of declared divergences therefore gives way to ADR-0026: the campaign runs under `ValidationPolicy::dss()` with no difference allowed. Under `strict()`, each difference is named by the switch that explains it.

The rule, as the s18 spikes read it from DSS 6.5.1 (2026-10-23, refined on 2026-10-24 by cases r1 to r8 and t1, t2 of `docs/research/s18-validate-level.md`):
- The form comes from `/SubFilter` (`ETSI.CAdES.detached` → PAdES, `adbe.pkcs7.detached` → PKCS7, anything else, missing or not a name → no level).
- A PAdES signature with neither ESS `signingCertificate` nor `signingCertificateV2` has no level.
- `signingTime`, or no readable `/M`, gives `PAdES-BES`, which climbs no further.
- T comes from a signature-timestamp attribute or a later document timestamp, valid or not.
- LT holds when the final `/DSS` holds, for each certificate except self-signed ones of the signer's chain and of the chain of each timestamp that counts, a CRL or OCSP response its issuer signed, expired or not. The timestamps that count are every signature timestamp, every document timestamp in a revision before the last `/DSS`, and, for a signature with no signature timestamp, the first document timestamp after it. Revocation data in the CMS does not count.
- LTA holds when a document timestamp follows a revision whose `/DSS` already gives LT.
- PKCS7 climbs the same way (`PKCS7-T`, `-LT`, `-LTA`).

### Consequences
- Good, because Patelle reads the same level DSS would print, and the campaign checks every level.
- Bad, because a signature can read `PAdES-BASELINE-T` while no timestamp proves its time. A caller that needs the proof reads `best_signature_time`.
- Neutral: a DSS upgrade (ADR-0007) reruns the campaign, which shows any branch of DSS's rule the spike did not see.
