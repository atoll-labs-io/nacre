# QA — s17-validate-revocation

[Story](../../stories.md) · [Plan](../../plans/s17-validate-revocation.md)

Scope: the story's surface, what `git diff main...story/s17-validate-revocation` touches on it, and the acceptance criteria its user can observe through it; nothing else was checked.
Driver: scenarios.md of qa-drivers — surface endpoint, platform lib (row `endpoint` / `api`, `lib`; `cli` has no row for `endpoint`)
Evidence: transcripts
Tool: Bash — a scratch binary crate under a `mktemp -d` directory, depending by path on a copy of the tracked files, calling `validate_with_revocation`, `validate_with_anchors` and `TrustAnchors::from_certificates`
Origin: —

This is the second walk, after fix run 1 (6ecbc40). That fix adds `FRESHNESS_TOLERANCE`: a signature with no proof of existence counts only revocation data issued within 24 h before the control date (plan, step 10 and "Deliberate divergence from DSS"). Every transcript of the first walk was replaced; `ac2-fresh`, `ac2-fresh-error` and `ac4-near` are new.

The criteria are held against the story as corrected on `main` by 7eaee8f, which the validated plan names: AC1 `INDETERMINATE` / `REVOKED_NO_POE`, AC3 `INDETERMINATE` / `CERTIFICATE_CHAIN_GENERAL_FAILURE`. The story branch starts at de558ca, before 7eaee8f, so its copy of `docs/stories.md` still has the earlier wording (`TOTAL_FAILED` / `REVOKED`, `TRY_LATER` or `REVOCATION_OUT_OF_BOUNDS_NO_POE`).

Inputs were built at run time with the story's test forge (`tests/support/forge.rs`, included by path), under a PKI of this QA's own: other keys, names, serials and dates than `tests/revocation.rs`.
- Signature: 2026-10-22T08:00Z.
- Default CRLs: 10-22T14:00.
- Control date: 2026-10-25T00:00Z, so the default CRLs are 34 h old at the control date.
- `ac4-near` uses a control date of 2026-10-23T00:00Z, so its CRLs are 10 h old.

Each scenario was run twice; the outputs were identical.

## Coverage
| Criterion or item | Reached | Result |
| --- | --- | --- |
| AC1 — B-T before revocation stays valid; stamp after revocation gives `INDETERMINATE` / `REVOKED_NO_POE` (`ac1.txt`) | yes | as expected, unchanged by the fix: revoked 12:00 after a 08:00 stamp → `TOTAL_PASSED`, BST 08:00, on 34 h-old CRLs; revoked 06:00 → `REVOKED_NO_POE`; exactly 08:00 → `REVOKED_NO_POE`; 08:00:01 → `TOTAL_PASSED` |
| AC1, invalid input (`ac1-error.txt`) | yes | as expected: not a PDF, truncated PDF → `Err` `InvalidInput` naming the cause; PEM anchor → "give it as DER"; garbage anchor → DER error; foreign anchor → `NO_CERTIFICATE_CHAIN_FOUND`; junk `/DSS` CRL → `CERTIFICATE_CHAIN_GENERAL_FAILURE` |
| AC2 — B-B judged at the control date, revoked since → `INDETERMINATE` / `REVOKED_NO_POE`, with data issued within 24 h (`ac2-fresh.txt`, `ac4-near.txt`) | yes | as expected: CRLs 12 h old listing the signer → `REVOKED_NO_POE`, BST `None`; nothing listed → `TOTAL_PASSED`; intermediate revoked by a fresh root CRL → `REVOKED_CA_NO_POE`, depth 1; [stale clean, fresh revoked] in both array orders → `REVOKED_NO_POE`; data 10 h old (`ac4-near`) → `REVOKED_NO_POE` |
| AC2 — same, with the only data older than 24 h (`ac2.txt`, `ac2-fresh.txt`) | yes | finding 1 |
| AC2, freshness boundary and the attack the fix closes (`ac2-fresh.txt`) | yes | as expected: intermediate CRL exactly 24 h old → counts (`TOTAL_PASSED`); 24 h + 1 s → `Missing { depth: 0 }`; fresh intermediate CRL with a stale root CRL → `Missing { depth: 1 }`; key revoked since, `/DSS` holding only an old clean CRL → `CERTIFICATE_CHAIN_GENERAL_FAILURE`, no longer `TOTAL_PASSED`; B-T on the same stale CRLs → `TOTAL_PASSED` (DSS's rule kept with a POE) |
| AC2, invalid input (`ac2-error.txt`, `ac2-fresh-error.txt`) | yes | as expected: control date `UNIX_EPOCH` (24 h cannot be subtracted) → `Chain(NotYetValid)` / `OUT_OF_BOUNDS_NO_POE`, no panic; no anchor → `NO_CERTIFICATE_CHAIN_FOUND`; fresh CRL signed by another key → `Missing`, never read as "not revoked"; CRLs dated after the control date → counted, `TOTAL_PASSED` |
| AC3 — `/DSS` suffices offline for B-LT and B-LTA; no data and no source → `INDETERMINATE` / `CERTIFICATE_CHAIN_GENERAL_FAILURE` (`ac3.txt`) | yes | as expected: B-LT and B-LTA from `nacre_pades::sign_at_level` (stub source at signing), validated with no source → `TOTAL_PASSED`; B-B with no CRL, with or without a `/DSS` → `CERTIFICATE_CHAIN_GENERAL_FAILURE`, `Missing { depth: 0 }`. A source answering CRLs of 10-22 now gives `Missing` too (freshness); one answering CRLs of 10-24T18:00 → `TOTAL_PASSED` (`ac2-fresh-error.txt`) |
| AC3, invalid input (`ac3-error.txt`) | yes | as expected: a source returning `Err`, or garbage as a CRL → `Missing`, no panic, no `Err` |
| AC4 — the TSA chain judged like the signer's (`ac4.txt`, `ac4-near.txt`) | yes | as expected for the TSA: TSA revoked after the stamp, before the control date → no POE, BST `None`; common intermediate revoked → same; token certificate without `id-kp-timeStamping` → no POE; TSA not revoked → `TOTAL_PASSED`. The signer is then judged as a B-B: `REVOKED_NO_POE` at 10-23 (`ac4-near`), `CERTIFICATE_CHAIN_GENERAL_FAILURE` at 10-25 (`ac4`, finding 1) |
| AC4, invalid input (`ac4-error.txt`, `ac4-near.txt`) | yes | as expected: token over another imprint → no POE (`REVOKED_NO_POE` at 10-23, `GENERAL_FAILURE` at 10-25, finding 1); control date before `genTime` → BST `None`, judged at the control date |
| AC5 — confrontation with DSS on the s02 bench | no | not reached — see `## Not seen` |

## Findings
Status rule: **verified** means the steps were replayed and reproduced the defect, and an evidence file holds it; **probable** means it was seen once, or no evidence file could be kept; **unverified** means it is suspected from what the surface showed, not seen happening.

### Finding 1 — A revocation proven by data older than 24 h gives `CERTIFICATE_CHAIN_GENERAL_FAILURE`, not `REVOKED_NO_POE`
Severity: minor
Status: verified
Steps to reproduce:
1. Sign a B-B PDF (`signed(.., Level::B)`) under the QA PKI. Append a `/DSS` holding the root, the intermediate, an intermediate CRL of 2026-10-22T14:00 listing the signer revoked at 12:00, and a root CRL (scenario `fresh`, sixth case, or `ac2`, first case).
2. Call `validate_with_anchors(pdf, anchors, 2026-10-25T00:00Z)`, with no source.
3. Observe `INDETERMINATE` / `CERTIFICATE_CHAIN_GENERAL_FAILURE`, defect `Revocation(Missing { depth: 0 })`.
4. Do the same with the control date at 2026-10-23T00:00Z (`ac4-near`, third case): `REVOKED_NO_POE`. A B-T whose stamp gives no POE (TSA revoked, foreign imprint) behaves the same way: compare `ac4` and `ac4-error` with `ac4-near`.
Capture: docs/qa/s17-validate-revocation/ac2-fresh.txt, ac2.txt, ac4.txt, ac4-near.txt: transcripts
Expected: AC2, "un certificat révoqué depuis rend `INDETERMINATE` (`REVOKED_NO_POE`)"; AC5 asks for DSS's sub-indication, and DSS ignores freshness.
Observed: the freshness filter drops a CRL that lists the revocation as well as a clean one, so the caller is told the data is missing rather than that the key is revoked.
- The result is still `INDETERMINATE`, so it fails closed.
- The plan records this divergence from DSS as decided by the person on 2026-10-23. Its "Cost" line names only a CA publishing less than daily, not this change of sub-indication on a revoked key.
- For the person to confirm, and for s18 to list.

## Not seen
- AC5, DSS giving the same indication and sub-indication. It shows only through the DSS bench of s02 (`conformance/compose.yaml`), a dependency this driver did not start. The `#[ignore = "conformance"]` tests C0 to C6, and the level they now assert, were not run.
- AC3 on files made by the bench's real HTTP TSA and revocation sources (C4 of `conformance.rs`), for the same reason. B-LT and B-LTA were checked on files from `sign_at_level` with a stub source only.
- OCSP responses as revocation data, and the 24 h window applied to `producedAt`. Every scenario used CRLs: the forge has no OCSP helper, and the plan reaches OCSP only through the bench.
- Behaviour on a real network, which is out of reach of the driver.

Tree: 50fecebeed209d68f59e11126ba87223b014f482
QA status: complete
