# QA — s41-validation-policy

[Story](../../stories.md) · [Plan](../../plans/s41-validation-policy.md)

Scope: the story's surface, what `git diff main...story/s41-validation-policy` touches on it, and the acceptance criteria its user can observe through it; nothing else was checked.
Driver: scenarios.md of qa-drivers — surface endpoint, platform lib (setting `Platform: lib, cli`; the `cli` row applies only to a `command` surface)
Evidence: transcripts
Tool: Bash — a scratch binary crate `qa-scen` in a `mktemp -d` copy of `git ls-files` (no `.env*` file to copy), calling the public API of `nacre-validate` (`ValidationPolicy`, `validate`, `validate_with_anchors`, `validate_with_revocation`, `validate_with_policy`, `TrustAnchors`), plus `qa-literal`, a three-line caller that builds a policy with struct update syntax. Input files are corpus files of `crates/nacre-validate/tests/corpus/` or PDFs signed at run time with `nacre_pades::sign_at_level` under a fictitious PKI built with the bench's `tests/support/forge.rs` (included by `#[path]`). `cargo fetch` and `cargo build --workspace --all-features` ran in the copy (exit 0). Every scenario was run twice and the two outputs compared with `cmp` (identical); the program is quoted whole in each transcript. This walk replays the first QA (tree 1deb2cc6…) after fix commit 1b76dd3, with the same program plus one boundary case in c4-error
Origin: —

## Coverage
| Criterion or item | Reached | Result |
| --- | --- | --- |
| 1. `ValidationPolicy` has one switch per rule: eight `pub bool` fields, `strict()` all on, `dss()` all off, `Default` = `strict()`; each switch turned off alone changes one field | yes | as expected (`c1-policy-presets.txt`) |
| 1. `validate`, `validate_with_anchors`, `validate_with_revocation` without a policy apply `strict()` | yes | as expected — on eight attack files, each entry point's result equals `validate_with_policy(…, strict())` with the same anchors and date (`c1-policy-presets.txt`) |
| 1. invalid input — empty input, non-PDF, truncated file, `unsigned.pdf` plus trailing garbage, under both presets; a policy built with struct update syntax | yes | as expected — `MissingHeader`, `MissingStartxref`, `TrailingData { offset: 745 }` of kind `InvalidInput` with readable messages; `dss()` reads the garbage-tailed unsigned file as having no signature; struct update syntax refused at compile time by `E0639` (`#[non_exhaustive]`), the fields stay mutable on a preset (`c1-policy-presets-error.txt`) |
| 2. Under `dss()`: appended revision accepted (`isa-appended-revision`, `byterange-not-whole-file`, `ssa-visible-signature`) | yes | as expected — no defect, `INDETERMINATE` / `NO_CERTIFICATE_CHAIN_FOUND` with no anchor (`c2-dss-verdicts.txt`) |
| 2. `keyCertSign`-only leaf and `serverAuth` EKU leaf accepted | yes | as expected — path kept (3 certificates), judged on revocation: `CERTIFICATE_CHAIN_GENERAL_FAILURE` (no data); `strict()` gives `CHAIN_CONSTRAINTS_FAILURE` (`c2-dss-verdicts.txt`) |
| 2. Expired or not-yet-valid signer judged after revocation | yes | as expected — no data: `CERTIFICATE_CHAIN_GENERAL_FAILURE` (`chain-expired`, `chain-not-yet-valid`, forged); "not revoked" CRL: `OUT_OF_BOUNDS_NOT_REVOKED`, `OutOfRangeNotRevoked(Expired)`; revoked: `REVOKED_NO_POE`; `strict()` gives `OUT_OF_BOUNDS_NO_POE` in all three (`c2-dss-verdicts.txt`) |
| 2. USF files: no signature | yes | as expected — the seven `usf-*` files give 0 results under `dss()`, one `TOTAL_FAILED` each under `strict()`; `byterange-overlap` stays listed `TOTAL_FAILED` under both (`c2-dss-verdicts.txt`) |
| 2. `isa-no-xref` read and judged; `chain-malformed-extension` an error | yes | as expected — `isa-no-xref`: one signature, no defect under `dss()`, `Err(TrailingData)` under `strict()`; `chain-malformed-extension`: `Err(MalformedCertificate)`, kind `InvalidInput`, under `dss()`, `MalformedExtension` verdict under `strict()` (`c2-dss-verdicts.txt`) |
| 2. invalid input — truncated attack files under `dss()`, a non-root anchor, a non-certificate anchor | yes | as expected — `MissingStartxref`; intermediate as anchor gives a 2-certificate path; `TrustAnchor` error naming the DER tag (`c2-dss-verdicts-error.txt`) |
| 3. `/M` before the signer's `notBefore` gives `SIG_CONSTRAINTS_FAILURE` under `strict()` and `dss()` | yes | as expected — `/M` 1 s and 16 h before `notBefore`: `ClaimedTimeBeforeCertificate`, path kept, under both presets; `/M` equal to or after `notBefore`: `TOTAL_PASSED` (`c3-claimed-time.txt`) |
| 3. invalid input — `/M` before `notBefore` with no revocation data; control date before `notBefore` | yes | as expected — the revocation or validity verdict comes first (`CERTIFICATE_CHAIN_GENERAL_FAILURE`; `OUT_OF_BOUNDS_NO_POE` under `strict()`), as the plan orders the rule after chain and revocation (`c3-claimed-time-error.txt`) |
| 4. Under `strict()`, an old (25 h) CRL that revokes the signer stays a proof: `REVOKED_NO_POE`; `certificateHold` excepted; an old "not revoked" dropped | yes | as expected — `keyCompromise`, no reason code and `superseded`: `REVOKED_NO_POE`; `certificateHold`: `CERTIFICATE_CHAIN_GENERAL_FAILURE`; old "not revoked": `CERTIFICATE_CHAIN_GENERAL_FAILURE`; 23 h, exactly 24 h and fresh CRLs: `TOTAL_PASSED`; `dss()` passes the old "not revoked" (`c4-freshness-window.txt`) |
| 4. invalid input — old CRL signed by another key; old CRL revoking another serial; garbage CRL stream; old CRL whose entry for the signer is dated after the control date | yes | as expected — all four `CERTIFICATE_CHAIN_GENERAL_FAILURE` under `strict()`; the future-dated entry no longer passes (it gave `TOTAL_PASSED` on tree 1deb2cc6…); with the freshness switch off and under `dss()` it still passes, as those policies ignore freshness (`c4-freshness-window-error.txt`) |
| 4. boundary — old CRL whose entry for the signer is dated exactly at the control date | yes | as expected — REVOKED_NO_POE, Revoked { depth: 0 } (c4-freshness-window-error.txt) |

## Findings
Status rule: **verified** means the steps were replayed and reproduced the defect, and an evidence file holds it; **probable** means it was seen once, or no evidence file could be kept; **unverified** means it is suspected from what the surface showed, not seen happening.

None. Finding 1 of the first QA no longer reproduces on this tree.

## Not seen
- Criterion 2, the comparison with DSS 6.5.1 itself — Nacre's verdicts were held against the verdicts the story text names, not against a running DSS: DSS is a dependency the driver did not start (`conformance/compose.yaml`).
- Criterion 5, one conformance test per switch against DSS — the tests are `#[ignore = "conformance"]` and need the DSS bench, a dependency the driver did not start; the switch-by-switch effect on one file was seen through the library instead (criteria 1, 2, 4).
- Criterion 6, `docs/security/attacks/` per attack and policy — a document, with no effect observable through the library's interface; left to the review.
- Criterion 2, `/M` before `notBefore` on the spike's own file — only forged signatures were walked.

Tree: 19da54846d84a8a4bbdf860f8cfea2d36bf59f1a
QA status: complete
