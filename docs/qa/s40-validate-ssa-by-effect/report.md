# QA — s40-validate-ssa-by-effect

[Story](../../stories.md) · [Plan](../../plans/s40-validate-ssa-by-effect.md)

Scope: the story's surface, what `git diff main...story/s40-validate-ssa-by-effect` touches on it, and the acceptance criteria its user can observe through it; nothing else was checked. This walk replaces the one of tree `cd4cc1d6…` and covers the third fix run (commit `7a8574d`): `placement` now reads NoView with ToggleNoView as shown in the state after a certification, with the new case `ssa-toggle-noview-shown`. Every scenario of the previous walk was run again on this tree.
Driver: scenarios.md of qa-drivers — surface endpoint, platform lib (setting `Platform: lib, cli`; the `cli` row applies only to a `command` surface)
Evidence: transcripts
Tool: Bash — two scratch binary crates in a `mktemp -d` copy of `git ls-files` (no `.env*` file to copy): `qa-scen`, calling the public `nacre_validate::validate` on one file, and `qa-sign`, calling the public `nacre_pades::sign` with a `TestSigner`; both quoted whole in the transcripts. `cargo fetch` and `cargo build --workspace --all-features` ran in the copy (exit 0). Every run was made twice and the two outputs compared with `cmp` (identical)
Origin: —

## Coverage
| Criterion or item | Reached | Result |
| --- | --- | --- |
| 1. Certified PDF (P=1, 2, 3), signature visible while no appearance of its field was visible when certified: `AddedByRevisionNotAllowed` on it, `RevisionNotAllowed` on the certification | yes | as expected — P=2 `ssa-visible-signature.pdf`, `ssa-zero-rect-shown.pdf`, `ssa-unreadable-rect.pdf`, `ssa-toggle-noview-shown.pdf` and P=3 `ssa-hidden-widget-shown.pdf`: `Sneaky` `TOTAL_FAILED / FORMAT_FAILURE` with `AddedByRevisionNotAllowed`, `Certification` `RevisionNotAllowed`, digests and signatures verified; P=1 `certified-p1-second-signature.pdf` refused the same way (`c1-visible-ssa-refused.txt`) |
| 1. invalid input — no argument, missing, empty and non-PDF file, three certified attack files truncated mid-revision | yes | as expected — `MissingHeader` and `MissingStartxref` errors of kind `InvalidInput`, no verdict, no panic (`c1-visible-ssa-refused-error.txt`) |
| 2. Each shape of the story: merged, split (`/Kids`), field added then signed later, zero `/Rect` made visible, Hidden widget made visible, indirect `/Rect`, kid widget changed | yes | as expected — all seven files end with `Sneaky` `AddedByRevisionNotAllowed` and the certification `RevisionNotAllowed` (`c2-each-shape.txt`) |
| 2. Shapes of the earlier fix runs: orphan widget, unlisted widget, off layer (`/OC`), moved `/Rect`, unreadable `/Rect` | yes | as expected — unchanged from the previous walk, each `Sneaky` `AddedByRevisionNotAllowed`, the certification `RevisionNotAllowed` (`c2-each-shape.txt`) |
| 2. Shape of the third fix run: merged visible signature flagged Print, NoView and ToggleNoView (`/F 292`, `ssa-toggle-noview-shown.pdf`) | yes | as expected — `Sneaky` `AddedByRevisionNotAllowed`, the certification `RevisionNotAllowed` refusing objects 3, 6, 11, 12, 13 (`c2-each-shape.txt`) |
| 2. Shape: signature outside `/Fields`, only the page listing it | yes | finding 1 — the certification gets `RevisionNotAllowed`, but `validate` returns one signature only (`c2-each-shape.txt`) |
| 2. counter-cases — moved rect put back; unreadable rect hidden or made readable; layer, unlisted, orphan shapes left invisible; ToggleNoView varied: `/F 36` (NoView alone), `/F 294` (Hidden + NoView + ToggleNoView), `/F 260` (ToggleNoView without NoView) | yes | as expected — rect put back, unreadable rect hidden, `/F 36` and `/F 294`: the certification reads `Allowed([Signature])`; unreadable rect made readable and `/F 260`: `RevisionNotAllowed`; the three invisible variants still refused (the revision also removes `/OC`, rewrites the page or adds an annotation: fail-closed). Each edited signer's own digest fails by construction and masks its SSA verdict (`c2-each-shape-error.txt`) |
| 3. A field visible when certified, signed with no other change, stays sound; an invisible second signer on an uncertified PDF too | yes | as expected — `certified-visible-field-signed.pdf`: `Approver` no defect, certification `Allowed([Signature])`; `unsigned.pdf` signed twice with `nacre_pades::sign`: both no defect, `Allowed([Signature])`; an invisible signer appended to the certified P=2 `certified-form-fill.pdf`: `Allowed([FormFill])` then `Allowed([Signature])`, no defect; `signed-twice-pyhanko.pdf` and `Bob` of `fill-and-second-signature.pdf` no defect (`c3-honest-signers.txt`) |
| 3. invalid input — the prepared visible field signed at another `/Rect`; the signing program given a non-PDF, an empty file, no argument | yes | as expected — moved rect: certification `RevisionNotAllowed`; `sign` answers `the input does not start with %PDF-`, no output file written (`c3-honest-signers-error.txt`) |

## Findings
Status rule: **verified** means the steps were replayed and reproduced the defect, and an evidence file holds it; **probable** means it was seen once, or no evidence file could be kept; **unverified** means it is suspected from what the surface showed, not seen happening.

### Finding 1 — A visible signature outside `/Fields` is not reported, so it never carries `AddedByRevisionNotAllowed`
Severity: minor
Status: verified
Steps to reproduce:
1. In the scratch copy, build `qa-scen` (quoted in `c2-each-shape.txt`) against `crates/nacre-validate`.
2. Run `qa-scen attacks/ssa-outside-fields.pdf` from `crates/nacre-validate/tests/corpus`; run it again.
Capture: docs/qa/s40-validate-ssa-by-effect/c2-each-shape.txt: transcript
Expected: criterion 1 — the signature visible on the page while absent from the certified state carries `AddedByRevisionNotAllowed`, and the certification `RevisionNotAllowed`; an application that shows each signature of the PDF would show `Sneaky` as refused.
Observed: `signatures: 1` — only `Certification`, with `RevisionNotAllowed`. The `Sneaky` signature that page 3 draws is not in the result, so an application listing signatures shows one where the page shows two. The document is still not read as sound, and `docs/security/attacks/pades.md` and the test `ssa_outside_fields_is_rejected` state this outcome, so it is an announced limit, not a regression. The shape is not one of criterion 2's listed shapes. Unchanged since the two previous walks.

## Not seen
- Criterion 4, `docs/security/attacks/pades.md` describing the rule by its effect — a document, with no effect observable through the library's interface; left to the review.
- The certified-state side of the third fix run: a widget flagged NoView with ToggleNoView already in the certified state, then signed — the corpus holds no such file and `qa-sign` makes invisible signatures only, so only the "after" side (`ssa-toggle-noview-shown.pdf` and its three flag variants) was walked.
- A visible SSA on a P=1 document — the corpus has only an invisible late signature under P=1, refused by the P=1 rule alone; the by-effect pass was seen at P=2 and P=3 only.
- The SSA verdict on a counter-case's own signer — every counter-case is a same-length byte edit that breaks that signer's digest, and `validate` reports the CMS defect first; only the certification's verdict could be read.
- Whether a viewer (Acrobat, pdf.js) draws the orphan, unlisted, layer, outside-`/Fields`, unreadable-rect or ToggleNoView widgets (on hover) as the review supposes — Nacre does not render; only its verdict was seen.
- Files from real signers other than pyHanko (Acrobat and others) — none in the corpus.

Tree: fa962eba87b4f60a363208383cce9838b3b30760
QA status: complete
