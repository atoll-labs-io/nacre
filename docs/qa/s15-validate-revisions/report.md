# QA — s15-validate-revisions

[Story](../../stories.md) · [Plan](../../plans/s15-validate-revisions.md)

Scope: the story's surface, what `git diff main...story/s15-validate-revisions` touches on it, and the acceptance criteria its user can observe through it; nothing else was checked.
Driver: scenarios.md of qa-drivers — surface endpoint, platform lib (setting `Platform: lib, cli`; the `cli` row applies only to a `command` surface)
Evidence: transcripts
Tool: Bash — a scratch binary crate (`qa-scen`, quoted whole at the end of each transcript) in a `mktemp -d` copy of `git ls-files`, depending on `crates/nacre-validate` by path and calling the public `nacre_validate::validate`; `cargo fetch` and `cargo build --workspace --all-features` ran in the copy (exit 0)
Origin: —

This walk replaces the one recorded on tree `1eb2bd7…`: the fix commit `4d08296` changed the code, so every scenario was run again on the tree below, and the two corpus files that commit added (`ssa-split-widget.pdf`, `ssa-empty-field-signed.pdf`) and the rebuilt `docmdp-reference-cap.pdf` were walked too. Every scenario the previous walk ran gave byte-identical output, except `docmdp-reference-cap.pdf`, whose last revision is now a signature.

## Coverage
| Criterion or item | Reached | Result |
| --- | --- | --- |
| 1. Each later revision listed and qualified, allowed (`/DSS`, document timestamp, new signature, DocMDP-permitted fill) or not, with the objects it changes | yes | as expected — `Allowed([Signature])` on `signed-twice-pyhanko.pdf`, `Allowed([FormFill])` on `certified-form-fill.pdf`, `Allowed([Dss, DocumentTimestamp])` then `Allowed([Dss])` on `signed-lta-pyhanko.pdf`, `NotAllowed` with `refused` ids under P=1 and on a FieldMDP-locked field; `fill-and-second-signature.pdf` and `certified-p1-second-signature.pdf` as before. `docmdp-reference-cap.pdf` now reports the capped revision `Unreadable` with `changed=[1, 12]`, then the invisible signature `Late` `NotAllowed` (objects 3, 6, 13, 14 refused) and `Late` itself `TOTAL_FAILED` with `AddedByRevisionNotAllowed { end: 24327 }` (`c1-later-revisions-qualified.txt`) |
| 1. invalid input — no argument, missing, empty, non-PDF file; an empty xref-only revision; 64 and 66 revisions after the signature; a later revision pointing DocMDP at a `/Reference` array of 32 and of 40 entries; a form fill appended after each | yes | as expected — `MissingHeader` errors of kind `InvalidInput`; an empty revision gives `Allowed([])`; 64 revisions all qualified, 66 give `TooManyRevisions { count: 66, max: 64 }`; 32 references give `NotAllowed`, a later fill there `Allowed([FormFill])`; 40 references give `Unreadable` with `changed=[1, 20]`, a later fill `NotAllowed`; no panic from the library (`c1-later-revisions-qualified-error.txt`) |
| 2. Shadow hide, replace, hide-and-replace never `TOTAL_PASSED` | yes | as expected — all three, plus `shadow-late-definition`, `shadow-form-field`, `shadow-fill-late-definition` and `shadow-dss-page`, end `TOTAL_FAILED / FORMAT_FAILURE`, `RevisionNotAllowed`, digest and signature verified (`c2-shadow-attacks.txt`) |
| 2. invalid input — signed file truncated mid-revision, broken revision appended | yes | as expected — `TrailingData { offset: 46212 }` and `NotAnXrefSection { offset: 999999 }`, both `InvalidInput`, no verdict given (`c2-shadow-attacks-error.txt`) |
| 3. EAA and SSA on certified PDFs detected | yes | as expected — `eaa-freetext.pdf` ends `TOTAL_FAILED`, `RevisionNotAllowed`; on `ssa-visible-signature.pdf`, `ssa-split-widget.pdf` (field and visible widget as separate objects) and `ssa-empty-field-signed.pdf` (empty visible field added, signed in the next revision) the certification signature ends `TOTAL_FAILED`, `RevisionNotAllowed`, and `Sneaky` ends `TOTAL_FAILED / FORMAT_FAILURE` with `AddedByRevisionNotAllowed` (`c3-eaa-ssa.txt`) |
| 3. invalid input — a certified file given an empty visible signature field, never signed | yes | as expected — the revision adding the field is `NotAllowed` (objects 3, 8, 9, 10 refused), the certification `TOTAL_FAILED`, `RevisionNotAllowed { end: 10562 }` (`c3-eaa-ssa-error.txt`). Adding an empty signature field is refused even under P=2: no row of the plan's rule table accepts a new signature field without `/V`, so this follows the plan |
| 4. A B-LTA adding `/DSS` and `/DocTimeStamp` is not flagged | yes, on pyHanko's LTA file | as expected — `INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND`, no defect, both later revisions `Allowed` (`c4-lta-not-altered.txt`) |

## Findings
Status rule: **verified** means the steps were replayed and reproduced the defect, and an evidence file holds it; **probable** means it was seen once, or no evidence file could be kept; **unverified** means it is suspected from what the surface showed, not seen happening.

None on this tree.

## Not seen
- Criterion 4 on Nacre's own B-LTA output — s12's output was not regenerated here; only pyHanko's LTA file was checked (the plan's own limit; s12 is to re-run it).
- Files from real signers other than pyHanko (Acrobat and others) — none in the corpus; s19's foreign corpus is the wider check.
- An `Unreadable` revision caused by a state that fails to parse or to walk — every truncated or broken input tried was refused by `Document::parse` as a whole, with an error; the only `Unreadable` reached comes from the DocMDP bound.
- An SSA variant signed with a new key or a new CMS built for this walk — the scenario program has no signer; new shapes were checked only through the corpus files and truncations of them.

Tree: 01c707683773d66253d174bb8c4da4216606d9f1
QA status: complete
