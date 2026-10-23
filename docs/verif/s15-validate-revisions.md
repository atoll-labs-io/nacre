# Verification — s15-validate-revisions

[Story](../stories.md) · [Plan](../plans/s15-validate-revisions.md)

The link line under the title is part of this template: it is copied with it, never edited after the copy, and is not one of the implementer's lines.

The implementer writes this file before its final runs, then edits only `Tree:`, the `## Checks` table, "Not proven here" and the status line. `po-run` writes the `## Runs` section, one row per launch; no one else touches it. The gate compares the tree of each run with `Tree:` outside `docs/`: a declared check counts only through its runs on that code, and the last of them must have exited 0. Commands are copied exactly from `AGENTS.local.md`.

Order that produces `Tree:` — `git add -A`, then `git write-tree`. The hash therefore names the exact code the checks ran on. This file and the plan's ticks live inside `docs/`, which the comparison leaves out.

Tree: 0aea21d5fde32bd035a0221bc838c899704535d3

## Checks
| Check | Command | Note |
| --- | --- | --- |
| Unit suite | `cargo test --workspace` | |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | |
| End to end | — | no such command in this project |
| Build | — | deferred to ship (`Build stage: ship-if-route`) |

A row with a command is a check you launch through `po-run`. A check not run at this stage, or one the project does not have, gets `—` as its command and says why in Note ("no such command in this project", "deferred to ship").

## Not proven here
- DSS parity of the revision verdicts (allowed DSS, timestamps, signatures and fills; the refused shadow, EAA and SSA cases; `TOTAL_FAILED` / `FORMAT_FAILURE` for a refused revision) is not checked: no bench run in this story; s18 and s19 compare.
- Criterion 4 is proven on pyHanko's B-LTA file only; s12 has not shipped and must re-run `lta_dss_and_timestamp_are_allowed`'s check on its own output.
- The fuzz target `crates/nacre-validate/fuzz/` was not run here; CI's `fuzz` job runs it at each push.
- The forge reproduces the corpus byte for byte: run twice, `sha256sum -c` against the first run's sums, all identical. Not a `po-run` row.
- Fix run: the cost of `Document::doc_mdp_level` on a hostile `/Reference` array was not timed. Its reading now goes through one `Resolver` (each object stream decoded once per state) and refuses more than 32 entries; `doc_mdp_references_over_the_cap_are_refused` covers the cap, while the shared resolver is checked by reading only, since its result is the same either way.
- Fix run: the forge was rerun after the change; the 21 earlier corpus files came out byte-identical and the two new ones (`shadow-dss-page.pdf`, `shadow-fill-late-definition.pdf`) kept their SHA-256 across two runs.
- Fix run 2: `AddedByRevisionNotAllowed` now fires only for a signature its own revision refuses as a signature (SSA, DocMDP 1); `fill-and-second-signature.pdf` and `certified-p1-second-signature.pdf` cover both sides. A DocMDP permission the reader refuses makes only the revision that introduces it `Unreadable`, its objects listed, and the next revisions are judged as under `/P 1` (`docmdp-reference-cap.pdf`). The forge was rerun twice: the 30 earlier corpus files came out byte-identical and the three new ones kept their SHA-256. No DSS comparison of the second-signer verdict was made.
- Fix run 3: a signature is `AddedByRevisionNotAllowed` when the document is certified, a widget of its field (the field itself when merged, or one of its `/Kids`) is visible, and that field is absent from the first certified state, whether the signing revision or an earlier one added it; `ssa-split-widget.pdf` and `ssa-empty-field-signed.pdf` cover the two shapes, and the honest second signers (`fill-and-second-signature.pdf`, `signed-twice-pyhanko.pdf`, `certified-dss.pdf` signed again) stay sound. `docmdp-reference-cap.pdf` now ends with an invisible signature `Late`, refused only because the unreadable permission counts as `/P 1`. The forge was rerun twice: every earlier file except `docmdp-reference-cap.pdf` came out byte-identical, and the three changed or new files kept their SHA-256 across both runs. Neither verdict was compared with DSS.
- `cargo fmt --all` was applied to the final code, not recorded as a `po-run` row; formatting is checked again at commit and in CI.

Verification status: complete

## Runs
Written by `po-run`, one row per launch. Never edit, reorder or delete a row.

| Check | Command | Exit | Tree | Time (UTC) |
| --- | --- | --- | --- | --- |
| Unit suite | `cargo test --workspace` | 0 | d81a3eccbb3ae6b20d803b8d9328d4e8bb3753ee | 2026-10-22T12:34:22Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | b88d2ea6eeaba8e86ffb6ff42839da99c5f6f637 | 2026-10-22T12:34:33Z |
| Unit suite | `cargo test --workspace` | 0 | fdaf556c2f8930118b89ad9fcc8f65432ef87fd4 | 2026-10-22T12:51:01Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | a3535a7a79f614678dfdda0c2d9b76499b3b32c7 | 2026-10-22T12:51:02Z |
| Unit suite | `cargo test --workspace` | 0 | 9ef35eb6355394c671238290b73483cb55771eac | 2026-10-23T09:10:08Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 418932480de5bc8eff5ea2ce727a7b84d0223971 | 2026-10-23T09:10:12Z |
| Unit suite | `cargo test --workspace` | 0 | e395af4554b320d103af6ad1942436458c15afa5 | 2026-10-23T12:17:36Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 3eaa493584311fae740bce0f0dacd8c304791224 | 2026-10-23T12:17:40Z |
