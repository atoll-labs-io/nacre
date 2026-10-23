# Verification — s40-validate-ssa-by-effect

[Story](../stories.md) · [Plan](../plans/s40-validate-ssa-by-effect.md)

The link line under the title is part of this template: it is copied with it, never edited after the copy, and is not one of the implementer's lines.

The implementer writes this file before its final runs, then edits only `Tree:`, the `## Checks` table, "Not proven here" and the status line. `po-run` writes the `## Runs` section, one row per launch; no one else touches it. The gate compares the tree of each run with `Tree:` outside `docs/`: a declared check counts only through its runs on that code, and the last of them must have exited 0. Commands are copied exactly from `AGENTS.local.md`.

Order that produces `Tree:` — `git add -A`, then `git write-tree`. The hash therefore names the exact code the checks ran on. This file and the plan's ticks live inside `docs/`, which the comparison leaves out.

Tree: 9b4c368494bca6b30a669e05f0f091e51a029d28

## Checks
| Check | Command | Note |
| --- | --- | --- |
| Unit suite | `cargo test --workspace` | |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | |
| End to end | — | no such command in this project |
| Build | — | deferred to ship (`Build stage: ship-if-route`) |

A row with a command is a check you launch through `po-run`. A check not run at this stage, or one the project does not have, gets `—` as its command and says why in Note ("no such command in this project", "deferred to ship").

## Not proven here
- Lead decision applied (the plan's fallback for its decision 2): `/AP` is not part of "shown", so a new visible-rect signature with no `/AP` on a certified document stays refused as SSA, as in s15. `appears`, `certified-new-field-no-appearance.pdf` and `certified_new_field_without_appearance_is_allowed` were dropped; five corpus files and five tests added instead of six.
- Fix run (review fix loop 0): five more corpus files and five rejecting tests (orphan `/Parent` widget, widget absent from the certified `/Annots`, widget in an off layer, moved `/Rect`, signature outside `/Fields`); ten new tests in all.
- Fix run 2 (review fix loop 1): one more corpus file and test, `ssa-unreadable-rect.pdf` / `ssa_unreadable_rect_is_rejected`, for the fail-closed `Placement::Unknown` branch; no code change. Eleven new tests in all. The forge was rerun once: only the new file appeared, every other corpus file byte-identical.
- Fix run 3 (review fix loop 2, granted by the person past `Max attempts`): `placement` reads NoView with ToggleNoView as shown in the state after and as off in the certified state; one corpus file and test, `ssa-toggle-noview-shown.pdf` / `ssa_toggle_noview_shown_is_rejected`. Twelve new tests in all. The forge was rerun once: only the new file appeared, every other corpus file byte-identical. Whether a viewer draws that widget on hover was not checked.
- `/OC` is read as "not placed" in the certified state whatever the layer's state; the layer configuration (`/OCProperties`, `/D /ON /OFF`, usage) is not evaluated. In the state after, `/OC` and the page lists are ignored (fail closed).
- A certified widget moved to another page at the same rectangle is not seen by the by-effect rule; the certification still refuses it (`/Annots` only gains new signature fields). No corpus case.
- A kid field outside `/Fields` that inherits `/FT /Sig` from its parent without carrying `/FT` itself is not among the judged fields. No corpus case.
- DSS parity of the new verdicts (four refused shapes, the honest prepared-field signing) is not checked: s18 and s19 compare.
- The forge was rerun twice in each run: every earlier corpus file came out byte-identical (`git status` lists only the new files) and the new files kept their SHA-256. Not a `po-run` row.
- The fuzz target `crates/nacre-validate/fuzz/` was not run here; CI's `fuzz` job runs it.
- `cargo fmt -p nacre-validate` was applied, not recorded as a `po-run` row; formatting is checked at commit and in CI.

Verification status: complete

## Runs
Written by `po-run`, one row per launch. Never edit, reorder or delete a row.

| Check | Command | Exit | Tree | Time (UTC) |
| --- | --- | --- | --- | --- |
| Unit suite | `cargo test --workspace` | 0 | d8b82c91cde3261eb7aa6734ad7907c444313381 | 2026-10-23T13:07:11Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 955d038a06b038278f08f407c8c226cf1a5d728c | 2026-10-23T13:07:21Z |
| Unit suite | `cargo test --workspace` | 0 | 1bebc4032388d2f60f6cc89d1c6edc8c27e18b53 | 2026-10-23T13:25:24Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 9e6593d57d7e67d7b1e529b591263a18a0a0505f | 2026-10-23T13:25:31Z |
| Unit suite | `cargo test --workspace` | 0 | be1e05f9e9bdd315e6532d7c5697935bdee06999 | 2026-10-23T13:46:27Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 328388522d2011783bcb4e7302c98a77e6a476e3 | 2026-10-23T13:46:31Z |
| Unit suite | `cargo test --workspace` | 0 | 639d791161c65ada877c491451788bc94001cd29 | 2026-10-23T14:19:50Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 008299b3e8bc4cc55964fee49d6ef459d3696b2d | 2026-10-23T14:19:56Z |
