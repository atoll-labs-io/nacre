# nacre — Polype settings

This file is the project's. Polype's installer never rewrites it; `/po-setup` writes it once and you edit it afterwards. Rules live in `AGENTS.md`, which the installer regenerates — do not edit that one.

Format: one `Name: value` per line inside the blocks below, with no comment after the value (anything after the colon is the value, except a final `(forge)` or `(chosen)` on `Ship confirmation`, which records where the value came from). After a change, rerun the installer so the conventions at the bottom reach `AGENTS.md`.

## Pipeline

```
Merge mode:        pr
Target branch:     main
Plan validation:   autonomous
Ship confirmation: automatic (chosen)
Test budget:       25
Verification mode: record
Full suite:        execute-end
E2E stage:         ship
E2E scope:         nominal
E2E browsers:      —
Build stage:       ship-if-route
Platform:          lib, cli
QA stage:          surfaces
Issue tracker:     github
Worktree root:     .worktrees/
ADR directory:     docs/decisions/
Entry mode:        new
Design source:     —
Design skill:      —
Design tool:       —
Story track:       auto
Flow threshold:    2
Parallel:          3
Max attempts:      2
Tracker:           none
Model strong:      opus
Model light:       sonnet
Light up to:       2
Project CLAUDE file: absorbed
```

| Setting | Values |
| --- | --- |
| Merge mode | `pr` — a pull request to the target branch, landed as one commit · `local` — only for a repository without a remote: the commit lands on this machine and nothing is pushed |
| Target branch | where finished stories land |
| Plan validation | `human` — you approve each plan · `autonomous` — the planner approves its own and says so; the default, since a human is asked only for the reasons ADR-0077 names |
| Ship confirmation | `human` — you approve each merge · `automatic` — the review gate is enough. A final `(forge)` means the value follows the repository and `/po-ship` keeps it in line at each ship; `(chosen)` is the person's choice on a solo repository, never rewritten by an agent; no suffix reads `(forge)`. A collaborative repository gives `human (forge)` whatever the line says |
| Test budget | maximum tests per story before the plan must justify more |
| Verification mode | `record` — a review reuses a current verification record · `rerun` — a review repeats the checks |
| Full suite | where the complete unit suite runs: `execute-end` · `ship` · `both` |
| E2E stage | where end-to-end tests run: `ship` · `ci` · `—` |
| E2E scope | how much end-to-end runs; `nominal` means one happy path |
| E2E browsers | browsers used before ship, e.g. `chromium`; `—` leaves the project default. Ship always uses all of them |
| Build stage | where the production build runs: `ship-if-route` (only when routing or a manifest changed) · `ship` · `ci` · `—` |
| Platform | what the project builds, one or more of `web` · `mobile` · `cli` · `api` · `lib` · `xr` · `robot`, separated by commas; it decides which boilerplate profiles `/po-setup` offers and which `Surface` a story may declare (ADR-0054, ADR-0055) |
| QA stage | `screens` — /po-qa walks the screens a story touches before its review · `surfaces` — /po-qa checks every story whose `Surface` is not `—`, with the driver of that surface (ADR-0054) · `—` — no QA stage |
| Issue tracker | where ideas, features and defects to handle are filed, and the findings a shipped review leaves open: `github` · `taskwarrior` · `—`; `—` sends them to the person |
| Worktree root | folder that holds story worktrees, ending with `/`; kept out of git by `.gitignore` |
| ADR directory | where the project's ADRs live, with its own numbering; ends with `/` |
| Entry mode | where the project starts: `replace` — build an internal replacement of a paid SaaS · `adapt` — a competing product with its own angle · `new` — an idea from scratch · `—` not chosen yet |
| Design source | who draws the screens: `internal` — screens drawn in the repository by an agent skill · `external` — a tool outside the repository · `—` means design commands stop and ask |
| Design skill | skill that draws the screens when `Design source` is `internal`; `—` otherwise |
| Design tool | tool the screens come from when `Design source` is `external`; `—` otherwise |
| Story track | `full` — every story walks every stage · `flow` — every story takes the short track · `auto` — the short track up to `Flow threshold` |
| Flow threshold | highest story complexity allowed on the short track when `Story track` is `auto` |
| Parallel | how many story lanes the fleet driver runs at once |
| Max attempts | fix runs a story gets before the fleet driver hands it to a human |
| Tracker | where the fleet publishes story state: `none` · `github` when the repository has a remote |
| Model strong | the model every deciding subagent (planner, designer, reviewer, qa, stories-reviewer) runs on: a name the Agent tool accepts, or `—` for the session's model |
| Model light | the model the implementer runs on for a story whose complexity is at most `Light up to`: a name the Agent tool accepts, or `—` for the session's model |
| Light up to | highest story complexity whose implementer runs on `Model light`; `—` means never |
| Project CLAUDE file | `absorbed` — the installer moves a root `CLAUDE.md` or `CLAUDE.local.md` into `AGENTS.local.md` and the pre-commit refuses one at any depth (ADR-0086) · `kept` — both stay, the root `CLAUDE.md` starts with `@AGENTS.md` and the pre-commit lets them through (ADR-0089); with the line missing nothing is touched, and the installer, `check` and `po-session` name the setting |

## Commands

```
Package manager:   cargo
Install:           cargo fetch
Test:              cargo test --workspace
Typecheck:         cargo clippy --workspace --all-targets --all-features -- -D warnings
E2E:               —
Build:             cargo build --workspace --all-features
Dev:               —
```

Agents run these exactly as written. `—` means the project has no such command, and no agent will make one up. `Test` has to accept paths to test files, so a single task's tests can run alone. `Dev` starts the development server, or whatever serves what a person looks at (the web render of a mobile app), and prints the address it serves; `—` when the project has nothing to serve. QA of a `screen` surface needs it; the other drivers start what they check themselves.

## Conventions

No code exists yet (ADR-0002): these rules come from the ADRs and the stories, and story s01 makes the base show them. Each rule names its source.

- Layout: one crate per family at `crates/nacre-<family>/`, the facade at `crates/nacre-sig/` imported as `nacre`; the root `Cargo.toml` (`members = ["crates/*"]`) is never edited after s01 (ADR-0003).
- Each crate declares its own dependency versions; never add `[workspace.dependencies]` outside a contract story (ADR-0003).
- `Cargo.lock` stays out of git (ADR-0003).
- Edition 2024, `rust-version = "1.97"` in every crate (ADR-0003).
- Every crate starts with `#![forbid(unsafe_code)]`; only `nacre-pkcs11` may relax it, and only for a call `cryptoki` cannot make safely (ADR-0005, brief Security & abuse).
- Parsing code never panics on input: `clippy::unwrap_used`, `clippy::expect_used`, `clippy::panic` and `clippy::indexing_slicing` are denied outside `#[cfg(test)]`; every length, depth and size read from input is bounded (brief, Security & abuse).
- Errors are one `thiserror` enum per crate, returned, never logged; no crate writes to stdout, stderr or a logger.
- A secret (PIN, token, key handle) is held in a `zeroize` type and never derives or implements `Debug` or `Display` with its value.
- No judging code reads the system clock: the control date is a parameter (s09, s16, s17).
- No crate opens a network connection outside the implementations behind its `http` feature; the core goes through the `Signer`, `TimestampAuthority` and `RevocationSource` traits of `nacre-core` (ADR-0006, s01).
- Primitives, DER, certificates, CRLs and OCSP structures come from RustCrypto (`der`, `spki`, `x509-cert`, `x509-ocsp`); every signature format is written in Nacre; never add the `cms` or `x509-tsp` crates (ADR-0001, ADR-0004).
- Encodings come from `miniz_oxide`, `roxmltree`, `serde_json`, `ciborium` and `zip` (ADR-0009).
- Each parser has a cargo-fuzz target in `crates/<crate>/fuzz/`; each crash found becomes a corpus file before its fix (ADR-0008).
- Test data lives in `crates/<crate>/tests/corpus/` and is fictitious or public, its source noted in a `README.md` next to it; real documents never enter the repository (brief, Security & abuse).
- Each format keeps its known attacks in `docs/security/attacks/<format>.md`, one corpus case and one rejecting test per attack (brief, pre-mortem finding 4).
- Conformance tests that need DSS or SoftHSM are `#[ignore]`d with the reason `"conformance"` and run by `.github/workflows/conformance.yml` (`cargo test -- --ignored`) against `conformance/compose.yaml` (ADR-0007).
- A conformance test asserts the exact level DSS reports, never the indication alone (brief, premise 4).
- A family written for the exercise says "experimental" at the top of its crate documentation until it is fuzzed and cross-checked against its reference crate (brief, Security & abuse).
- Code, comments, rustdoc, `README.md` and `CHANGELOG.md` are in English; framing documents under `docs/` are in French.
- Commit messages follow the repository's style: `<type>: <summary>` (`docs:`, `chore:`), and `<id>: <story title>` for a story's landing.
