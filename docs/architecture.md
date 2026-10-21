# Architecture — Nacre

Written by `/po-architect`, committed on the target branch. Research and planning read it before touching the code. Change it through `/po-architect` again: a decision that changes gets a new ADR superseding the old one.

## Base
- **Name**: empty repository
- **Origin**: none; story s01 creates the cargo workspace
- **Licence**: MIT OR Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`)
- **Profile**: analysis only (no base to analyse)
- **Decision**: [ADR-0002](decisions/0002-empty-repository-base.md)

## Map
No code exists yet. The layout below is decided by [ADR-0003](decisions/0003-cargo-workspace-one-crate-per-family.md); each path is created by the story named.

| Kind | Path | Created by |
| --- | --- | --- |
| Workspace root | `Cargo.toml`, `rust-toolchain.toml` | s01 |
| Shared core (traits, report) | `crates/nacre-core/` | s01 |
| Family crates | `crates/nacre-<family>/` (`cms`, `pdf`, `pades`, `tsp`, `revocation`, `validate`, `pkcs11`, then `cades`, `asic`, `xml`, `xades`, `jose`, `jades`, `cose`, `openpgp`, `ssh`, `minisign`, `csc`, `trust`) | s03 to s36 |
| Facade | `crates/nacre-sig/` | s20, s37 |
| Fuzz targets | `crates/<crate>/fuzz/` | each parser story |
| Test corpus | `crates/<crate>/tests/corpus/` | each story |
| Conformance bench | `conformance/` (`compose.yaml`, `pki/`, `campaign/`, `corpus/foreign/`), `crates/nacre-conformance/` | s02, s18, s19 |
| Known attacks | `docs/security/attacks/<format>.md` | each format story |
| CI | `.github/workflows/ci.yml`, `.github/workflows/conformance.yml` | s01, s02 |

Routes, migrations, policies and UI components: none, Nacre is a library.

## Capabilities
Nacre is a library with no server, storage or users of its own (brief, non-goals): no application capability applies.

| Capability | Brick | Alternatives | ADR |
| --- | --- | --- | --- |
| Database | not needed: a library that stores nothing | — | — |
| Auth | not needed: no accounts; key access goes through `Signer` | — | — |
| Authorization | not needed | — | — |
| Multi-tenancy | not needed | — | — |
| Files | not needed: callers pass bytes in and get bytes out | — | — |
| Jobs | not needed: renewing an archive timestamp is the caller's decision (s12) | — | — |
| Email | not needed | — | — |
| Payment | not needed: free, MIT OR Apache-2.0 | — | — |
| Cache and rate limiting | not needed | — | — |
| Observability | not needed: errors are returned, nothing is logged (conventions) | — | — |
| i18n | not needed: error messages in English | — | — |
| Deployment | not needed: published to crates.io by a person (brief, Operations) | — | — |

Integrations and building blocks:

| Need | Brick | Alternatives | ADR |
| --- | --- | --- | --- |
| Stack and layout | Rust 2024, cargo workspace, one crate per family, `nacre-sig` facade | one crate with modules; one repository per family | [ADR-0003](decisions/0003-cargo-workspace-one-crate-per-family.md) |
| Primitives and PKIX models | RustCrypto: `der`, `spki`, `x509-cert`, `x509-ocsp`, `p256`, `sha2`, `ed25519-dalek`, `rsa` | OCSP written on `der`; X.509 in Nacre | [ADR-0004](decisions/0004-rustcrypto-foundations-and-x509-boundary.md) |
| Hardware keys | `cryptoki` | own bindings; `pkcs11` | [ADR-0005](decisions/0005-pkcs11-through-cryptoki.md) |
| HTTP (feature `http`) | `ureq` | `reqwest` blocking; `minreq` | [ADR-0006](decisions/0006-http-through-ureq.md) |
| Conformance judge | DSS 6.5.1 in a local container, plus each format's reference tool | pyHanko; the online demo | [ADR-0007](decisions/0007-dss-local-pinned-conformance-judge.md) |
| Fuzzing | `cargo-fuzz` | `afl.rs`; `bolero`; `proptest` alone | [ADR-0008](decisions/0008-fuzzing-with-cargo-fuzz.md) |
| Encodings and containers | `miniz_oxide`, `roxmltree`, `serde_json`, `ciborium`, `zip` | `flate2`, `quick-xml`, `minicbor`; writing them in Nacre | [ADR-0009](decisions/0009-encodings-from-existing-crates.md) |

## Ownership
- `Cargo.toml`, `rust-toolchain.toml`, `.gitignore`, `.github/workflows/ci.yml` — shared: s01 only, then a contract story.
- `crates/nacre-core/` — shared: s01 only, then a contract story (every family codes against it).
- `conformance/` and `crates/nacre-conformance/` — shared: s02, then s18 (`campaign/`) and s19 (`corpus/foreign/`) along their dependency chain.
- `crates/nacre-<family>/` — owned by one story at a time, in the order of its family's stories.
- `crates/nacre-sig/`, `README.md`, `CHANGELOG.md` — owned by s20, then s37.
- `docs/security/attacks/<format>.md` — owned by the stories of that format, in order.

## Attachment points
No code yet; these are where work plugs in once s01 and s20 exist.
- `Cargo.toml` — `members = ["crates/*"]`: a new crate joins the workspace by its folder alone.
- `.github/workflows/ci.yml` — fuzz job over every `crates/*/fuzz/`: a new target needs no workflow change.
- `crates/nacre-core/src/lib.rs` — the `Signer`, `TimestampAuthority`, `RevocationSource` traits and `ValidationReport`: each family implements or returns them.
- `crates/nacre-sig/Cargo.toml` — one optional dependency and one feature per family.

## Commands
Quoted from `AGENTS.local.md`, never decided here.

| Setting | Value |
| --- | --- |
| Package manager | cargo |
| Install | cargo fetch |
| Test | cargo test --workspace |
| Typecheck | cargo clippy --workspace --all-targets --all-features -- -D warnings |
| E2E | — |
| Build | cargo build --workspace --all-features |

`cargo test` filters by test target and name rather than by file path: a single task's tests run with `cargo test -p <crate> --test <file stem>`.

## Conventions
The rules live in the « Conventions » section of `AGENTS.local.md`, which every agent loads through `AGENTS.md`. This file does not repeat them.
