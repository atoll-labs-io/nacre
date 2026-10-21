# QA — s01-workspace-contract

[Story](../../stories.md) · [Plan](../../plans/s01-workspace-contract.md)

Scope: the story's surface, what `git diff main...story/s01-workspace-contract` touches on it, and the acceptance criteria its user can observe through it; nothing else was checked.
Driver: `scenarios.md` of qa-drivers — surface `endpoint`, platform `lib, cli` (row `endpoint` / `lib`; no `command` surface, so the `cli` row does not apply)
Evidence: transcripts
Tool: Bash (cargo 1.97.1, toolchain pinned by `rust-toolchain.toml`), on a copy of the tracked files in a `mktemp -d` directory; `Install` (`cargo fetch`) and `Build` (`cargo build --workspace --all-features`) run there, both exit 0
Origin: — (a library: nothing served)

Each `lib` scenario is a scratch crate outside the workspace depending on the copied `crates/nacre-core` by path, as a family or Patelle would; each transcript quotes the scratch crate whole.

## Coverage
| Criterion or item | Reached | Result |
| --- | --- | --- |
| 1. `cargo test --workspace`, `cargo clippy … -D warnings`, `cargo fmt --check` pass locally | yes | as expected: tests 1 + 2 + 2 passed (`contract_objects`, `contract_signer`, `report`), clippy and fmt exit 0 (`c1-checks-pass.txt`). Bad input: an appended, badly formatted `x.unwrap()` makes `fmt --check` exit 1 and clippy refuse it with `used unwrap() on an Option value` (`c1-checks-pass-error.txt`) |
| 1. … and in `.github/workflows/ci.yml` | no | not reached — see Not seen |
| 2. `Signer`, `TimestampAuthority`, `RevocationSource`, synchronous, no I/O | yes | as expected: a caller implements a TSA and a revocation source and uses all three through `&dyn`, as plain function calls; the TSA failure surfaces as `the timestamp authority failed` with its source `tsa unreachable` reachable through `Error::source`; `RevocationSource::revocation` takes the certificate and its issuer, as the plan's correction says (`c2-traits-c3-report-c4-test-signer.txt`). No `std::fs`, `std::net`, `SystemTime` or print in `src`, and `thiserror` is the only normal dependency (`c6-forbid-unsafe-gitignore.txt`) |
| 3. `ValidationReport`: indication, sub-indication, level, EN 319 102-1 names | yes | as expected: `TOTAL_PASSED` / `TOTAL_FAILED` / `INDETERMINATE` with their `urn:etsi:019102:mainindication:*` URNs, 25 sub-indications by their EN names, level as form + profile (`c2-traits-c3-report-c4-test-signer.txt`). Bad input: a `TOTAL_PASSED` report carrying a sub-indication cannot be built, because the fields are private (`c3-report-error.txt`) |
| 4. P-256 test signer behind `test-signer`, never default; signature verified with `p256` | yes | as expected: a 70-byte DER signature over a SHA-256 digest verifies with `p256` against the key of the chain's certificate (`CN=Nacre test signer,O=Nacre tests,C=FR`) and fails on an altered digest (`c2-traits-c3-report-c4-test-signer.txt`). With default features `TestSigner` is absent and rustc says it is gated behind `test-signer` (`c4-test-signer-default-features-error.txt`); it does not implement `Debug` (`c4-test-signer-debug-error.txt`). Digests of 20, 0 and 48 bytes are refused with `digest length is N bytes, the signature algorithm expects 32`; an invalid secret is refused, with a vague message — finding 1 (`c4-test-signer-error.txt`) |
| 5. CI fuzzes every target of every `crates/*/fuzz/` for 60 s, no later workflow edit | partly | the discovery step of the `fuzz` job, extracted verbatim and run locally: with no `fuzz/` folder it prints `no fuzz targets` and sets `dirs=` (the later steps are skipped by their `if`); with two folders added to a copy it sets `dirs=crates/nacre-a/fuzz crates/nacre-b/fuzz` with no edit (`c5-fuzz-discovery.txt`). The 60 s run of each target: not reached — see Not seen |
| 6. `#![forbid(unsafe_code)]` in `nacre-core`; `Cargo.lock` in `.gitignore` | yes | as expected: first line of `lib.rs`; `git check-ignore` matches `Cargo.lock` (`.gitignore:4`) and `target` (`c6-forbid-unsafe-gitignore.txt`). Bad input: an `unsafe` block under `#[allow(unsafe_code)]` does not compile, `overruled by previous forbid` (`c6-forbid-unsafe-gitignore-error.txt`) |

## Findings
Status rule: **verified** means the steps were replayed and reproduced the defect, and an evidence file holds it; **probable** means it was seen once, or no evidence file could be kept; **unverified** means it is suspected from what the surface showed, not seen happening.

### Finding 1 — An invalid test-signer secret is reported as "the signer failed" / "signature error"
Severity: minor
Status: verified
Steps to reproduce:
1. In a crate depending on `nacre-core` with feature `test-signer`, call `TestSigner::from_secret(&[0u8; 32])` (or `&[0xFF; 32]`, above the P-256 order).
2. Print the error's `Display` and its `std::error::Error::source`.
Capture: docs/qa/s01-workspace-contract/c4-test-signer-error.txt
Expected: an error that says what was wrong — the secret is not a valid P-256 scalar (the driver counts a message that does not say what was wrong as a finding).
Observed: `Err(Display = "the signer failed", source = Some("signature error"))` for both secrets: nothing names the secret or the key as the cause, and "signature error" suggests a signing failure although nothing was signed. The refusal itself is correct; only the wording misleads. `TestSigner` is test-only, so the reach is small.

## Not seen
- Criterion 1 in `.github/workflows/ci.yml`, both jobs green on GitHub Actions — a remote service the driver did not start; only the workflow's discovery step was replayed locally.
- Criterion 5, the `cargo +nightly fuzz list` / `fuzz run -- -max_total_time=60` loop — no `crates/*/fuzz/` exists yet (the plan leaves its first run to s03), `cargo-fuzz` and a nightly toolchain are not installed here, and the run happens on GitHub Actions.

Tree: b81b7195f12c7d768afbfcbec334e43156a1a8bf
QA status: complete
