---
validated: yes
---
# Plan — s02-conformance-harness

[Story](../stories.md) · [Research](../research/s02-conformance-harness.md)

Branch `story/s02-conformance-harness`. Read `docs/research/s02-conformance-harness.md` first; this plan builds on it without repeating it.

The bench's PKI, TSA, OCSP responder and CRL server are settled by [ADR-0011](../decisions/0011-bench-pki-tsa-ocsp-on-openssl.md), accepted by the owner on 2026-10-22: OpenSSL in one Alpine container behind `busybox httpd` CGI. Turned down: Rust test servers, EJBCA Community, DSS's own services, a Python toolchain. The owner asks that the bench stay light enough for a laptop, never limit what can be tested, and catch drift at once (task 8's daily schedule).

## Story
A replayable bench that submits a signed file to a local, pinned DSS and reads the exact level, with a test PKI and a local TSA.
- `conformance/compose.yaml` runs DSS pinned, a local RFC 3161 TSA and an OCSP responder; an HTTP server serves the PKI's CRL.
- `conformance/pki/` generates, by a rerunnable script, a root, an intermediate, a signer, a TSA certificate, a revoked certificate and the matching CRL, with test keys published for that use only.
- `nacre-conformance` (`publish = false`) submits a file to DSS's REST validation, with the bench's anchors (research: no per-request anchors exist), and returns indication, sub-indication and level read from the simple report; the XML report (the ETSI `ValidationReport`, research) is kept under `target/conformance/`.
- A test submits a reference signed PDF shipped with the bench and checks the exact level.
- `.github/workflows/conformance.yml` starts the bench and runs the conformance tests; the reports are CI artefacts.

## Reuse
| New code | Rung that holds | Why each rung above fails |
| --- | --- | --- |
| `conformance/dss/` image | Already here, next door: Patelle `story/s01-sign-decision:conformance/dss/Containerfile:1-24` and `dss-custom.properties:1-8`, copied, plus two `sed` lines on Tomcat's `server.xml` | — (copy, not a reference: Patelle is another repository and must not be modified) |
| DSS request shape and simple-report reading | Already proven: Patelle `lib/tests/support/dss.rs:19-48` (endpoint, body, `SignatureFormat`) | — rewritten without its `unwrap`/`expect`/`[…]`, denied here (`Cargo.toml:5-9`) |
| Indication, sub-indication, level types | `nacre_core::{ValidationReport, Indication, SubIndication, SignatureLevel, SignatureForm, SignatureProfile}` (`crates/nacre-core/src/report.rs:94-178`); `SubIndication::ALL` + `as_str()` (`report.rs:44-60`) give the string → enum lookup | — |
| DSS format string → `SignatureLevel` | New code, a match in `nacre-conformance` | `nacre-core` has enum → string only (`report.rs:15-20`) and is frozen (`docs/architecture.md:61`) |
| HTTP, JSON, base64 | Dependencies: `ureq` 3 without TLS (ADR-0006), `serde_json` (ADR-0009), `base64ct` (already in the graph, `Cargo.lock:18-19`) | Standard library has no HTTP client nor base64 |
| PKI, TSA, OCSP, CRL server | Platform tools: OpenSSL + `busybox httpd` (ADR-0011, proposed) | Nothing in the repository; a new Rust server is rung 4 and option 2 of the ADR |
| Smoke checks of the bench | Platform tools: `openssl ts -query/-verify`, `openssl ocsp`, `curl` in `conformance/check.sh` | A Rust test per service would spend the test budget on infrastructure |

## Tasks
Order matters: tasks 5 and 6 record files that task 5's offline tests read, and need the bench of tasks 1-4 running.

1. [x] **PKI** — `conformance/pki/`: `Containerfile` (Alpine pinned by tag and digest, `apk add openssl busybox-extras`), `openssl.cnf`, `generate.sh` (POSIX sh, OpenSSL ≥ 3.2, runnable on the host or in that image), `README.md`. All keys P-256; fixed validity `20260101000000Z`–`20460101000000Z`; outputs committed under `conformance/pki/`: `root`, `intermediate` (CA, CDP `http://127.0.0.1:18081/crl/root.crl`), `signer` (`digitalSignature`, `nonRepudiation`), `tsa` (`extendedKeyUsage` critical `timeStamping`), `revoked` (same profile as `signer`, then revoked), each with `.key.pem`/`.cert.pem`; leaf certificates carry CDP `http://127.0.0.1:18081/crl/intermediate.crl` and OCSP AIA `http://127.0.0.1:18081/ocsp`; `root.crl` and `intermediate.crl` (the latter lists `revoked`), `crldays` 7300; the `openssl ca` index for the responder; `anchors.p12` (root only, password `nacre-anchors`, `openssl pkcs12 -export -nokeys -jdktrust anyExtendedKeyUsage`). README: test keys for this bench only, regeneration changes every key and requires redoing task 5. Check: `openssl verify -CAfile root.cert.pem -untrusted intermediate.cert.pem signer.cert.pem` prints OK, `openssl crl -in intermediate.crl -noout -text` lists the `revoked` serial; both become lines of `check.sh` (task 4).
2. [x] **Responders** — `conformance/pki/serve.sh` (entrypoint): copies the read-only `/pki` mount to a writable state dir, then `busybox httpd -f -p 127.0.0.1:18081` serving `/crl/*.crl` statically, `POST /tsa` (CGI: reads exactly `CONTENT_LENGTH` bytes, `openssl ts -reply -config … -queryfile -`, answers `Content-Type: application/timestamp-reply`) and `POST /ocsp` (CGI: `openssl ocsp -index … -CA intermediate -rsigner intermediate -rkey … -reqin - -respout - -nmin 5`, answers `application/ocsp-response`, nonce echoed). Check: lines of `check.sh` — `openssl ts -query -sha256 -cert | curl --data-binary` then `openssl ts -verify -CAfile root -untrusted intermediate` succeeds; `openssl ocsp -url http://127.0.0.1:18081/ocsp -issuer intermediate -cert signer` says `good`, for `revoked` says `revoked`.
3. [x] **DSS image** — `conformance/dss/Containerfile` copied from Patelle (same base images, version 6.5.1, same SHA-256), plus `sed` on `conf/server.xml`: connector `port="18080" address="127.0.0.1"`, shutdown port `-1`; `dss-custom.properties` naming `nacre-anchors.p12`/`nacre-anchors`, `cron.tl.loader.enable = false`, nothing else disabled; `README.md` (English): build, run, anchors, never the online demo. Check: task 4's wait loop gets `200` on `http://127.0.0.1:18080/`.
4. [x] **Compose and check** — `conformance/compose.yaml`: services `dss` (`image: localhost/nacre-dss:6.5.1`, `build` from `./dss`, `./pki/anchors.p12` mounted read-only at `/usr/local/tomcat/lib/nacre-anchors.p12`) and `pki` (`image: localhost/nacre-pki`, `build` from `./pki`, `./pki` mounted read-only at `/pki`), both `network_mode: host`; no `:Z` suffix. `conformance/check.sh`: waits up to 300 s for DSS and the CRL URL, then runs the smoke lines of tasks 1-2; exits non-zero on the first failure. `conformance/README.md`: `podman compose -f conformance/compose.yaml up -d`, `sh conformance/check.sh`, ports 18080/18081, env vars of task 6. Check: `check.sh` exits 0 against the running bench, with `patelle-dss` still on 8080.
5. [x] **Reference PDFs and recorded reports** — `conformance/reference/`: `unsigned.pdf` (hand-written one-page fictitious PDF), `generate.sh` (curl + jq + openssl against the bench: `getDataToSign` with `PAdES_BASELINE_B`, `ENVELOPED`, `SHA256`, `ECDSA`, signer + intermediate as chain → `openssl dgst -sha256 -sign` → `signDocument`), producing `pades-baseline-b.pdf` (signer) and `pades-baseline-b-revoked.pdf` (revoked certificate), then posting each to `validateSignature` and saving the raw responses as `crates/nacre-conformance/tests/corpus/dss-6.5.1-pades-baseline-b.json` and `…-revoked.json`; `README.md` next to each folder naming the source (produced by DSS 6.5.1 with the bench PKI, date). Check: the first response shows `TOTAL_PASSED` and `PAdES-BASELINE-B`; if not, fix the PKI or anchors (research, open questions) before going on — never loosen DSS's policy.
6. [x] **`nacre-conformance` crate** — `Cargo.toml` (`publish = false`, edition 2024, `rust-version = "1.97"`, MIT OR Apache-2.0, `[lints] workspace = true`; deps `thiserror` 2, `serde_json` 1, `base64ct`, `nacre-core` by path; `ureq` 3 `default-features = false, features = ["json"]` optional behind feature `http`, none by default; dev-dependency on itself with `http`, as `crates/nacre-core/Cargo.toml:24`). `src/lib.rs` with `#![forbid(unsafe_code)]`, rustdoc in English:
   - `Error` (thiserror): `Url`, `Http` (feature `http`), `Json`, `Report(&'static str)`, `Io`.
   - `parse_response(&[u8]) -> Result<Reports, Error>`: reads `SimpleReport.signatureOrTimestampOrEvidenceRecord`, keeps `Signature` entries in report order as `SignatureVerdict { id, format: String, report: ValidationReport }`; `Indication`/`SubIndication` matched against `as_str()` names; TOTAL_PASSED with a sub-indication, or another indication without one, is `Error::Report`; decodes `validationReportDataHandler` into `Reports::etsi_xml`. Every read through `.get()`; no panic on any input.
   - `level(format: &str) -> Option<SignatureLevel>`: `<CAdES|PAdES|XAdES|JAdES>-BASELINE-{B,T,LT,LTA}` and the extended names of `SignatureProfile`; anything else (`PDF-NOT-ETSI`, `UNKNOWN`) → `None`, the raw `format` staying available.
   - Feature `http`: `Dss::new(base_url)` refuses any URL that is not `http://127.0.0.1:<port>` or `http://localhost:<port>` (never the online demo, brief Security & abuse); `Dss::from_env()` reads `NACRE_DSS_URL`, default `http://127.0.0.1:18080`; `validate(name, document) -> Result<Reports, Error>` posts the Patelle-shaped body, reads the body with a 64 MiB limit and a 120 s timeout, writes the raw JSON and the ETSI XML to `<CARGO_TARGET_DIR or workspace target>/conformance/<name>.{json,xml}` (`name` with a `/`, `\` or `..` → `Error::Url`), then parses.
   - `pki_dir()` / `reference_dir()` → `conformance/pki/` and `conformance/reference/` from `CARGO_MANIFEST_DIR`.
   Tests (offline, run by `ci.yml`), `tests/report.rs`: (a) the recorded B response gives one signature, `TOTAL_PASSED`, no sub-indication, `format == "PAdES-BASELINE-B"`, level `Some(PAdES, BaselineB)` — fails if the reader took `SignatureLevel` instead of `SignatureFormat`; (b) the recorded revoked response gives the exact indication and sub-indication it holds — fails if the sub-indication is dropped; (c) a response whose signature lacks `Indication`, and one with `TOTAL_PASSED` plus a sub-indication, are `Err`, not a panic; (d) `level` over representative names (`PAdES-BASELINE-LTA`, `CAdES-BASELINE-T`, `XAdES-BASELINE-LT`, `PAdES-BES`, `PDF-NOT-ETSI`) — fails if a form or profile is swapped; (e) `etsi_xml` of the recorded response starts with `<?xml` and holds `ValidationReport`. `tests/client.rs` (feature `http`): (f) `Dss::new` refuses `https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo` and `http://10.0.0.1:8080`, accepts `http://127.0.0.1:18080`; (g) a `name` holding `../` is refused before any request.
7. [x] **Conformance tests** — `crates/nacre-conformance/tests/dss_reference.rs`, each `#[ignore = "conformance"]`: (h) `conformance/reference/pades-baseline-b.pdf` → `TOTAL_PASSED`, `format == "PAdES-BASELINE-B"` exactly, and `target/conformance/pades-baseline-b.xml` exists after the call; (i) `pades-baseline-b-revoked.pdf` → the indication, sub-indication and format recorded in task 5, exactly. Check: `NACRE_DSS_URL=http://127.0.0.1:18080 cargo test -p nacre-conformance --test dss_reference -- --ignored` passes against the bench; both fail if DSS is given another anchor store.
8. [x] **Workflow** — `.github/workflows/conformance.yml`, on `push` to `main`, `pull_request`, `workflow_dispatch` and a daily `schedule` (`cron: "17 4 * * *"`, ADR-0011: with no versioned `Cargo.lock`, a dependency release is caught within a day): `rustup toolchain install`; `docker/setup-buildx-action` + `docker/build-push-action` building `conformance/dss` with `load: true`, tag `localhost/nacre-dss:6.5.1`, `cache-from/cache-to: type=gha,scope=nacre-dss` (ADR-0007, Consequences); `docker compose -f conformance/compose.yaml up -d`; `sh conformance/check.sh`; `sudo apt-get install -y softhsm2` and `NACRE_SOFTHSM_MODULE=/usr/lib/softhsm/libsofthsm2.so` exported (issue #6: s13 needs no workflow edit); `cargo test --workspace --all-features -- --ignored` with `NACRE_DSS_URL`; then every example of the workspace, found by `cargo metadata --no-deps --format-version 1 | jq` over targets of kind `example`, run with `cargo run -p <package> --example <name> --all-features` (issue #6: s20 needs no workflow edit; none today); `actions/upload-artifact@v4` of `target/conformance/` with `if: always()`; `docker compose logs` on failure; `down` at the end. Check: `actionlint` if installed, else a reading against `ci.yml`'s step style; the first CI run on the pull request is the real check.

## Scene viewpoints
—

## Amendment — 2026-10-22, the owner's decision on test keys
The first implementation run was stopped at its commit: task 1 committed the bench's private keys in PEM, which the pre-commit guard and the owner refuse. The owner decided that **no private key enters git, test keys included**; the PKI is regenerated at every bench start, locally and in CI. This amendment overrides tasks 1, 5 and 7 where they differ; every other task stands as written and ticked.
- **Task 1, PKI.** `generate.sh` writes keys, certificates, CRLs, the `openssl ca` index files and `anchors.p12` into `conformance/pki/out/`, which `conformance/pki/.gitignore` ignores (the root `.gitignore` stays frozen). Nothing under `out/` is committed; `openssl.cnf`, the scripts and the README are. The compose `pki` service, or a one-shot `pki-init` step it depends on, runs `generate.sh` before the responders start, and the DSS service mounts `out/anchors.p12`. Every run gets fresh keys and serials; no test may depend on a fixed key, serial or fingerprint.
- **Task 5, reference PDFs.** `conformance/reference/generate.sh` signs `unsigned.pdf` with the freshly generated signer and revoked keys at bench start, into `conformance/reference/out/` (ignored the same way). `unsigned.pdf`, the script and the README stay committed; the signed PDFs are not. The recorded DSS JSON responses under `crates/nacre-conformance/tests/corpus/` stay committed as parser fixtures: they hold public certificates only, never a key.
- **Task 7, conformance tests (h), (i).** They read the PDFs from `conformance/reference/out/`, and fail with a message naming `generate.sh` when the files are missing. They assert the exact verdict (`TOTAL_PASSED` / `PAdES-BASELINE-B`; `INDETERMINATE` / `REVOKED_NO_POE` / `PAdES-BASELINE-B`), never a key-dependent value.
- **New interdict.** `git diff main...story/s02-conformance-harness` adds no line matching `-----BEGIN[A-Z ]*PRIVATE KEY`, no `.p12`, no `.key` file and no DER private key; the pre-commit hook runs on the commit, never `--no-verify`.
- **Work already done.** The previous run left its work staged in the worktree's index and untracked files. Reuse it: move the generated material under `out/`, drop the committed keys, certificates, CRLs, index files, `anchors.p12` and signed PDFs from the index, and keep everything else.

## Run interdicts
- `Cargo.toml`, `rust-toolchain.toml`, `.gitignore`, `.github/workflows/ci.yml` and `crates/nacre-core/` end with an empty diff (s01's, frozen).
- No file outside `conformance/`, `crates/nacre-conformance/`, `.github/workflows/conformance.yml` and this story's `docs/` files changes (story Owns); `docs/stories.md` is not edited.
- Nothing in `/home/lecrabe/dev/atoll/patelle` changes; the `patelle-dss` container is neither stopped nor reused.
- No call to the Commission's online DSS demo, nor to any public TSA or OCSP responder, from code, scripts or CI.
- DSS's validation policy is not edited and no check is disabled: anchors pass through `anchors.p12` only.
- No private key other than the bench's published P-256 test keys enters the repository; no real document.
- No `[workspace.dependencies]`, no `cms` or `x509-tsp` crate, no TLS feature of `ureq`.
- No `unwrap`, `expect`, `panic!` or slice/JSON indexing in `src/`.
- `ureq` appears only behind the `http` feature (`cargo tree -p nacre-conformance -e normal` without features shows no `ureq`).

## The pivot
**Host networking, every listener on `127.0.0.1`, certificate URLs at `http://127.0.0.1:18081`.** One URL must work for DSS inside its container and for s09/s10 tests on the host; it rests on three things that could be wrong:
- podman rootless or GitHub's Docker refusing `network_mode: host` with compose: compare `podman compose up` locally and the first CI run; the fallback is a shared network namespace (`network_mode: "service:pki"`) with ports published on `pki`.
- Tomcat still listening on `0.0.0.0` or on 8005 after the `sed`: check `ss -ltnp` while the bench runs.
- DSS not trusting the OpenSSL-made anchor store, or not finding fresh revocation for the intermediate: the recorded verdict of task 5 shows it; never fixed by a policy change.
Second hinge: reading the level from `SignatureFormat`. Compare with the recorded JSON, where `SignatureLevel` is `N/A`.

## Files touched
- `conformance/compose.yaml`, `conformance/check.sh`, `conformance/README.md`
- `conformance/dss/Containerfile`, `conformance/dss/dss-custom.properties`, `conformance/dss/README.md`
- `conformance/pki/Containerfile`, `openssl.cnf`, `generate.sh`, `serve.sh`, `cgi-bin/tsa`, `cgi-bin/ocsp`, `README.md`, and the generated keys, certificates, CRLs, index, serials and `anchors.p12`
- `conformance/reference/unsigned.pdf`, `generate.sh`, `pades-baseline-b.pdf`, `pades-baseline-b-revoked.pdf`, `README.md`
- `crates/nacre-conformance/Cargo.toml`, `src/lib.rs` (and modules if it grows), `tests/report.rs`, `tests/client.rs`, `tests/dss_reference.rs`, `tests/corpus/` (two JSON responses, `README.md`)
- `.github/workflows/conformance.yml`
- `docs/decisions/0011-bench-pki-tsa-ocsp-on-openssl.md`, `docs/research/s02-conformance-harness.md`, this plan

## Test strategy
Nine Rust tests, within `Test budget` (25). No fuzz target: the crate reads the answer of a local, trusted judge, is never published, and its reading is denied panics by lint; the research records this so the reviewer can contest it.

Automated, offline (`cargo test -p nacre-conformance --test report --test client`, run by `ci.yml`):
- (a) to (e) on the recorded real responses of DSS 6.5.1 — the risk the story names is the report shape, so the reader is tested on what DSS really returned, not on hand-written JSON; the two hand-made inputs of (c) are only refusals.
- (f), (g) on the client's guards; no network involved (`Dss::new` and the name check refuse before any request).

Automated, conformance (`-- --ignored`, run by `conformance.yml` against the bench):
- (h) exact `PAdES-BASELINE-B` on the reference PDF — criterion 4.
- (i) exact verdict on the revoked signer — proves the PKI's revocation reaches DSS through the bench's CRL and OCSP.

Shell checks of `conformance/check.sh` (not Rust tests): PKI chain verifies, CRL lists the revoked serial, TSA answers a verifiable token, OCSP says `good` and `revoked` — criteria 1 and 2, with OpenSSL as the judge.

Manual: `ss -ltnp` shows only `127.0.0.1` listeners on 18080 and 18081 while the bench runs.

## Done when
- The eight tasks are ticked; `cargo test --workspace` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` pass (through `po-run`), `cargo fmt --check` too.
- `conformance/check.sh` and the conformance tests pass against the bench locally, and `conformance.yml` is green on the pull request with the reports uploaded.
- ADR-0011 accepted by the owner.
- One commit on `story/s02-conformance-harness`, a review with no open critical finding, landed through a pull request.
