# Review — s39-error-kind-from-sources

[Story](../stories.md) · [Plan](../plans/s39-error-kind-from-sources.md) · [Verification](../verif/s39-error-kind-from-sources.md)

Diff reviewed: `git diff main...story/s39-error-kind-from-sources`, in a context that did not write it. Findings rated critical, major or minor.

Review status: complete
Fix loop: 0
Reviewed tree: 72cd31c5a07970b20e3a2abb1b580333bd4d3998

## Ownership
I listed the diff with `git diff --name-only main...story/s39-error-kind-from-sources` and held each path against the story's `Owns` line.
- [x] Every path is inside `Owns`. The 12 code paths fall under `crates/nacre-core/`, `crates/nacre-tsp/src/`, `crates/nacre-tsp/tests/http.rs`, `crates/nacre-revocation/src/`, `crates/nacre-revocation/tests/http.rs`, `crates/nacre-cms/src/error.rs`, `crates/nacre-pades/src/error.rs` and `crates/nacre-pades/tests/`. The rest are this story's own evidence (`docs/plans`, `docs/research`, `docs/verif`, `docs/qa/<id>/`). `docs/decisions/0020-source-kind-in-struct-variants.md` is an added file (status A), and the plan names it, so it is in scope.
- [x] No path outside `Owns`.
- [x] No path inside another running story's `Owns`.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s39-error-kind-from-sources` exits 0. Since `Verification mode: record`, I reused the record instead of rerunning: `cargo test --workspace` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` both exited 0 on `Tree: 2d7daaaf…`. I also read its "Not proven here" section (the ignored conformance tests, and the build left to ship).
- [x] `po-gate qa-current s39-error-kind-from-sources` exits 0. The story goes to QA (`QA stage: surfaces`, `Surface: endpoint`). The report is complete and committed (`Tree: 15c2511e…`). Its one verified finding is carried into Findings below.

## Plan
- [x] Tasks 1 to 5 are all present, at the lines the plan names. Nothing is outside the plan. The old tuple variants are gone everywhere: a grep for `Error::Timestamp(` and `Error::Revocation(` finds only the pades crate's own variants.
- [x] I checked each run interdict:
  - No `downcast` in `crates/nacre-core/src`.
  - The `#[error]` texts and the `ErrorKind` block are unchanged.
  - `crates/nacre-tsp/src/error.rs` and `crates/nacre-revocation/src/error.rs` are not in the diff.
  - `crates/nacre-revocation/src/http.rs` changes only at :206 and :311.
  - `timestamp.rs` and `revocation.rs` in core are untouched.
  - No `Cargo.toml` change and no new dependency. `sha2` was already a dev-dependency (`crates/nacre-tsp/Cargo.toml:30`).
  - Every test server binds 127.0.0.1.
  - No `with_kind(.*Box::new`.

## References
- [x] Opened and confirmed:
  - `nacre_tsp::Error::kind()` (`crates/nacre-tsp/src/error.rs`) and `nacre_revocation::Error::kind()` (`crates/nacre-revocation/src/error.rs:108`).
  - `verify_response` and `verify_token` check the signature before the imprint, and the imprint before the nonce. So `signature-invalid.tsr` reaches `Cms(SignatureInvalid)` and `valid.tsr` reaches `NonceMismatch`. `valid.tsr` verifies against SHA-256 of `data.bin` (`tests/attacks.rs:22`).
  - `NonPublicAddress` maps to `InvalidInput`, `Http` to `Unavailable`, and `Der` to `InvalidInput`.
- [x] Every expected kind traces back to these mapping tables.

## Rules
- [x] The `AGENTS.md` conventions hold: no panic in non-test code, English rustdoc, no address in any message.
- [x] No accepted ADR is contradicted. The change follows ADR-0020 option 1 (accepted); this is a contract story, as ADR-0016 requires, and nothing downcasts in core.

## Tests
- [x] Floor: `po-gate floor-guard s39-error-kind-from-sources main` exits 0, so nothing was lowered.
- [x] The assertions pin the kinds the criteria name, and I found none of the six empty test shapes. One case lacks a test of its own (see Findings).
- [x] 7 new tests (2 core rows, 3 TSA, 4 revocation), within `Test budget: 25`.
- [x] Bite. Each change was undone, and `git diff --exit-code` was clean after every one:
  - `crates/nacre-tsp/src/http.rs:60` changed to `Error::timestamp(error)`: 2 of 4 tests in `--test http` fail (forged, replayed).
  - `crates/nacre-revocation/src/http.rs:206` (OCSP) changed to `revocation(error)`: 1 of 9 fails (replayed OCSP).
  - `crates/nacre-revocation/src/http.rs:311` (CRL) changed to `revocation(error)`: 2 of 9 fail (malformed, refused).
  - `crates/nacre-core/src/error.rs:40`, `kind()` changed to return `Unavailable`: `core_kinds` fails.
- [x] No existing test was made useless; `fetch` and `ask` were migrated to the struct pattern.

## Neighbours
- [x] `nacre_pades::Error::kind()` delegates `Timestamp(inner)` and `Revocation { source }` to the core kind (`crates/nacre-pades/src/error.rs:103-104`), and so does `nacre_cms::Error::Signer` (`crates/nacre-cms/src/error.rs:93`). The new kind therefore reaches applications through the facade. Nothing is broken; the workspace compiles, per the record.

## Lenses
Lenses run:
- security: content trigger, an HTTP call whose URL comes from input (the CRL and OCSP URLs taken from the certificate, `crates/nacre-revocation/src/http.rs:206,311`). The refused-address paths report `InvalidInput` and messages never name the address, which the existing test and QA c3/c4 confirm. No finding.
- dependencies, migration, performance: not triggered.
- [x] No lens finding.

## Findings
- minor — crates/nacre-revocation/tests/http.rs:247 — Criterion 4 asks that `HttpOcspSource` with a refused address return `InvalidInput`, and criterion 5 asks for one test per case. The diff adds no test asserting the core error's `kind()` for a refused OCSP address. The plan's restatement of the criteria (`## Story`, item 3) dropped that case without saying so.
  - The behaviour is covered by other means. The same `map_err` line is bitten by `replayed_ocsp_response_is_invalid_signature`. `ocsp_loopback_responder_is_refused_by_default` asserts the inner `NonPublicAddress`, whose kind is pinned in the crate's variant table. QA scenario c4 observed `InvalidInput`.
  - So the gap is a missing test row, not a defect.
- minor — crates/nacre-tsp/src/error.rs (`Http` → `Unavailable`) — Carried from verified QA finding 1. `HttpTsa::new("not a url")` returns `kind()` = `Unavailable`, so an application would retry a caller configuration mistake as if it were an outage.
  - The cause is the existing mapping of `nacre_tsp::Error::Http`, which this story's plan forbids touching. It is outside the criteria's cases.
  - Worth a tracker issue for a later story.

## Not verified
- The `#[ignore]`d conformance tests (DSS, SoftHSM) were not run. They run in `.github/workflows/conformance.yml`, and this story touches none of their paths. A person can check that the conformance workflow is green on the pull request.
- The production build was not run. It is deferred to ship (`Build stage: ship-if-route`); no manifest changed.
- The project has no E2E command (`E2E: —`), so no end-to-end check exists.
- Behaviour against a real TSA, CRL server or OCSP responder over a real network was not seen (from the QA `## Not seen`). The QA driver contacts only servers it starts, and the story forbids a public TSA in tests. A person could do a one-off manual call against a test TSA outside CI.
- QA `## Not seen` also lists criterion 5, "un test par cas, sur un serveur local", as a property of the suite that QA could not observe. I checked it here; see the first minor finding.
- Patelle, the first downstream client, is outside this repository. Its migration to the new constructors and struct patterns is a breaking API change for it, and I did not check it. A person should plan that migration when Patelle next takes a Nacre update.

Max severity: minor
Ship allowed: yes
