# Review — s09-revocation-crl

[Story](../stories.md) · [Plan](../plans/s09-revocation-crl.md) · [Verification](../verif/s09-revocation-crl.md)

Diff reviewed: `git diff main...story/s09-revocation-crl`, in a context that did not write it. Findings rated critical, major or minor.

Review status: complete
Fix loop: 0
Reviewed tree: 0066b75cb5539be28bda669242a851178acd7971

## When blocked
- Failure cause: none
- Missing: none
- Required adaptation: none
- Next action: none

## Ownership
I listed the diff with `git diff --name-only main...story/s09-revocation-crl` and held each path against `Owns: crates/nacre-revocation/, docs/security/attacks/revocation.md` (docs/stories.md:160).
- [x] Every path is inside `Owns` or is the story's own pipeline evidence (`docs/plans/`, `docs/research/`, `docs/verif/`, `docs/qa/s09-revocation-crl/`).
- [x] No path is outside `Owns`.
- [x] No path is inside another running story's `Owns`. The other worktrees are s06-pades-bb (`crates/nacre-pades/`) and s07-tsp-client (`crates/nacre-tsp/`, `docs/security/attacks/tsp.md`); neither overlaps.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s09-revocation-crl` exited 0, so the record is reused. I also checked by hand: `Tree: 949c786…` and the passing runs (unit suite at 870497d…, exit 0; type check at d0f066d…, exit 0) all match HEAD outside `docs/`. Under `Verification mode: record`, the suite and clippy were not rerun. Its "Not proven here" is carried below.
- [x] `po-gate qa-current s09-revocation-crl` exited 0 (`QA status: complete`, `Tree: d4f293b…` matches HEAD outside `docs/`). Its two verified QA findings (both minor) are carried to Findings, and its `## Not seen` is carried to Not verified.

## Plan
- [x] Tasks 1–9 are present (19 tests, as the plan counts). One addition the plan did not ask for: public `certificate_list()` and `tbs_bytes()` (finding 5).
- [x] Run interdicts, checked one by one:
  - Diff confined to the allowed paths: yes.
  - No `[workspace.dependencies]`, no `cms` or `x509-tsp`: yes.
  - No `SystemTime::now`, `Time::now` or `CrlBuilder::new(` in `src/`: grep empty.
  - `ureq` is optional behind `http`, so it is absent without features: yes.
  - No `println!`, `eprintln!`, `dbg!` or `log::` in `src/`: grep empty.
  - No `PRIVATE KEY` in the crate, and `Cargo.lock` is untracked: yes.
  - `verify` hashes the stored received TBS bytes (`crl.rs:51-55`, `verify.rs:40`), never a re-encoding: yes.
  - No unwrap or indexing outside tests: workspace lints plus a clean clippy run in the record.

## References
- [x] Every import, call and API exists. The code compiles under clippy `--all-features` (record), and I read the `ureq` 3.5.0 config defaults in the cargo registry. Dependency versions match the existing `nacre-cms` and `nacre-conformance` manifests.
- [x] Values checked:
  - Fuzz `AT = 1_798_761_600` is 2027-01-01T00:00:00Z.
  - The expiry comparison `next_update < at` accepts the day of `nextUpdate` itself, which QA saw.
  - The 30 s timeout and 16 MiB body limit are the plan's values.
  - Not set: `max_redirects`, which keeps ureq's default of 10 (`ureq-3.5.0/src/config.rs:1075`). The research flagged this knob (research:42); the plan never decided it (finding 1).

## Rules
- [x] `AGENTS.md` conventions are respected: `forbid(unsafe_code)`, "Experimental" crate doc, edition 2024 and MSRV 1.97, one `thiserror` enum with `kind()`, no clock, no output, network only behind `http`, a fuzz target, a corpus README, and the attacks file in French.
- [x] No accepted ADR is contradicted (0004, 0006, 0010 and 0012 were checked against the code).

## Tests
- [x] Floor: `po-gate floor-guard s09-revocation-crl main` exited 0, so nothing was lowered.
- [x] Assertions pin down the acceptance criteria. Each attack case asserts its exact variant, and none of the six empty test shapes appears. The hostile test asserts that the unmodified CRL is accepted before it mutates it.
- [x] 19 tests, within `Test budget` 25.
- Bite (only `tests/attacks.rs` and `tests/status.rs` run):
  - [x] `next_update < at` turned into `false && …` → 1 failing test (`stale_crl_is_rejected`). Undone; `git diff --exit-code` is clean.
  - [ ] `|| crl_issuer != issuer.tbs_certificate().subject()` (`crl.rs:116`) turned into `|| false` → **0 failing tests**. Undone; `git diff --exit-code` and `git status --porcelain` are clean (finding 2).
- [x] The story makes no test useless (new crate).

## Neighbours
- [x] The diff adds a new crate with no other callers. It implements `nacre_core::RevocationSource` without changing it.

## Lenses
Lenses run:
- security, triggered by `crates/nacre-revocation/src/http.rs`, an HTTP call whose URL comes from input (the certificate's distribution point);
- dependencies, triggered by the new manifest `crates/nacre-revocation/Cargo.toml` and its dependency list. Every dependency is already in the workspace at the same version, the plan names each one, and no lockfile is committed. Nothing found.

- [x] Each lens finding is graded and listed under Findings.

## Findings
- major — crates/nacre-revocation/src/http.rs:27-31,65-76 — SSRF: the source fetches whatever `http://` URL a certificate names, with no allow-list and nothing blocking loopback, private or link-local addresses.
  The certificate is untrusted input whenever a third party's signature is validated (B-LT and s17).
  ureq's default `max_redirects` of 10 is kept, so even a public distribution point can bounce the GET to an internal `http://` host. `docs/security/attacks/revocation.md` ("Source HTTP") documents the fetch-any-URL behaviour but not the redirects.
  The impact is contained: it is a blind GET, the body is only returned once it parses as a CRL, the message is generic, and no caller in this diff passes untrusted certificates.
  This is a security finding: under Law 7 (ADR-0077, ADR-0090) it goes to the person, not to the tracker on its own.
  Options to weigh:
  - set `max_redirects(0)`, or refuse redirects that leave the first host;
  - an opt-in address filter. The bench uses `127.0.0.1`, so a hard block would need a constructor that allows it.
- minor — crates/nacre-revocation/src/crl.rs:116 — the half of the `WrongIssuer` rule that compares the CRL issuer with the given issuer certificate's subject is untested. Disabling it fails none of the 11 judgement tests, because `wrong-issuer.der` is caught by the first half alone. The plan's test strategy claims that "deleting a rule makes its test fail", which is not true for this half.
  The rule matters when the given issuer certificate holds the CA's key under another subject: the signature then verifies. One attack case would cover it (CRL and leaf naming `ca.der`, judged against a certificate with the same key and a different subject).
- minor — crates/nacre-revocation/src/error.rs:12-16 — `Der` and `Certificate` both format their inner `der::Error` (`"invalid DER: {0}"`, `"invalid certificate: {0}"`) and also return it as `source()`, so a printed error chain repeats the DER fault. Carried from QA finding 1 (verified, `docs/qa/s09-revocation-crl/replay-findings.txt`). Fix: drop `{0}` from the messages.
- minor — crates/nacre-revocation/src/crl.rs:111-112 — `Error::Certificate` does not say which argument (`certificate` or `issuer`) failed to decode; both give the same text and kind. Carried from QA finding 2 (verified, `docs/qa/s09-revocation-crl/c3-refusals-error.txt`).
- minor — crates/nacre-revocation/src/crl.rs:59-67 — public `certificate_list()` and `tbs_bytes()` are not in plan task 2. `certificate_list()` adds `x509_cert::crl::CertificateList` to the crate's public API, which ties Nacre's semver to x509-cert's. Either keep them on purpose with a sentence saying so, or make them `pub(crate)` (the fuzz target only needs `tbs_bytes`, and only as a smoke call).

## Not verified
- **CRL download from the s02 bench** (`tests/bench.rs::revoked_is_listed_and_signer_is_not_on_the_bench`). The driver note forbade starting the bench, and QA did not see it either (the s06 lane held its ports). The CI `conformance` job runs it; a person can run the `conformance/README.md` steps, then `cargo test -p nacre-revocation --all-features -- --ignored`.
- **The 16 MiB body limit and the 30 s timeout** (from QA's Not seen). No scenario served an oversized or slow answer, and the plan leaves them to ureq.
- **Behaviour on a real network or against a real CA's distribution point** (from QA's Not seen). The QA driver reaches only its own server.
- **Redirect handling, in practice.** I read the ureq default (`max_redirects: 10`) but sent no request. A person can serve a 302 to `http://127.0.0.1:<port>/` from a local server and watch whether `HttpCrlSource` follows it.
- **The CI fuzz job on GitHub Actions** (from QA's Not seen). It is a remote service; QA did a 60 s local run (535 700 runs, no crash), and I did not fuzz.
- **Unit suite and clippy.** Not rerun: the record is current and reused under `Verification mode: record`.
- **Production build.** Deferred to ship (`Build stage: ship-if-route`).
- **End to end.** The project has none (`E2E: —`).
- **Fixture regeneration.** I did not regenerate the attack corpus with `cargo run --example forge_crl_attacks`, nor the OpenSSL fixtures from the README commands, so I did not confirm that the committed files are exactly what they produce. A person can regenerate into a scratch directory and compare, keeping in mind that the README says OpenSSL keys and signatures change between runs while dates do not.

Max severity: major
Ship allowed: yes

# Review — s09-revocation-crl

Review status: blocked
Fix loop: 1
Reviewed tree: b8054b9e08f49087ef8964e7598f43376bc20638

## When blocked
- Failure cause: `po-gate qa-current s09-revocation-crl` exited 1: "po-gate: the code of s09-revocation-crl changed after its QA walk; the report no longer matches HEAD — /po-qa s09-revocation-crl". The QA report (`Tree: d4f293b…`) predates fix run 1 (9a45b4e), which rewrote `src/http.rs`, `src/error.rs`, `src/crl.rs` and `src/verify.rs`.
- Missing: a QA walk of the code at this tree, in particular the new `HttpCrlSource` refusals (`NonPublicAddress`, a 3xx not followed) and the new `Error::IssuerCertificate`.
- Required adaptation: walk QA again on the fixed code, then review again. Nothing in the code has to change for this block.
- Next action: `/po-qa s09-revocation-crl`, then `/po-review s09-revocation-crl`.

## Done anyway (does not declare the code safe)
- Ownership, run interdicts, references (ureq 3.5.0 resolver, `max_redirects`, `proxy`), rules and floor all hold; 24 tests within budget.
- Bites: address check `.all(|_| true)` → 2 failing; issuer-subject half of `WrongIssuer` → 1 failing (fix-loop-0 gap closed); `.proxy(None)` removed → 0 failing without proxy variables (finding 1).
- SSRF defence judged closely: check after resolution with no second lookup (connector uses the resolver's addresses), proxy disabled, IPv4 and IPv6 ranges complete, IPv4-mapped and 6to4 judged on the carried IPv4, the same parsed `Uri` used for check and connect. What remains is a blind GET to a public address, as the owner decided.

## Lenses
Lenses run: security (`crates/nacre-revocation/src/http.rs`, a URL from a certificate); dependencies (`ureq` requirement `~3.5`, self dev-dependency with `http`; nothing found).

## Findings
- minor — crates/nacre-revocation/src/http.rs:51 — the `.proxy(None)` guard is not tested: removing it fails no test where no `HTTP_PROXY`/`ALL_PROXY` is set (CI included), yet it alone keeps ureq from leaving name resolution to a proxy and bypassing the address check (`ureq-3.5.0/src/run.rs:387`). A test could set `HTTP_PROXY` to a closed port and assert `HttpCrlSource` ignores it, or assert the agent's config holds no proxy.

## Not verified
- The QA walk of the fixed code (the block) and the old report's Not seen items; the CRL download from the s02 bench (stand-in server only; CI runs it); a DNS name resolving to a non-public address (read, not run); behaviour behind an environment proxy; fuzzing after the fix; production build (at ship); E2E (none); corpus regeneration of the two new files.

Max severity: minor
Ship allowed: no

---

# Review — s09-revocation-crl

[Story](../stories.md) · [Plan](../plans/s09-revocation-crl.md) · [Verification](../verif/s09-revocation-crl.md)

Diff reviewed: `git diff main...story/s09-revocation-crl`, by a reviewer that did not write it. Each finding is graded critical, major or minor.

Review status: complete
Fix loop: 1
Reviewed tree: ee678944207a2553a11d308836bef1f660b1ed30

## When blocked
- Failure cause: none
- Missing: none
- Required adaptation: none
- Next action: none

## Ownership
I held every path from `git diff --name-only main...story/s09-revocation-crl` against `Owns: crates/nacre-revocation/, docs/security/attacks/revocation.md` (docs/stories.md:160).
- [x] Every path is inside `Owns` or is the story's own pipeline evidence (`docs/plans/`, `docs/research/`, `docs/verif/`, `docs/reviews/`, `docs/qa/s09-revocation-crl/`).
- [x] No path is outside `Owns`.
- [x] No path is inside another running story's `Owns`. The other worktrees are s07 (`crates/nacre-tsp/`, `docs/security/attacks/tsp.md`), s13 (`crates/nacre-pkcs11/`) and s15 (`crates/nacre-validate/`, `docs/security/attacks/pades.md`). None of them overlaps.
- [x] The story has an `Owns` line.
- The worktree's only uncommitted change is `docs/reviews/s09-revocation-crl.md`, the fix-run review that Law 4 allows.

## Evidence reused
- [x] `po-gate verif-current s09-revocation-crl` exited 0.
  - Under `Verification mode: record`, I reused its unit suite and clippy runs and did not rerun them.
  - Its "Not proven here" section is carried below.
- [x] `po-gate qa-current s09-revocation-crl` exited 0.
  - The new walk has `Tree: b8054b9…`. Its code outside `docs/` is identical to HEAD (`git diff --quiet b8054b9 HEAD -- . ':(exclude)docs'` → 0). The last blocked review is therefore lifted: its only cause was the outdated QA.
  - The report's one verified finding is carried to Findings (finding 2).
  - Its `## Not seen` is carried to Not verified.

## Plan
- [x] Tasks 1–9 are present.
- [x] Fix run 1 settles each fix-loop-0 finding:
  - **SSRF:** an address policy in the resolver, `max_redirects(0)`, `proxy(None)`, and `allowing_loopback()` for the bench.
  - **Untested issuer-subject half:** the `issuer-renamed.der` case was added.
  - **DER printed twice:** the messages no longer repeat the DER fault.
  - **The two certificate arguments could not be told apart:** `IssuerCertificate` was added.
  - **Public `certificate_list()` and `tbs_bytes()`:** both are now `pub(crate)`.
- [x] Run interdicts hold: no `[workspace.dependencies]`, `cms` or `x509-tsp`, no clock in `src/`, no output in `src/`, `ureq` only behind `http`.
- [x] `verify` hashes the stored received TBS bytes (`crl.rs:55`, `verify.rs:40`).
- The plan's text was not updated for the fix run: it still says 19 tests (24 now) and does not list `tests/http.rs`. These are bookkeeping gaps, not a defect, so I raised no finding.

## References
- [x] I read the `ureq` 3.5.0 source.
  - `Agent::with_parts(config, connector, resolver)` exists (`agent.rs:130`).
  - The resolver's addresses are the ones `run.rs:387-399` connects to. When a proxy is set, `run.rs` skips resolution.
  - The default `proxy` is `Proxy::try_from_env()` (`config.rs:1073`), so `.proxy(None)` is what keeps the address check in force.
  - `max_redirects(0)` disables redirect errors (`config.rs:261`), so the explicit `is_redirection()` guard is what refuses a 3xx.
- [x] Values checked:
  - The IPv4 and IPv6 ranges in `public_v4` and `public_v6`.
  - IPv4-mapped addresses and 6to4 are judged on the IPv4 address they carry.
  - Teredo (`2001:0::/32`) and NAT64 (`64:ff9b::`) fall outside the public set.
  - The 30 s timeout and the 16 MiB limit match the plan.

## Rules
- [x] The `AGENTS.md` conventions hold:
  - `forbid(unsafe_code)` and the "Experimental" crate doc;
  - edition 2024 and MSRV 1.97;
  - one `thiserror` enum with `kind()`, and no message names a URL;
  - no clock and no output;
  - network only behind `http`;
  - a fuzz target, a corpus README, and the attacks file in French.
- [x] No accepted ADR is contradicted (0004, 0006, 0010, 0012).

## Tests
- [x] Floor: `po-gate floor-guard s09-revocation-crl main` exited 0.
- [x] I read the fixtures and the stand-in server in `tests/http.rs`. Each refusal test first proves the same server would serve a valid CRL. None of the six empty test shapes appears.
- [x] 24 tests, within `Test budget` 25.
- Bite: I ran only the files that exercise each rule, undid each change, and confirmed it with `git diff --exit-code` and `git status --porcelain`.
  - [x] `status.is_redirection()` → `false && …` (`http.rs:85`): 1 failing (`redirect_is_not_followed`).
  - [x] Entry critical-extension check removed (`crl.rs:121-123`): 1 failing (`critical_entry_extension_is_rejected`).
  - [x] `|| crl_issuer != issuer…subject()` → `|| false` (`crl.rs:115`): 1 failing (`issuer_certificate_under_another_name_is_rejected`). The fix-loop-0 gap is closed.
  - [ ] `.proxy(None)` replaced by ureq's default `Proxy::try_from_env()` (`http.rs:51`): **0 failing**, with no proxy variable set (finding 1).

## Neighbours
- [x] This is a new crate with no other callers. It implements `nacre_core::RevocationSource` and leaves the trait unchanged.

## Lenses
Lenses run:
- security, triggered by `crates/nacre-revocation/src/http.rs`, an HTTP call to a URL taken from an untrusted certificate;
- dependencies, triggered by the new manifest `crates/nacre-revocation/Cargo.toml`:
  - `ureq ~3.5` is pinned because `ureq::unversioned` is used, and the manifest says why;
  - the other dependencies match the versions in the workspace;
  - no lockfile is committed.

  The dependencies lens found nothing. The security lens found finding 1.

## Findings
- minor — crates/nacre-revocation/src/http.rs:51 — the `.proxy(None)` guard is not tested.
  - Swapping it back to ureq's default `Proxy::try_from_env()` fails none of the 7 HTTP and unit tests, in an environment with no `HTTP_PROXY`/`ALL_PROXY` (CI included).
  - Yet this line alone stops a proxy from resolving the host and bypassing the address check (`ureq-3.5.0/src/run.rs:387`).
  - QA did see the variables being ignored, but nothing would catch the line being removed later.
  - A test could set `ALL_PROXY` to a closed port and assert a loopback fetch still succeeds through `allowing_loopback()`.
- minor — crates/nacre-revocation/src/http.rs:181 — through `RevocationSource`, a refused distribution point reads `kind() = Unavailable`, the same kind as a transient outage.
  - The `InvalidInput` kind of `NonPublicAddress` is visible only on the boxed inner error.
  - The `Revocation(_) => Unavailable` mapping lives in `crates/nacre-core/src/error.rs:28`, outside this story's `Owns`.
  - Carried from QA finding 1 (verified, `docs/qa/s09-revocation-crl/c2-http-source-error.txt`, `replay-findings.txt`).
  - It touches how a security refusal is reported, so it goes to the person, as Law 7 says.

## Not verified
- **CRL download from the bench's own `pki` container.** QA served the same s02 files at the same URL from its own static server, and `tests/bench.rs` passed against it. The CI `conformance` job runs it against the real container. A person can follow `conformance/README.md`, then run `cargo test -p nacre-revocation --all-features -- --ignored`.
- **A DNS name resolving to a non-public address other than `localhost` (DNS rebinding).** I read the code path but did not run it; QA had no resolver to serve such a name. A person can add a hosts or DNS entry pointing a name at `10.x` and check that the result is `NonPublicAddress`.
- **The `[::1]` download with `allowing_loopback()`.** QA's server listened on IPv4 only.
- **The 16 MiB body limit and the 30 s timeout.** No oversized or slow answer was served.
- **A public distribution point, or a real CA's CRL on a real network.** The QA driver reaches only its own servers.
- **Behaviour behind a real environment proxy.** QA set the variables to a closed port only, and the guard is untested (finding 1).
- **The CI fuzz job on GitHub Actions.** QA did a 60 s local run (607 113 runs, no crash); I did not fuzz.
- **Unit suite and clippy.** Not rerun: the record is current and reused.
- **Production build.** Deferred to ship (`Build stage: ship-if-route`).
- **End to end.** The project has no E2E command (`E2E: —`).
- **Fixture regeneration.** I did not regenerate the attack corpus with `cargo run --example forge_crl_attacks`, nor the OpenSSL fixtures, to compare them with the committed files.

Max severity: minor
Ship allowed: yes
