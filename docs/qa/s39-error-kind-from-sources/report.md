# QA — s39-error-kind-from-sources

[Story](../../stories.md) · [Plan](../../plans/s39-error-kind-from-sources.md)

Scope: the story's surface, what `git diff main...story/s39-error-kind-from-sources` touches on it, and the acceptance criteria its user can observe through it; nothing else was checked.
Driver: `scenarios.md` of qa-drivers — surface `endpoint`, platform `lib, cli` (row `endpoint` / `lib`)
Evidence: transcripts
Tool: Bash — a Rust program written under the `mktemp -d` directory, built against a copy of the story's tracked files, calling the public interface of `nacre-core`, `nacre-tsp` (`http`) and `nacre-revocation` (`http`); quoted whole in `program.txt`
Origin: — (the driver serves nothing; every server was started in-process by the program on 127.0.0.1, no other host was contacted)

Install (`cargo fetch`) and Build (`cargo build --workspace --all-features`) ran in the copy, both exit 0. Every scenario was run twice; the two outputs were byte-identical.

## Coverage
| Criterion or item | Reached | Result |
| --- | --- | --- |
| 1. `Error::Timestamp` / `Error::Revocation` carry a kind set by the source, `Unavailable` by default, `kind()` returns it (`c1-core-kind.txt`) | yes | as expected — `timestamp()` / `revocation()` give `Unavailable`; `*_with_kind` and a struct literal give the kind passed; `source()` still downcasts to the implementation's error |
| 1. invalid input: a boxed error passed to the constructor (`c1-core-kind-error.txt`) | yes | as expected — a `BoxError` passes unchanged; a concrete `Box<io::Error>` is boxed again, as the rustdoc warns |
| 2. `HttpTsa`: forged token → `InvalidSignature`, replayed token → `InvalidSignature`, wrong-length imprint → `InvalidInput`, unreachable → `Unavailable` (`c2-http-tsa.txt`) | yes | as expected — the wrong-length imprint comes back as `Error::DigestLength`, kind `InvalidInput`, before any request |
| 2. invalid input: garbage answer, 500, malformed URL, empty imprint (`c2-http-tsa-error.txt`) | yes | garbage → `InvalidInput`, 500 → `Unavailable`, empty imprint → `InvalidInput`; malformed URL → `Unavailable`: finding 1 |
| 3. `HttpCrlSource`: malformed CRL → `InvalidInput`, refused address → `InvalidInput` (127.0.0.1 by default, 10.1.2.3 even with loopback allowed), unreachable → `Unavailable`; no signature check (`c3-http-crl.txt`) | yes | as expected — a control fetch of a valid CRL with an empty issuer comes back `Ok`, so the source does not judge the signature |
| 3. invalid input: certificate not DER, no distribution point, 404 (`c3-http-crl-error.txt`) | yes | as expected — `InvalidInput`, `Indeterminate`, `Unavailable`; each message says what was wrong, none names the address |
| 4. `HttpOcspSource`: replayed response (fixed nonce) → `InvalidSignature`, refused address → `InvalidInput` (127.0.0.1 by default, fd00::1 with loopback allowed) (`c4-http-ocsp.txt`) | yes | as expected |
| 4. invalid input: certificate not DER, no responder, garbage answer, unreachable (`c4-http-ocsp-error.txt`) | yes | as expected — `InvalidInput`, `Indeterminate`, `InvalidInput`, `Unavailable` |
| Every `Display` of the core error | yes | as expected — the fixed texts "the timestamp authority failed" / "the revocation source failed"; no address, path or secret in any message seen |

## Findings
Status rule: **verified** means the steps were replayed and reproduced the defect, and an evidence file holds it; **probable** means it was seen once, or no evidence file could be kept; **unverified** means it is suspected from what the surface showed, not seen happening.

### Finding 1 — A malformed TSA URL reads as an outage
Severity: minor
Status: verified
Steps to reproduce:
1. Build the program of `program.txt` against the story's tree.
2. Run scenario `tsa-error`: `HttpTsa::new("not a url").timestamp(DigestAlgorithm::Sha256, &digest)`.
Capture: docs/qa/s39-error-kind-from-sources/c2-http-tsa-error.txt: transcript
Expected: the story's aim is that `kind()` says the true category so an application does not retry the wrong thing; a URL the caller wrote wrong is the caller's input, not an unavailable service.
Observed: `Err(nacre_core::Error::Timestamp { .. })`, `kind()` = `Unavailable`, source "TSA request failed: http: invalid uri character". An application following the kind would retry a configuration mistake as an outage. The kind comes from the existing mapping of `nacre_tsp::Error::Http` in `crates/nacre-tsp/src/error.rs`, which this story carries unchanged by design (plan, run interdicts); it is outside the criteria's cases, so it does not contradict them.

## Not seen
- 5. "Un test par cas, sur un serveur local" — no observable effect through the endpoint: it is a property of the test suite, which the record (`docs/verif/`) and the review check, not the surface.
- Behaviour against a real TSA, CRL server or OCSP responder over a real network — the driver contacts nothing it did not start, and the story forbids a public TSA in tests.

Tree: 15c2511ea3c27f115eda5de6b2ffbbdca4a2e94e
QA status: complete
