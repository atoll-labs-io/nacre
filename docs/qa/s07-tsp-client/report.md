# QA — s07-tsp-client

[Story](../../stories.md) · [Plan](../../plans/s07-tsp-client.md)

Scope: the story's surface, what `git diff main...story/s07-tsp-client` touches on it, and the acceptance criteria its user can observe through it; nothing else was checked.
Driver: `scenarios.md` of qa-drivers — surface `endpoint`, platform `lib, cli` (row `endpoint` / `api, lib`; no `cli` row matches `endpoint`)
Evidence: transcripts
Tool: Bash (scratch Rust crate depending on a copy of the worktree, run from a `mktemp -d` directory; `Install` and `Build` run in that copy, both exit 0)
Origin: — (a library: nothing served. Only QA's own throwaway servers on 127.0.0.1:28461–28463 were called, and 28464 was checked closed; no public TSA, no s02 bench port)

Second walk, on the code after fix commit `fab0657`. Every scenario was run again on this tree, twice. `c1-request-and-verify.txt`, `c1-request-and-verify-error.txt`, `c2-rejections-error.txt`, `c4-no-network-deps.txt`, `c4-no-network-deps-error.txt` and `c5-hostile.txt` printed byte-for-byte what they already hold, so they stand unchanged. The other transcripts were rewritten from this walk.

## Coverage
| Criterion or item | Reached | Result |
| --- | --- | --- |
| 1. An imprint gives a DER `TimeStampReq` with nonce and `certReq`; the `TimeStampResp` is read and `TSTInfo` checked (imprint, nonce, status, signature) — `c1-request-and-verify.txt`, `c1-request-and-verify-error.txt` | yes | as expected. The request is byte-for-byte OpenSSL's `request.tsq`, and OpenSSL reads it back with nonce `0xD41CBFF4FDED9D81` and `Certificate required: yes`. The recorded bench and DigiCert responses verify. A wrong-length imprint, non-DER input, a refused status and a granted status with no token each give an error that says what was wrong |
| 2. A differing imprint, nonce or signature is rejected, each with its own error — `c2-rejections.txt`, `c2-rejections-error.txt` | yes | as expected: `ImprintMismatch`, `NonceMismatch`, `NonceMissing` and `Cms(SignatureInvalid)` are all distinct. The forged baseline verifies. A wrong algorithm, a cut imprint and a truncated token are refused. The five cases forged by the fix run are each rejected with the error `docs/security/attacks/tsp.md` names: `NotTstInfo`, `NotTimestampingCertificate` (twice), `ImprintMismatch` (twice) |
| 3. With `http`, a `TimestampAuthority` calls a TSA over HTTP (`application/timestamp-query`) and returns a verified token — `c3-http.txt`, `c3-http-error.txt`, `c3-http-replay.txt` | partly (s02's own TSA script, started by QA, not the s02 bench) | as expected for the nominal run. Two tokens verified per run, each with an 8-byte nonce, and the TSA certificate equals `tsa.cert.pem`. The server received `Content-Type: application/timestamp-query`. A closed port, a server that is not a TSA and a malformed URL give kind `Unavailable`. A 5-byte imprint now gives `nacre_core::Error::DigestLength`, kind `InvalidInput`, and no request is sent (this is the fix for half of the first walk's finding 1). See findings 1 and 2 |
| 4. Without `http`, no network dependency (`cargo tree`) — `c4-no-network-deps.txt`, `c4-no-network-deps-error.txt` | yes | as expected: the normal tree is the same as before and has no ureq, rustls, ring, webpki, hyper, tokio or similar crate. With `--features http` they show up (ureq 3.5.0, rustls 0.23.46, ring 0.17.14, webpki 0.103.16). An unknown feature `https` is refused, and cargo names `http` |
| 5. A hostile response gives an error, never a panic; a fuzz target exists; `docs/security/attacks/tsp.md` lists the three attacks, each with its rejected case — `c5-hostile.txt`, `c5-fuzz-target.txt`, `c2-rejections.txt` | yes | as expected. 200 000 mutated or truncated `bench.tsr` inputs give 200 000 errors and no panic. 100 000 nested indefinite SEQUENCEs and a 2^32−1 length give errors. `cargo +nightly fuzz build response` builds; a 20 s run did 851 602 runs with no crash and no artifact. The fuzz target is unchanged since the first walk. The attack file lists replay without a nonce, a token of another imprint and a TSA certificate without `id-kp-timeStamping`, plus the eight others. Each corpus case is rejected with the error the file names |

## Findings
Status rule: **verified** means the steps were replayed and reproduced the defect, and an evidence file holds it; **probable** means it was seen once, or no evidence file could be kept; **unverified** means it is suspected from what the surface showed, not seen happening.

### Finding 1 — Through `TimestampAuthority`, a forged or replayed token still reports kind `Unavailable`
Severity: minor
Status: verified
Steps to reproduce:
1. Serve, on 127.0.0.1, an HTTP endpoint that answers every POST with `crates/nacre-tsp/tests/corpus/recorded/bench.tsr`. QA's `replay.sh` behind `tsa_server.py` does this; both are quoted in the transcripts.
2. `HttpTsa::new("http://127.0.0.1:28463/").timestamp(DigestAlgorithm::Sha256, &[7; 32])`.
3. Read `e.kind()` and `e.source()`.
Capture: `docs/qa/s07-tsp-client/c3-http-replay.txt`. It was replayed once and gave the same output.
Expected: the coarse kind a caller acts on keeps a token that fails verification apart from a TSA that cannot be reached. `verify_response` itself classes `ImprintMismatch` and `NonceMismatch` as `InvalidSignature` (`c2-rejections.txt`).
Observed: `the timestamp authority failed | source: "the token time-stamps another imprint" | kind Unavailable`. This is carried from the first walk. Its wrong-length-imprint half is fixed (see criterion 3). The review records the rest as the subject of contract story s39 (ADR-0016), not to be fixed in s07.

### Finding 2 — A wrong-length imprint given to `HttpTsa` is reported against "the signature algorithm"
Severity: minor
Status: verified
Steps to reproduce:
1. `HttpTsa::new("http://127.0.0.1:28461/cgi-bin/tsa").timestamp(DigestAlgorithm::Sha256, &[7; 5])`.
2. Print the error.
Capture: `docs/qa/s07-tsp-client/c3-http-error.txt` (last line). It was replayed once and gave the same output.
Expected: a message naming the digest. `nacre-tsp`'s own `Request::new` says `digest length is 5 bytes, the algorithm produces 32` (`c1-request-and-verify-error.txt`).
Observed: `digest length is 5 bytes, the signature algorithm expects 32`. This is the text of `nacre_core::Error::DigestLength`, which the fix run now returns. There is no signature algorithm in a time-stamp request, so a caller reading the message is pointed at the wrong input. The kind (`InvalidInput`) and the numbers are right. The text lives in `nacre-core`, outside this story's `Owns`.

## Not seen
- Criterion 3 against the s02 conformance bench itself (the `pki` container on 127.0.0.1:18081). The driver forbids starting a service QA did not start. QA ran s02's own `cgi-bin/tsa` script instead, on a PKI it generated in its copy, behind its own server on a free port. The bench run is the implementer's `conformance` row in `docs/verif/s07-tsp-client.md`, and CI's `conformance` job runs it again.
- Live public TSAs (FreeTSA, DigiCert): never called, by the story's own rule. Only their recorded responses were exercised. DigiCert verifies. FreeTSA is `Indeterminate` (`Cms(UnsupportedAlgorithm(sha512))`), as the plan intends.
- Behaviour on a real network or under load (timeouts against a slow TSA, TLS to an `https://` TSA, redirects): the scenarios driver cannot show it.
- "Only the imprint leaves, never the document": only partly shown. The request is OpenSSL's byte for byte and holds only the digest, and the local TSA got only that request. It was not observed against a third-party server.

Tree: 66213787fb0f8c8fc2b24273d15b2ff321f1df46
QA status: complete
