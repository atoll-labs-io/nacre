# QA — s08-pades-bt

[Story](../../stories.md) · [Plan](../../plans/s08-pades-bt.md)

Scope: the story's surface, what `git diff main...story/s08-pades-bt` touches on it, and the acceptance criteria its user can observe through it; nothing else was checked.
Driver: scenarios.md — surface endpoint, platform lib, cli
Evidence: transcripts
Tool: Bash (a scratch Rust crate calling the public interface of `nacre-pades`, on a copy of the tracked files under a `mktemp -d` directory; quoted whole in `scenario-program.txt`)
Origin: —

The walk used `sign_at_level(…, Level::T { tsa })` as the plan names it (`sign` stays B-B). The authority was `nacre_tsp::HttpTsa` against a throwaway TSA this QA started on `127.0.0.1` (`openssl ts -reply`, its own self-signed timeStamping certificate), or a caller-written `TimestampAuthority` returning fixed bytes. The signer was `nacre_core::TestSigner`.

## Coverage
| Criterion or item | Reached | Result |
| --- | --- | --- |
| 1. `sign` at T with the s02 local TSA → DSS `TOTAL_PASSED`, `PAdES-BASELINE-T` | no | not reached — needs the DSS bench and its TSA, which this QA did not start (see Not seen) |
| 2. Token in unsigned attribute `signature-time-stamp` of the `SignerInfo`, over the signature value | yes | as expected — one unsigned attribute `1.2.840.113549.1.9.16.2.14`; its token verifies over SHA-256 of the signature value with `nacre_tsp::verify_token` and independently with `openssl ts -verify -data <signature value>`; unsigned input is a byte prefix of the output; authority asked once (`token-in-signerinfo.txt`). Invalid input (not a PDF): `PDF: the input does not start with %PDF-`, kind `InvalidInput`, authority asked 0 times (`token-in-signerinfo-error.txt`) |
| 3. Unreachable TSA or refused answer → `sign` fails with an error naming the TSA; no partial PDF | yes | as expected for the failure and the absence of a PDF (connection refused, status 2 rejection, malformed URL, non-DER token: all `Err`, no output); finding 1 on what the message names, finding 2 on its wording (`tsa-failure.txt`, `tsa-failure-error.txt`) |
| 4. `/Contents` reserve covers the token; too large a token → clear error | yes | as expected — a 16 384-byte token signs; 16 385 and 40 000 bytes give `the timestamp token is N bytes, more than the 16384 reserved`, kind `InvalidInput`, no PDF (`contents-reserve.txt`, `contents-reserve-error.txt`) |

## Findings
Status rule: **verified** means the steps were replayed and reproduced the defect, and an evidence file holds it; **probable** means it was seen once, or no evidence file could be kept; **unverified** means it is suspected from what the surface showed, not seen happening.

### Finding 1 — The TSA error does not say which TSA failed
Severity: minor
Status: verified
Steps to reproduce:
1. Build `HttpTsa::new("http://127.0.0.1:18493/")` with nothing listening on that port.
2. Call `sign_at_level(unsigned.pdf, &signer, time, Level::T { tsa: &tsa })` and print the error and its `source()` chain.
Capture: docs/qa/s08-pades-bt/tsa-failure.txt (first run and replay)
Expected: `docs/stories.md:148` — « une erreur qui nomme la TSA ». The plan rewords this as an error that designates the timestamp authority as its cause, and asks the lead to carry that wording into `docs/stories.md`, which still holds the original text.
Observed: `the timestamp authority failed`, caused by `TSA request failed: io: Connection refused (os error 111)`. The role is named; no line of the chain identifies the authority (its URL or name). A caller juggling two TSAs (s12, Patelle) cannot tell from the error alone which one failed. Whether this is a defect depends on which wording of criterion 3 holds; ADR-0012 keeps file paths out of messages but says nothing on URLs.

### Finding 2 — The error chain repeats its first message
Severity: minor
Status: verified
Steps to reproduce:
1. Same as finding 1, or point `HttpTsa` at the local TSA that answers with status 2 (rejection).
2. Walk `Error::source()` from the returned `nacre_pades::Error`.
Capture: docs/qa/s08-pades-bt/tsa-failure.txt
Expected: each level of the chain adds information.
Observed: `Err (Display): the timestamp authority failed`, then `caused by: the timestamp authority failed` (the wrapped `nacre_core::Error::Timestamp`), then the real cause. A reporter that prints the whole chain shows the same sentence twice.

## Not seen
- Criterion 1 (DSS declares `TOTAL_PASSED` at `PAdES-BASELINE-T`) — it shows only through the DSS bench and the s02 local TSA (`conformance/compose.yaml`), dependencies this driver did not start and may not write to. `docs/verif/s08-pades-bt.md` records a hand run of `bench_signature_is_pades_baseline_t` as passed; that claim was not replayed here.
- Behaviour against a real remote TSA or under network latency — out of reach of the driver (real network).

Tree: 5841213cf1ea278bd0cfcce3e3e3341223601a1a
QA status: complete
