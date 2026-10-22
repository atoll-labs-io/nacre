# QA — s13-pkcs11-signer

[Story](../../stories.md) · [Plan](../../plans/s13-pkcs11-signer.md)

Scope: the story's surface, what `git diff main...story/s13-pkcs11-signer` touches on it, and the acceptance criteria its user can observe through it; nothing else was checked.
Driver: scenarios.md — surface endpoint, platform lib, cli
Evidence: transcripts
Tool: Bash (cargo, SoftHSM 2.7.0 with softhsm2-util and p11tool, OpenSSL, podman compose for the conformance bench)
Origin: —

Second walk, on the code after fix run 1 (`bc6436e`). Every scenario ran on a copy of the tracked files in a `mktemp -d` folder (Install `cargo fetch`, Build `cargo build --workspace --all-features`, both exit 0), against a throwaway SoftHSM token created in that folder, with fictitious keys and certificates. The library was driven through its public interface by the probes `probe.rs`, `two.rs`, `seq.rs`, `reauth.rs` and `mkalways.rs` (kept next to this report), and through the crate's example `sign_pdf`. The conformance bench `nacre-conformance` was started from the copy (fresh PKI, `bench ready`) and brought down at the end; `patelle-dss` was not touched. No hardware token was touched.

## Coverage
| Criterion or item | Reached | Result |
| --- | --- | --- |
| 1. ECDSA P-256 key found by label, `r\|\|s` returned as DER (`c1-ecdsa.txt`) | yes | as expected: three 71-72-byte DER signatures, each verified by OpenSSL against the token's certificate; chain[0] is that certificate |
| 1. RSA key found by id, PKCS#1 v1.5 SHA-256 (`c1-rsa.txt`) | yes | as expected: verified by OpenSSL; recovered DigestInfo is sha256 + the digest |
| 1. Token not named, one initialized token (`c1-rsa.txt`, 1c) | yes | as expected |
| 1. Key marked always-authenticate (the PIV 9c case), two signatures from one signer (`c1-always-authenticate.txt`) | yes | as expected: both verified by OpenSSL |
| 1. Invalid inputs: absent key label, unknown token, missing module path, non-PKCS#11 library, P-384 key, key without certificate, 20-byte digest to ECDSA and RSA (`c1-ecdsa-rsa-error.txt`) | yes | as expected: a named error each (`KeyNotFound`, `TokenNotFound`, `ModuleUnavailable` x2, `UnsupportedKey`, `CertificateNotFound`, `DigestLength { expected: 32, actual: 20 }` x2), no panic, no path or label in any message, no signature file |
| 2. A PDF signed by a SoftHSM key is `PAdES-BASELINE-B` for DSS (`c2-dss-pades-b.txt`, `c2-dss-report.xml`) | yes, locally | as expected: `TotalPassed`, no sub-indication, format `PAdES-BASELINE-B`. The one `FAILED` in DSS's JSON is the eIDAS qualification block ("Unable to build a certificate chain up to a trusted list!"), expected on the test PKI |
| 3. Wrong PIN to `open`: error with the token's state, no panic, no signature (`c3-wrong-pin.txt`) | yes | as expected: `WrongPin(CountLow)` ("the token refused the PIN (few tries left)") for a wrong, an empty and a 300-character PIN; no signature file; a typo then the right PIN in the same process signs |
| 3. A second signer opened on a token the process is already logged in to (`c3-wrong-pin-second-signer.txt`) | yes | as expected: the previous walk's finding 1 no longer reproduces. With a wrong PIN, and with the right one, the second `open` fails with `AlreadyLoggedIn` ("this process is already logged in to the token; open one signer per token"); the first signer keeps signing. Once the first signer is dropped, a second signer gets `WrongPin(CountLow)` for a wrong PIN and opens and signs with the right one |
| 3. The token refuses an always-authenticate key's PIN at a signature (PIN changed after `open`) (`c3-refused-pin-at-signature.txt`) | yes | as expected: the first signature after the change fails with `WrongPin(CountLow)`, the next two with `PinRefused` ("the token refused this signer's PIN earlier; open a new signer"); no panic, no signature; replayed with the same result |
| 4. PIN in no error message and no log (`c3-wrong-pin.txt`, `c3-refused-pin-at-signature.txt`, `c4-pin-not-shown.txt`) | yes | as expected: 0 occurrences of any PIN in Display, Debug, source chains, the example's stdout and stderr (wrong and right PIN); the library prints nothing on a nominal run |

## Findings
Status rule: **verified** means the steps were replayed and reproduced the defect, and an evidence file holds it; **probable** means it was seen once, or no evidence file could be kept; **unverified** means it is suspected from what the surface showed, not seen happening.

No finding on this walk. Finding 1 of the previous walk (a wrong PIN opening a second signer while another signer of the process was logged in) was replayed twice on the fixed code and no longer reproduces: `c3-wrong-pin-second-signer.txt`.

## Not seen
- Criterion 2, "dans la CI" — only the local run was seen; the `conformance.yml` job (Ubuntu's SoftHSM 2.6.1) is outside this walk.
- Criterion 3, `FinalTry` and `Locked` on a token — SoftHSM 2.7.0 reports only "count low"; those states would show only on a token that raises them (real hardware).
- Criterion 3, whether a refused context-specific PIN is sent to the token again — the surface shows `PinRefused` returned on later signatures, not what reaches the token; SoftHSM exposes no try counter to read.
- Criterion 4, the PIN's zeroization in memory — no observable effect through the surface (no safe way to read freed memory); only its absence from messages and output was checked.
- Criterion 5, the manual run on a real YubiKey (PIV 9c, `libykcs11`) recorded in `MANUAL.md` with DSS's report — only real hardware would show it; it is the person's run, and no hardware token was touched. `MANUAL.md`'s results table still reads "not run".

Tree: fcb0b500e2430d972712ceb4b9ea1b5e6a239611
QA status: complete
