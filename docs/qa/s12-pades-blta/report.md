# QA — s12-pades-blta

[Story](../../stories.md) · [Plan](../../plans/s12-pades-blta.md)

Scope: the story's surface, what `git diff main...story/s12-pades-blta` touches on it, and the acceptance criteria its user can observe through it; nothing else was checked.
Driver: scenarios.md — surface endpoint, platform lib, cli
Evidence: transcripts
Tool: Bash (a scratch Rust crate calling the public interface of `nacre-pades`, on a copy of the tracked files under a `mktemp -d` directory; quoted whole in `scenario-program.txt`)
Origin: —

This walk replaces the one made on tree `576cdbd8…`. The fix commit `b20a2c2` changed `extend`: it now keeps only the `/DSS /Certs` entries that parse as certificates. It also serialised the bench TSA script. So every scenario was run again on the current tree, and two scenarios were added for the filtered `/DSS` case of the last review's major finding. The walk called `sign_at_level(…, Level::LTA { tsa, revocation, issuers, document_tsa })` and `extend(pdf, tsa, revocation, issuers)` on `crates/nacre-pades/tests/corpus/unsigned.pdf`.

It used a throwaway P-256 PKI, regenerated for this walk:
- a root and a signer leaf (OCSP URL and CRL distribution point);
- two distinct TSA leaves, `Nacre QA signature TSA` and `Nacre QA document TSA`, with a CRL distribution point only;
- an `Orphan TSA` issued by an unrelated `Elsewhere CA`.

Each TSA was a caller-written `TimestampAuthority` answering through `openssl ts -reply -section <its section>`. A `CertLess` wrapper removed every certificate from a token before nacre saw it. Revocation came from `nacre_revocation::Fallback(HttpOcspSource::allowing_loopback(), HttpCrlSource::allowing_loopback())`, pointed at an `openssl ocsp` responder and a static CRL server. This QA started both on loopback and stopped them afterwards. Every output was read back through `nacre_pdf` and `nacre_cms`. Each document timestamp was checked with `openssl ts -verify -digest <SHA-256 over its /ByteRange> -CAfile <QA root>`.

## Coverage
| Criterion or item | Reached | Result |
| --- | --- | --- |
| 1. `Level::LTA` adds a `/DocTimeStamp` revision (`/SubFilter /ETSI.RFC3161`) after `/DSS`; DSS says `TOTAL_PASSED` at `PAdES-BASELINE-LTA` | partly | As expected for the file. DSS's verdict was not reached (see Not seen).<br>**Nominal** (`c1-lta-level.txt`):<br>- The output has 4 revisions. The last field is `/Type /DocTimeStamp /SubFilter /ETSI.RFC3161` with no `/M`, and its `/ByteRange` ends at the end of the file.<br>- The file cut before that revision already holds `/DSS`, so the timestamp comes after `/DSS` and covers it.<br>- `openssl ts -verify` says `Verification: OK`.<br>- The signer signed once and each TSA was asked once. The document TSA got the digest of the final range.<br>**Invalid input** (`c1-lta-level-error.txt`):<br>- A document TSA that is down, or one that answers bytes that are not a token, gives `Archive`: `the document timestamp could not be added: …`, kind `Unavailable` or `InvalidInput`. It hands back the B-LT file: 3 revisions, `/DSS`, no document timestamp, `Debug` = `SignedPdf { len: 40406 }`.<br>- A file that is not a PDF gives `PDF: the input does not start with %PDF-`, and no TSA, signer or source is asked. |
| 2. `extend` on an LTA PDF adds an updated `/DSS` (revocation of the previous TSA), then a new document timestamp; DSS still says `PAdES-BASELINE-LTA` | partly | As expected for the file. DSS's verdict was not reached.<br>**Nominal** (`c2-extend.txt`):<br>- Each call adds 2 revisions: a `/DSS` update, then a new document timestamp. The `/VRI` key added is the SHA-1 of the previous doc-TST `/Contents`.<br>- The second call takes the newest doc-TST. The source is asked only about the previous TSA's leaf. Every timestamp still verifies.<br>- When the newest token carries no certificate, `extend` finds its signer in `/DSS` or in `issuers`, then renews.<br>- **New since `b20a2c2`:** a FlateDecode stream (the TSA certificate deflated) or a raw non-certificate stream listed first in `/DSS /Certs` no longer blocks renewal. `extend` returns `Ok`, the signer is found in its unfiltered copy, and the new `/VRI` names that TSA and the root. The foreign stream stays in `/Certs` untouched. The last review's major finding no longer reproduces.<br>**Invalid input** (`c2-extend-error.txt`):<br>- Each of these gives a precise error with no TSA call: an unsigned file, a B-LT file or a file that is not a PDF; a doc-TST `/Contents` starting with `00` or padded with `01`; revocation that cannot be obtained. The errors are `NotArchived`, `Pdf`, `DocumentTimestamp` and `Revocation`.<br>- A certificate-less token whose signer is nowhere gives `TimestampSignerMissing` (kind `Indeterminate`), and neither the TSA nor the source is asked. The same happens with a wrong certificate, with bytes that are not X.509 in `issuers` and, new, when the signer's only `/DSS` copy is a FlateDecode stream. That last case is refused as missing, not guessed. Passing the certificate in `issuers` then renews.<br>- A renewing TSA that is down gives `Archive` with the file holding the new `/DSS` revision. Findings 1 and 3 apply. |
| 3. `extend` never decides when it is called | yes | As expected.<br>**Nominal** (`c3-caller-decides.txt`): three `extend` calls in a row, 17 to 23 ms apart and right after signing, all succeed, and each adds a document timestamp. The public signature takes no time or age parameter.<br>**Invalid input** (`c3-caller-decides-error.txt`): B-B and B-T files give `NotArchived`. There is never a "not due" refusal and never a silent upgrade. |
| 4. The bytes of each earlier revision are intact as a prefix of the result | yes | As expected.<br>**Nominal** (`c4-prefix.txt`): the files were chained unsigned → LTA → `extend` → `extend`. Each output starts with its input, and every revision end of the input is a byte prefix of the output. This also holds for the file `extend` hands back in `Archive` (`c2-extend-error.txt`) and for the filtered-`/DSS` inputs (`c2-extend.txt`).<br>**Invalid input** (`c4-prefix-error.txt`): an LTA file cut by 100 bytes, or one with bytes after `%%EOF`, gives a `PDF: …` error naming the fault, and the TSA is not asked. |
| 5. An LTA PDF with two distinct TSAs (signature, document) is accepted by DSS | partly | As expected for the file. DSS's acceptance was not reached.<br>**Nominal** (`c5-two-tsa.txt`): the signature-time-stamp token carries `Nacre QA signature TSA`, and the document timestamp carries `Nacre QA document TSA`. They are distinct certificates, with policies `tsa_policy1` and 1.2.3.4.2.<br>**Invalid input** (`c5-two-tsa-error.txt`):<br>- One TSA instance in both roles is accepted and asked twice. The story does not forbid this.<br>- A document TSA chained to a CA nobody passed: finding 2. |

## Findings
Status rule: **verified** means the steps were replayed and reproduced the defect, and an evidence file holds it; **probable** means it was seen once, or no evidence file could be kept; **unverified** means it is suspected from what the surface showed, not seen happening.

### Finding 1 — A file handed back in `Error::Archive` can be finished only by doing the work again
Severity: minor
Status: verified
Steps to reproduce:
1. Sign `unsigned.pdf` at `Level::LTA` with two working TSAs.
2. Call `extend(lta, &a_tsa_that_returns_Err, &http_source, &[])` and take `signed` from the `Error::Archive` it returns (75 730 bytes, 5 revisions, the new `/DSS`).
3. Call `extend(signed, &a_working_tsa, &http_source, &[])`.
4. Call `extend` on the B-LT file that `sign_at_level` hands back in criterion 1.
Capture: docs/qa/s12-pades-blta/c2-extend-error.txt (sections "the renewing TSA is down, then the handed-back file is given to extend again" with its replay, and "a B-LT PDF")
Expected: the rustdoc says the hand-back keeps the fetched data. A caller retrying after a TSA outage would expect the kept revision to spare the revocation fetch, leaving only the document timestamp to add.
Observed:
- Step 3 asks the revocation source again (`Crl, 211 bytes`) and writes a second `/DSS` revision before the timestamp. The result has 7 revisions, `/Certs` grows from 5 to 7 streams and `/CRLs` from 2 to 3.
- Step 4 returns `NotArchived`, so the public interface cannot raise the B-LT hand-back to LTA without signing again.

The story and the plan ask for no resume path, so this is a limit of the hand-back, not a departure from them. It is unchanged by `b20a2c2`.

### Finding 2 — An LTA signature accepts a document timestamp whose signer chain nacre cannot build, and only `extend` finds out
Severity: minor
Status: verified
Steps to reproduce:
1. Sign `unsigned.pdf` at `Level::LTA { tsa, revocation, issuers: &[], document_tsa }`, where `document_tsa` is `Orphan TSA`, issued by `Elsewhere CA`, which neither the token nor `issuers` holds.
2. Call `extend` on the result with `issuers` empty, then again with `issuers = [Elsewhere CA]`.
Capture: docs/qa/s12-pades-blta/c5-two-tsa-error.txt (first run and replay); docs/qa/s12-pades-blta/c2-extend.txt (certificate-less token, signed then renewed)
Expected: the brief wants the proof to survive once certificates expire. A document timestamp whose issuer is unknown cannot be renewed later, so a caller would want to learn that at signing time, not at the first renewal.
Observed:
- `sign_at_level` returns `Ok` (73 826 bytes) without checking or storing the document TSA's chain.
- The first `extend` fails with `IssuerMissing` (`the issuer of CN=Orphan TSA,O=Elsewhere,C=FR is in neither the chains nor the issuers given`, kind `Indeterminate`). The second succeeds.
- The same holds for a certificate-less document token: `sign_at_level` accepts it, and only `extend` returns `TimestampSignerMissing`.

This follows the plan's order. It is unchanged by `b20a2c2`.

### Finding 3 — Each `extend` stores again in `/DSS` the root and TSA certificates and the CRL already there
Severity: minor
Status: verified
Steps to reproduce:
1. Sign at `Level::LTA` with the signature TSA and the document TSA, both issued by the QA root.
2. Call `extend` with the signature TSA, then `extend` again with the document TSA.
3. List `/DSS /Certs` and `/CRLs`.
Capture: docs/qa/s12-pades-blta/c2-extend.txt (first run and replay)
Expected: nothing in the story asks for duplicates. A reader would expect one copy of each distinct item, especially in a file meant to be extended again and again.
Observed:
- After two renewals, `/Certs` holds 7 streams for 4 distinct certificates (`Nacre QA root` 3 times, `Nacre QA signature TSA` twice), and `/CRLs` holds the same 211-byte CRL 3 times.
- When the signer of a certificate-less token is found in `/DSS`, `extend` writes that TSA certificate into `/DSS` a second time. This happens in the filtered-`/DSS` scenarios too (`11 0 R` and `20 0 R`).
- The file grows by about 35 kB per `extend`.

This continues finding 3 of the s11 QA. It is unchanged by `b20a2c2`.

## Not seen
- Criteria 1, 2 and 5: DSS's verdict `TOTAL_PASSED` / `PAdES-BASELINE-LTA` after signing, after `extend`, and with two distinct TSAs. It shows only through the DSS bench and its TSA, OCSP and CRL services (`conformance/compose.yaml`), which this driver did not start and may not write to. `docs/verif/s12-pades-blta.md` records a run of the conformance tests against DSS. This QA did not replay it.
- The bench TSA scripts `tsa` (its new `flock` serialisation) and `tsa2`, with `check.sh` and `conformance/pki/`: they are reached only through the bench, which this driver may not start. The walk used its own TSAs.
- Revocation through a real remote OCSP responder or CRL server, and a real network TSA: they need a real network, which is out of the driver's reach. Only loopback servers that this QA started were used.
- An RSA signer or TSA, and a document TSA whose own certificate has an OCSP URL: not exercised, since the walk used P-256 throughout and CRL-only TSAs.
- A foreign LTA file written by another tool (DSS, pyHanko): every input was built by nacre. The filtered `/DSS /Certs` stream was added by this QA through `nacre_pdf`'s update API, not taken from such a file.

Tree: 0d268180e2ffb97fe85675ecd4b6f3ebd6861c5e
QA status: complete
