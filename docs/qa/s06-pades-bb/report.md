# QA — s06-pades-bb

[Story](../../stories.md) · [Plan](../../plans/s06-pades-bb.md)

Scope: the story's surface, what `git diff main...story/s06-pades-bb` touches on it, and the acceptance criteria its user can observe through it; nothing else was checked.
Driver: scenarios.md of qa-drivers — surface endpoint, platform lib, cli
Evidence: transcripts
Tool: Bash (a scratch Rust program calling `nacre_pades::sign` from outside the worktree, on a copy of the tracked files; openssl to read the CMS; the conformance bench's DSS 6.5.1 as judge)
Origin: — (nothing served by the story; the conformance bench was started from the temporary copy, compose project `nacre-conformance`, on 127.0.0.1:18080 and 18081, `check.sh` ending with `bench ready`, and brought down at the end of the walk)

The public interface walked is `nacre_pades::sign(pdf, &dyn Signer, DateTime)`, called as Patelle would: a `Signer` written by the caller over the bench's `signer` key and its chain up to the intermediate, a fixed time 2026-10-22T08:00:00Z. The program, its manifest, the transcript wrapper and the bench start are quoted whole in `scenario-program.txt`.

## Coverage
| Criterion or item | Reached | Result |
| --- | --- | --- |
| 1. `sign` with the bench signer and PKI → DSS `TOTAL_PASSED` at `PAdES-BASELINE-B` | yes | as expected — one signature, `format=PAdES-BASELINE-B`, `TotalPassed`, no sub-indication (`criterion-1-baseline-b.txt`) |
| 1. invalid input: not a PDF, an empty file, a truncated PDF | yes | as expected — refused with `Pdf(MissingHeader)` / `Pdf(MissingStartxref)`, kind `InvalidInput`, a message saying what is wrong (`criterion-1-baseline-b-error.txt`) |
| 2. `/SubFilter /ETSI.CAdES.detached`, CMS with `signing-certificate-v2` and no `signing-time`, time in `/M` | yes | as expected — `/Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached`, `/M` decodes to `D:20261022080000Z`; openssl lists signed attributes `contentType`, `messageDigest`, `id-smime-aa-signingCertificateV2` only, no `signingTime` anywhere, `crls` absent, no unsigned attributes (`criterion-2-subfilter-cms.txt`) |
| 2. invalid input: one byte of the page text changed after signing | yes | as expected — DSS `TotalFailed`, `HashFailure`: the `/ByteRange` covers the content (`criterion-2-subfilter-cms-error.txt`) |
| 3. second signature on a signed PDF, new revision, DSS judges both `PAdES-BASELINE-B` | yes | as expected — fields `Signature1` and `Signature2`, three `%%EOF`, the first `/ByteRange` ends at the first signed file's length; DSS: two signatures, both `PAdES-BASELINE-B`, `TotalPassed`. Also signed the bench's own `reference/out/pades-baseline-b.pdf` (signed by another tool): DSS judges both signatures `PAdES-BASELINE-B`, `TotalPassed` (`criterion-3-second-signature.txt`) |
| 3. invalid input: a signed PDF cut short | yes | as expected — refused, `Pdf(MissingStartxref)`, kind `InvalidInput` (`criterion-3-second-signature-error.txt`) |
| 4. original bytes intact as a prefix | yes | as expected — `cmp -n` and SHA-256 of the prefix match after the first and the second signature (`criterion-4-prefix.txt`) |
| 4. invalid input: data after the last `%%EOF` | yes | as expected — refused, `Pdf(TrailingData { offset: 746 })`, no file written, so no output can break the prefix rule (`criterion-4-prefix-error.txt`) |
| 5. `/Contents` reserve sufficient and computed | yes | as expected — reserve 1586 bytes, CMS 1584 bytes, 2 zero bytes left, equal to 72 (P-256 DER maximum) − 70 (the signature value openssl reads); same on every one of five signatures; with nacre-core's `TestSigner` (one self-signed certificate) the signed file is 3179 bytes against 4669 with the two-certificate chain, so the reserve follows the signer (`criterion-5-reserve.txt`) |

## Findings
None. No defect was seen through the surface.

Two notes that are not findings of this story:
- Changing byte 101 of a signed file (inside the PDF header region) made DSS answer HTTP 500 instead of a verdict (first step of `criterion-2-subfilter-cms-error.txt`). That is the bench's judge on a malformed file, not `nacre-pades`; the content tamper that followed got a proper `HashFailure`.
- In `criterion-5-reserve.txt`, the `inspect selfsigned.pdf` step panics with `NotFound`: the scratch binary was built before its `sign-test` mode was taught to write its output, so no file existed to read. A fault of the QA program, not of the story; only the output length of that run is evidence.

## Not seen
- Criterion 5 with a 71- or 72-byte ECDSA value, or with an RSA signer — every signature the bench signer produced in this walk had a 70-byte value, and building a second signer needed rebuilding the scratch program, which the temporary filesystem's disk quota (shared with the parallel QA lanes) refused during the walk. The relation reserve − CMS = 72 − signature length was observed only at 70; the RSA bound and other lengths are left to the unit tests `rsa_bound_covers_the_signature` and `reserve_leaves_only_the_signature_slack`.
- Criterion 5, invalid input (a signer of an unsupported algorithm) — needs a `Signer` the scratch program does not have, for the same reason.
- Behaviour in a real PDF reader (Acrobat, Okular) — not a dependency the driver starts; DSS is the judge the criteria name.

Tree: e0fff7cedabb0b9d2076220253895765774e2cc4
QA status: complete
