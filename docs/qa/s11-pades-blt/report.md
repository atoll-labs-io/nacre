# QA — s11-pades-blt

[Story](../../stories.md) · [Plan](../../plans/s11-pades-blt.md)

Scope: the story's surface, what `git diff main...story/s11-pades-blt` touches on it, and the acceptance criteria its user can observe through it; nothing else was checked.
Driver: scenarios.md — surface endpoint, platform lib, cli
Evidence: transcripts
Tool: Bash (a scratch Rust crate calling the public interface of `nacre-pades`, on a copy of the tracked files under a `mktemp -d` directory; quoted whole in `scenario-program.txt`)
Origin: —

The walk called `sign_at_level(…, Level::LT { tsa, revocation, issuers })` as the plan defines it, on `crates/nacre-pades/tests/corpus/unsigned.pdf`. It used a throwaway P-256 PKI made for this QA (root, signer leaf with an OCSP URL and a CRL distribution point, TSA leaf with a CRL distribution point only), and a caller-written `Signer` over the signer's key. The TSA was a caller-written `TimestampAuthority` that answers through `openssl ts -reply`. Revocation came from `nacre_revocation::Fallback(HttpOcspSource::allowing_loopback(), HttpCrlSource::allowing_loopback())`, pointed at an `openssl ocsp` responder and a static CRL server that this QA started on loopback and then stopped. Every output was read back through `nacre_pdf` and `nacre_cms`, the DSS streams through `openssl crl` / `openssl ocsp`, and the LT file once through poppler's `pdfsig`.

## Coverage
| Criterion or item | Reached | Result |
| --- | --- | --- |
| 1. `Level::LT` adds, after the signature, a revision holding `/DSS` with `/Certs`, `/CRLs`, `/OCSPs`; DSS says `TOTAL_PASSED` at `PAdES-BASELINE-LT` | partly | as expected for the file: 3 revisions against 2 at B-T. The signature's `/ByteRange` ends at byte 37050, where the B-T revision ends, and the CMS verifies over it. The third revision's catalog points at `/DSS` with `Certs`, `CRLs`, `OCSPs`, `VRI`. `pdfsig` reads the signature as valid, the DSS revision outside the signed ranges (`c1-dss-revision.txt`). Invalid input (not a PDF, truncated PDF): `PDF: …` error, kind `InvalidInput`, and signer, TSA and source are asked 0 times (`c1-dss-revision-error.txt`). The DSS verdict was not reached (see Not seen) |
| 2. `/DSS` covers the signer's chain and the TSA's, each with its revocation data; one `/VRI` entry per signature | yes | as expected — `/Certs` = signer, root, TSA (the TSA chain comes from the token). The signer is covered by an OCSP response (`good`) and the TSA by the root's CRL. The self-signed root is never asked about. One `/VRI` key equals the SHA-1 of the decoded `/Contents` with its padding. A root passed only in `issuers` is stored. A second LT signature on the LT file keeps the first `/VRI` entry and its references unchanged and adds a second one (`c2-dss-coverage.txt`). Invalid input: missing issuer, unrelated issuer, non-certificate bytes in `issuers` → `LongTerm` with the B-T returned (`c2-dss-coverage-error.txt`); findings 1, 2 and 3 |
| 3. Nothing is added to the CMS | yes | as expected — the CMS of the LT file holds the signer's chain only, `crls` empty, one unsigned attribute (`signature-time-stamp`), no `adbe-revocationInfoArchival`, and it verifies over the `/ByteRange` (`c3-cms-untouched.txt`). Invalid input (a source returning bytes that are not a CRL): the CMS is still untouched, but see finding 4 (`c3-cms-untouched-error.txt`) |
| 4. Revocation not obtainable → LT fails with an error naming the certificate; B-T handed back | yes | as expected — three causes, three runs: an OCSP-only source facing a TSA certificate with no OCSP URL; sources with the loopback policy off; both servers stopped. Each gives `the B-T signature could not be raised to B-LT: no revocation data could be obtained for <subject>`, with the cause chain below it and kind `Unavailable`. `SignedPdf` debug-prints only `len`, and the handed-back B-T parses, has no `/DSS` and its CMS verifies (`c4-revocation-unavailable.txt`, `c4-revocation-unavailable-error.txt`) |

## Findings
Status rule: **verified** means the steps were replayed and reproduced the defect, and an evidence file holds it; **probable** means it was seen once, or no evidence file could be kept; **unverified** means it is suspected from what the surface showed, not seen happening.

### Finding 1 — Malformed `issuers` is detected only after the signer has signed and the TSA has answered
Severity: minor
Status: verified
Steps to reproduce:
1. Call `sign_at_level(unsigned.pdf, &signer, time, Level::LT { tsa, revocation, issuers: &[b"not a certificate".to_vec()] })`.
2. Count the signer's and the TSA's calls and read the error.
Capture: docs/qa/s11-pades-blt/c2-dss-coverage-error.txt (first run and replay)
Expected: an input the caller gives, and that can be checked before any signing, is refused before the signer is used. With a PKCS#11 card (PIN, counter) or a paying TSA, every wasted signature costs.
Observed: `signer signed 1 time(s), TSA asked 1 time(s)`, then `LongTerm` over `Certificate`. The B-T is handed back, so nothing is lost, but the caller's own mistake costs a signature and a timestamp. A signer chain that lacks its root, with `issuers` empty, behaves the same way, and it is also knowable before signing for the signer's half of the walk. This follows the plan (task 4: "Errors before `embed` stay as today"; the pool is parsed in `ltv::material`).

### Finding 2 — "a certificate is not X.509 DER" does not say which list holds it
Severity: minor
Status: verified
Steps to reproduce:
1. Same call as finding 1.
2. Print the error and its `source()` chain.
Capture: docs/qa/s11-pades-blt/c2-dss-coverage-error.txt
Expected: an error the caller can act on: the bad item is in `issuers`, in the signer's chain or in the token's certificates.
Observed: `the B-T signature could not be raised to B-LT: a certificate is not X.509 DER`, caused by `unexpected ASN.1 DER tag: expected SEQUENCE, got APPLICATION [14] (constructed)`. Nothing says which of the three lists holds it, or at which position.

### Finding 3 — A second LT signature stores again in `/DSS` the certificates and CRL already there
Severity: minor
Status: verified
Steps to reproduce:
1. Sign `unsigned.pdf` at `Level::LT` with the signer chain `[signer, root]`.
2. Sign the result again at `Level::LT` with the same signer, TSA and sources.
3. List `/DSS /Certs`, `/CRLs`, `/OCSPs` with each stream's SHA-256.
Capture: docs/qa/s11-pades-blt/c2-dss-coverage.txt (first run and replay)
Expected: the story asks for nothing more than coverage; a reader would expect one copy of each distinct item.
Observed: `/Certs` holds 6 streams for 3 distinct certificates (same SHA-256 pairwise). `/CRLs` holds the same 209-byte CRL twice. The file grows by about 3.4 kB per signature for nothing new. The plan names this behaviour (task 3: "no deduplication against an earlier revision's streams"), so this is a cost to weigh rather than a departure from the plan; s12 (`extend`) will add to it.

### Finding 4 — Bytes that are not revocation data are stored in `/DSS` and the call succeeds
Severity: minor
Status: verified
Steps to reproduce:
1. Write a `RevocationSource` that returns `RevocationData::Crl(b"this is not a CRL".to_vec())`.
2. Call `sign_at_level(unsigned.pdf, &signer, time, Level::LT { tsa, revocation: &that_source, issuers: &[] })`.
3. Read `/DSS /CRLs` back and give the stream to `openssl crl -inform DER`.
Capture: docs/qa/s11-pades-blt/c3-cms-untouched-error.txt (first run and replay)
Expected: criterion 4 says a certificate whose revocation cannot be obtained makes LT fail. A source that hands back something that is not a CRL has not obtained one.
Observed: `Ok: 39300 bytes`. `/CRLs` holds one 17-byte stream that `openssl crl` refuses (`Could not find CRL`). `/VRI` lists it for this signature, and no `/OCSPs` is written. The caller gets an LT-shaped file that no validator would call LT, and no error. The plan intends pades to store without judging (test strategy), so the question is whether a DER-shape check at least belongs here or in s17.

## Not seen
- Criterion 1, DSS's verdict `TOTAL_PASSED` / `PAdES-BASELINE-LT`: it shows only through the DSS bench and its TSA, OCSP and CRL services (`conformance/compose.yaml`). This driver did not start them and may not write to them. `docs/verif/s11-pades-blt.md` records a hand run of `bench_signature_is_pades_baseline_lt` as passed against DSS 6.5.1; this QA did not replay it.
- Revocation through a real remote OCSP responder or CRL server, and under network latency: out of reach of the driver (real network). The HTTP sources ran only against loopback servers this QA started.
- An RSA signer or TSA, and an OCSP response signed by a delegated responder: not exercised; the walk used P-256 throughout and a root-signed OCSP response.
- The name-loop guard of the issuer walk (two certificates issuing each other): reaching it needs a crafted certificate pair this walk did not build; the plan leaves it to the reviewer too.

Tree: bfeb44789268358b506bab733f8c3faf2c5e3b28
QA status: complete
