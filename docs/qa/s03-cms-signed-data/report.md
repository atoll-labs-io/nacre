# QA — s03-cms-signed-data

[Story](../../stories.md) · [Plan](../../plans/s03-cms-signed-data.md)

Scope: the story's surface, what `git diff main...story/s03-cms-signed-data` touches on it, and the acceptance criteria its user can observe through it; nothing else was checked.
Driver: `scenarios.md` of qa-drivers — surface `endpoint`, platform `lib, cli` (row `endpoint` / `lib`; the story declares no `command` surface, so the `cli` row does not apply)
Evidence: transcripts
Tool: Bash (cargo 1.97 pinned by `rust-toolchain.toml`, OpenSSL 3.6.5, cargo-fuzz 0.13.2 on nightly), on a copy of the tracked files in a `mktemp -d` directory; `Install` (`cargo fetch`) and `Build` (`cargo build --workspace --all-features`) run there, both exit 0
Origin: — (a library: nothing served)

Each `lib` scenario is a binary of a scratch crate outside the workspace, depending on the copied `crates/nacre-cms` and `crates/nacre-core` (feature `test-signer`) by path, as PAdES or the TSP client would. Each transcript quotes its script whole. The OpenSSL signatures of criterion 3 were made fresh during the walk with throw-away keys in the scratch folder, in addition to the committed fixtures, so the reader is judged on files its author did not choose.

## Coverage
| Criterion or item | Reached | Result |
| --- | --- | --- |
| 1. Digest + `Signer` → detached DER `SignedData` with `content-type`, `message-digest`, `signing-certificate-v2`; `openssl cms -verify -binary -content <file>` accepts it | yes | as expected: `sign_detached` writes 839 bytes, no `eContent`, exactly the three signed attributes, and its own `verify` passes. `openssl cms -verify -binary -inform DER -content … -CAfile cert.pem -purpose any -cades` prints `CAdES Verification successful` (exit 0), and `-noverify` exits 0 too; one changed content byte makes OpenSSL exit 4 (`c1-sign-openssl.txt`, `c1-sign-openssl-error.txt`). Without `-purpose any` OpenSSL refuses with `unsuitable certificate purpose`: the s01 test signer's certificate carries `keyCertSign, cRLSign` only, as the plan states — a property of s01's fixture, not of the CMS. Bad input: digests of 29, 20, 64 and 0 bytes are refused with `digest length is N bytes, the algorithm produces 32` |
| 2. A profile forbids an attribute; under PAdES `signing-time` is never written | yes | as expected: `Profile::PADES` without a time writes no `signing-time`; asked for one it returns `ForbiddenAttribute(1.2.840.113549.1.9.5)` and writes nothing; `Profile::CMS` writes it; a caller-built `Profile::forbidding(&[signing-certificate-v2])` refuses that attribute (`c2-profile.txt`, `c2-profile-error.txt`). The message names the attribute only by dotted OID — finding 1 |
| 3. An OpenSSL `SignedData` is read and verified; one changed byte of content or signed attributes fails | yes | as expected: fresh OpenSSL signatures (P-256 CAdES detached, RSA-2048 detached, RSA attached) and the three committed fixtures all read and verify; the encapsulated content is exposed (46 and 80 bytes). One content byte changed → `MessageDigestMismatch` (detached EC and RSA, and inside an attached `eContent`); one byte of the `signingTime` value flipped → `SignatureInvalid` for EC and RSA, and OpenSSL fails the same file (`c3-read-verify-openssl.txt`). Bad input: no content for a detached file → `ContentMissing`; content given for an attached one → `ContentAmbiguous`; PEM, a bare certificate, a CMS `Data` → DER or `NotSignedData` errors; two signers → `SignerCount(2)`; P-384/SHA-384 and RSA-PSS → `UnsupportedAlgorithm`; `-noattr` → `MissingSignedAttributes` (`c3-read-verify-openssl-error.txt`) |
| 4. Hostile DER (truncated, wrong lengths, deep nesting) → error, never a panic; a fuzz target exists in `crates/nacre-cms/fuzz/` | yes | as expected: empty input, one byte, text, all 1099 strict prefixes of an OpenSSL file, a 2 GiB length claim, a 9-octet length, trailing bytes, 100 000 nested indefinite-length headers, 50 000 nested `SEQUENCE`/`[0]`/`SET` with canonical lengths, a 64 MiB input: each an `Err` within microseconds, no panic. A 50 000-deep blob placed in the open fields (a signed attribute value, the certificate, an unsigned attribute) gives `SignatureInvalid`, a certificate error, and an opaque unsigned attribute that does not touch the signature (`c4-hostile-error.txt`). `cargo +nightly fuzz list` names `signed_data`; a 60 s run seeded with the 11 corpus files did 804 046 runs with no crash (`c4-fuzz-target.txt`) |
| 5. `docs/security/attacks/cms.md` lists the known attacks, each with its rejected corpus case | yes | as expected: the file lists the four attacks the story names (algorithm confusion, signed attributes absent or duplicated, inconsistent `message-digest`, `SignerIdentifier` naming no certificate) plus `message-digest` absent, certificate substitution and content-type mismatch, eight rows. Each of the eight corpus files is rejected with the error its row gives; the generator reproduces all eight byte for byte; `tests/attacks.rs` passes 8/8 (`c5-attacks.txt`). Through `verify_detached_digest` (the ByteRange path) each file meets the same rule, whatever digest is given (`c5-attacks-error.txt`). For comparison, OpenSSL `-noverify` accepts four of them (`alg-confusion`, `cert-substitution`, `content-type-mismatch`, `signed-attrs-absent`) |

## Findings
Status rule: **verified** means the steps were replayed and reproduced the defect, and an evidence file holds it; **probable** means it was seen once, or no evidence file could be kept; **unverified** means it is suspected from what the surface showed, not seen happening.

### Finding 1 — Errors name attributes and algorithms only by their dotted OID
Severity: minor
Status: verified
Steps to reproduce:
1. In a crate depending on `nacre-cms` and `nacre-core` (`test-signer`), call `sign_detached(&digest, &signer, &Profile::PADES, Some(time))` and print the error's `Display`.
2. Verify `tests/corpus/attacks/message-digest-absent.der` or an OpenSSL `-md sha384` signature with `SignedData::verify` and print the error's `Display`.
Capture: docs/qa/s03-cms-signed-data/c2-profile.txt, c2-profile-error.txt (replay), c5-attacks.txt, c3-read-verify-openssl-error.txt
Expected: an error that says what was wrong in words its user reads (the driver counts a message that does not say what was wrong as a finding).
Observed: `the profile forbids attribute 1.2.840.113549.1.9.5`, `signed attribute 1.2.840.113549.1.9.4 is missing`, `signed attribute 1.2.840.113549.1.9.4 appears more than once`, `unsupported algorithm 2.16.840.1.101.3.4.2.2`. Each says what kind of fault it is and is exact, but the developer has to look up the OID to learn that it means `signingTime`, `messageDigest` or SHA-384. The variants (`ForbiddenAttribute(oid)`, …) carry the OID for code that matches on it, so only the wording is in question.

## Not seen
- Criterion 1 and criterion 4 as run by `.github/workflows/ci.yml` (the OpenSSL test and the 60 s fuzz job on GitHub Actions) — a remote service the driver did not start; both were replayed locally instead.
- Behaviour on real signing hardware or a real PKI chain — the walk used `TestSigner` and self-signed throw-away certificates only; trust in the chain is s16's.

Tree: b345abaa17db7be965ab343d2c63b3207b1fbfe1
QA status: complete
