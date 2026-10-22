# Reference documents

Fictitious documents for the conformance bench. Nothing here is a real document.

| File | Source |
| --- | --- |
| `unsigned.pdf` | Written by hand for the bench: one page of fictitious text (committed) |
| `generate.sh` | Signs `unsigned.pdf` with the bench's fresh keys (committed) |
| `out/pades-baseline-b.pdf` | `unsigned.pdf` signed `PAdES-BASELINE-B` with the bench's `signer` key, laid out by DSS 6.5.1; generated, never committed |
| `out/pades-baseline-b-revoked.pdf` | The same, signed with the bench's `revoked` key after its revocation; generated, never committed |

The keys are generated at every bench start (`conformance/pki/README.md`), so the signed PDFs
are produced again each time, after `check.sh`:

```sh
sh conformance/reference/generate.sh
```

DSS only builds the PDF signature dictionary and the CMS around a signature value; the value
itself is computed by `openssl dgst -sha256 -sign` with the bench key.

Verdicts DSS 6.5.1 gives them on the bench (observed on 2026-10-22; asserted by
`crates/nacre-conformance/tests/dss_reference.rs`):

| File | Indication | Sub-indication | `SignatureFormat` |
| --- | --- | --- | --- |
| `out/pades-baseline-b.pdf` | `TOTAL_PASSED` | — | `PAdES-BASELINE-B` |
| `out/pades-baseline-b-revoked.pdf` | `INDETERMINATE` | `REVOKED_NO_POE` | `PAdES-BASELINE-B` |

## Recording DSS's answers

`sh conformance/reference/generate.sh --record` also posts each signed PDF to DSS's
validation and overwrites the parser fixtures of `crates/nacre-conformance/tests/corpus/`.
Do it only when the DSS version moves; the fixtures hold public certificates, never a key.
