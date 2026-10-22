# Recorded DSS responses

Raw JSON answers of DSS 6.5.1's `POST /services/rest/validation/validateSignature`, recorded
on 2026-10-22 against the conformance bench by `conformance/reference/generate.sh --record`.
They hold only public certificates of a fictitious test PKI (`conformance/pki/`), since
regenerated, and fictitious documents; never a private key.

| File | Document validated | Verdict |
| --- | --- | --- |
| `dss-6.5.1-pades-baseline-b.json` | `conformance/reference/out/pades-baseline-b.pdf` | `TOTAL_PASSED`, `PAdES-BASELINE-B` |
| `dss-6.5.1-pades-baseline-b-revoked.json` | `conformance/reference/out/pades-baseline-b-revoked.pdf` | `INDETERMINATE` / `REVOKED_NO_POE`, `PAdES-BASELINE-B` |

The offline tests of `tests/report.rs` read them, so the report reader is checked against what
the pinned DSS really returns. Record them again when the DSS version moves.
