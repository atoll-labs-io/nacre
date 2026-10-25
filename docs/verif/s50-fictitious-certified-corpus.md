# Verification — s50-fictitious-certified-corpus

[Story](../stories.md) · [Plan](../plans/s50-fictitious-certified-corpus.md)

Tree: 2a3eb1bd9da225e85cfe2068cb11fcc429175f5c

## Checks
| Check | Command | Note |
| --- | --- | --- |
| Unit suite | `cargo test --workspace` | |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | |
| End to end | — | no such command in this project |
| Build | — | deferred to ship |

## AC4 scan (task 7)
- `pdfinfo` over `git ls-files '*.pdf'`: Author only on two files, `SE:W:CAR:MP` (IRS W-9 office code) and `Mary` (W3C sample `word-pdfmaker-linearized.pdf`, left as is, open question for the lead). Titles and Creators are tool names or fictitious/public document titles.
- `pdfinfo -meta` `dc:creator`: same two values.
- `pdfsig` signer names: `Nacre test signer`, `Nacre chain signer`, `Nacre third-party signer` (new), pyHanko's `Alice` and `Lord Testerino`; 11 files have no signer certificate (hostile or timestamp-only). The Nowina `good-user` is gone with the old file.
- `openssl x509 -subject` over committed `*.der`/`*.pem` that are certificates: only `Nacre ...` subjects (`O=Nacre tests,C=FR`); the other `*.der` files are CMS, CRL or OCSP data, not certificates.
- Case-insensitive `git grep` of the old surname: empty after scrubbing it from this story's own research and plan. No tracked file has sha256 `17c74d6c…`.
- Campaign: 0 `≠` row in `campaign-dss.md`; every `≠` row of `campaign-strict.md` carries its switches; both new files on `Certification`, count 1, `=`; no `certified-dss` in the reports.

## Not proven here
End to end and build are deferred to ship. The QA stage (surface `endpoint`) re-walks the endpoint. `qpdf_check_is_clean` is `#[ignore]`d and needs `qpdf` (not installed). Open question: `/Author Mary` in the W3C sample.

Verification status: complete

## Runs
Written by `po-run`, one row per launch. Never edit, reorder or delete a row.

| Check | Command | Exit | Tree | Time (UTC) |
| --- | --- | --- | --- | --- |
| Unit suite | `cargo test --workspace` | 0 | ded9aad3fa895deb483bf7b4c0650c7084ffd2de | 2026-10-25T20:01:36Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 9de5a47414a8704e9c37fe09b2d5cb637cf5d4e5 | 2026-10-25T20:01:48Z |
