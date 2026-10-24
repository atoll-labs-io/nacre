# QA — s18-validate-level

[Story](../../stories.md) · [Plan](../../plans/s18-validate-level.md)

Scope: the story's surface, what `git diff main...story/s18-validate-level` touches on it, and the acceptance criteria its user can observe through it; nothing else was checked.
Driver: scenarios.md of qa-drivers — surface endpoint, platform lib, cli (only the `endpoint`/`lib` row matches)
Evidence: transcripts
Tool: Bash — a scratch crate calling the public interface of `nacre-validate`, and `sh conformance/campaign/run.sh`, in a temporary copy of the tracked files
Origin: — (the driver serves nothing; the conformance bench was started from the copy on `127.0.0.1:18080` and `:18081`, the only addresses reached, and stopped at the end; `patelle-dss` was not touched)

This walk replaces the one on tree `3cae3e88…`: it reruns every criterion on the code of commit `07bcd80` ("address review findings"), on a freshly started bench.

## Coverage
| Criterion or item | Reached | Result |
| --- | --- | --- |
| AC1 — s06/s08/s11/s12 shapes give `PAdES-BASELINE-B`, `-T`, `-LT`, `-LTA` with `TOTAL_PASSED`, both policies | yes | as expected (`ac1-baseline-levels.txt`: campaign rows l01–l04 under `dss()` and `strict()`; the bench-signed reference file `TOTAL_PASSED` / B through `validate_with_policy` with the bench revocation source, its revoked twin `REVOKED_NO_POE`). Invalid inputs (empty, not a PDF, truncated, PEM or garbage anchor) give a readable `Err` of kind `InvalidInput` (`ac1-baseline-levels-error.txt`) |
| AC2 — structural level as DSS 6.5.1 (form from `/SubFilter`, BES, ESS, T, LT, LTA, CMS data leaves B) | yes | as expected (`ac2-structural-level.txt`: l05/l16/p05 BES, l36 no level, n09 ESS v1 B, l06/l35 CMS CRLs stay B/T, l14/t1/t2 PKCS7, r1–r8 and l30 T/LT/LTA, all `=`; committed `signed-lta-pyhanko.pdf` LTA and `signed-twice-pyhanko.pdf` PKCS7-T with no chain; `subfilter-unsupported.pdf` no level) |
| AC3 — a valid document timestamp is a proof of existence; an invalid one proves nothing and leaves the level | yes | as expected (`ac3-document-timestamp-poe.txt`: n13 and k4 `TOTAL_PASSED`, n14 `REVOKED_NO_POE` at the same level LT, l10 and l29 keep LTA) |
| AC4 — the campaign under `dss()`: 100 % identical to DSS on every corpus, one difference fails it | yes | as expected: test `campaign ... ok` in 136 s, "257 cases, 0 differ from DSS under `dss()`" (`ac4-campaign-dss.txt`; `conformance/corpus/` absent until s19). The five `error = error` cases now rest on an HTTP 500 DSS itself sent, kept with its body (`ac6-dss-reports-kept.txt`). Wrong inputs (`ac4-campaign-dss-error.txt`): DSS not started → fails in 0 s with "DSS does not answer at http://127.0.0.1:1 … start the bench"; a URL off the machine → fails at once, naming the allowed form; DSS stopped mid-run → fails with "<case>: no DSS verdict: DSS request failed"; each time exit 101 and the kept reports untouched |
| AC5 — the campaign under `strict()`: each difference with the strict rule that explains it | yes | as expected: "94 explained by switches under `strict()`, 0 unexplained"; 121 `≠` rows, none with an empty explanation cell (`ac5-campaign-strict.txt`) |
| AC6 — DSS's XML reports of each campaign are kept | yes | as expected: 259 files kept, 252 XML + 5 `campaign-<case>.error.txt` (HTTP status and DSS's body) + the two tables, so every one of the 257 cases has DSS's answer; same file names as the set committed on the branch (`ac6-dss-reports-kept.txt`) |
| Previous findings 1 (DSS failure counted as agreement, nothing kept), 2 (silent hang with DSS unreachable), 3 (explanation on the `(count)` row) | yes | no longer reproduced on this tree, by the same steps (AC4, AC5, AC6 rows above) |

## Findings
Status rule: **verified** means the steps were replayed and reproduced the defect, and an evidence file holds it; **probable** means it was seen once, or no evidence file could be kept; **unverified** means it is suspected from what the surface showed, not seen happening.

None.

## Not seen
- AC4 on `conformance/corpus/` — the folder does not exist before s19; the campaign skips it as its README says.
- AC4/AC5 on DSS's verdict for files signed by other tools than Nacre, pyHanko aside — beyond the corpus the story names (s19).
- Behaviour under real load or on a real network (public TSA, online CRL/OCSP) — the driver cannot show it, and the story forbids it.
- The `.github/workflows/conformance.yml` run of the campaign in CI — a dependency the driver did not start.
- A DSS that answers an HTTP error to the first request of a case and something else to the replay in `keep_error` — the bench gives no way to make DSS change its answer between two identical requests.

Tree: 943c490d323951617de8f1346550831a0e438773
QA status: complete
