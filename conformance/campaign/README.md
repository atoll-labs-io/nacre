# Campaign

Nacre against DSS 6.5.1 on every corpus (story s18, AC4 to AC6): the test
`campaign` of `crates/nacre-validate/tests/campaign.rs`, `#[ignore = "conformance"]`.

## What it judges

- every `*.pdf` under `crates/nacre-validate/tests/corpus/`, `crates/nacre-pdf/tests/corpus/hostile/`,
  `crates/nacre-pdf/tests/corpus/real/` and, once it exists, `conformance/corpus/`;
- the bench cases forged at run time, one per row of the spike tables of
  `docs/research/s18-validate-level.md`, the `x` cases aside (story s47). The bench regenerates its keys
  at every start, so they are never committed. Root-issued data on a forged CA is dated after the
  bench's `root.crl`, which DSS also applies to that CA.

Each case goes to DSS once. Nacre judges it with the bench root as anchor, the current time and the
bench revocation source, under `ValidationPolicy::dss()` and under `ValidationPolicy::strict()`.
Each signature, matched to DSS's by field name, gives its indication, sub-indication and level, and each
file its signature count. DSS answering an HTTP error status and Nacre returning `Err` agree; a
request that gets no answer, or an answer that is not a DSS report, fails the campaign. The
campaign checks first that DSS answers at `NACRE_DSS_URL`, and stops at once, naming the URL, when
it does not.

- Under `dss()`, any difference fails the campaign.
- Under `strict()`, a difference is explained by the smallest set of switches that, turned off from
  `strict()`, gives DSS's verdict on the file: single switches first, then pairs, then triples. A
  difference no such set explains fails the campaign.

## Run

Start the bench as `conformance/README.md` says, then, from the repository root:

```sh
sh conformance/campaign/run.sh
```

It runs `cargo test -p nacre-validate --all-features --test campaign -- --ignored`, then copies into
`reports/`:

| File | What it holds |
| --- | --- |
| `campaign-dss.md` | each signature under `dss()`: DSS's verdict, Nacre's, `=` or `≠`, and each file's count |
| `campaign-strict.md` | the same under `strict()`, each differing row with the switches that explain it |
| `campaign-<case>.xml` | DSS's ETSI validation report of each case |
| `campaign-<case>.error.txt` | the HTTP status and body of each case DSS answered with an error |

Stop the bench with `podman compose -f conformance/compose.yaml down`.
