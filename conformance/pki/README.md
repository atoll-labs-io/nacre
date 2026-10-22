# Bench PKI, TSA, OCSP responder and CRL server

**Test material only, and never committed.** `generate.sh` writes a fresh PKI into `out/`,
which git ignores, at every bench start: no private key enters the repository, test keys
included. Never trust these certificates anywhere else, and never sign a real document with
them.

The PKI and its responders are plain OpenSSL (ADR-0011).

## Contents

Committed: `generate.sh`, `openssl.cnf`, `serve.sh`, `cgi-bin/`, `Containerfile`, this README.
Generated in `out/` by `generate.sh`:

| File | What it is |
| --- | --- |
| `root.{key,cert}.pem` | Self-signed root CA, the bench's only trust anchor |
| `intermediate.{key,cert}.pem` | CA issued by the root; CRL distribution point `http://127.0.0.1:18081/crl/root.crl` |
| `signer.{key,cert}.pem` | Signing certificate (`digitalSignature`, `nonRepudiation`) |
| `tsa.{key,cert}.pem` | TSA certificate (critical `extendedKeyUsage` `timeStamping`) |
| `revoked.{key,cert}.pem` | Same profile as `signer`, revoked (`keyCompromise`) |
| `root.crl`, `intermediate.crl` | DER CRLs; the intermediate's lists `revoked`; `nextUpdate` 7300 days after generation |
| `*.index`, `*.serial`, `*.crlnumber`, `tsa.serial` | `openssl ca` and `openssl ts` state; the OCSP responder reads `intermediate.index` |
| `anchors.p12` | PKCS#12 trust store for DSS: the root only, password `nacre-anchors` |
| `openssl.cnf` | A copy of the configuration of the CAs, the extensions and the TSA, read by the responders |

All keys are ECDSA P-256, and they change, with every serial, on each run: nothing may
depend on a fixed key, serial or fingerprint. Every certificate is valid from `2026-01-01T00:00:00Z` to
`2046-01-01T00:00:00Z`. Leaf certificates carry the CRL distribution point
`http://127.0.0.1:18081/crl/intermediate.crl` and the OCSP responder
`http://127.0.0.1:18081/cgi-bin/ocsp`.

## Services

`serve.sh`, the entrypoint of `Containerfile`'s image, copies the read-only `/pki` mount
(`out/`) to a writable directory and runs `busybox httpd` on `127.0.0.1:18081`:

- `GET /crl/root.crl`, `GET /crl/intermediate.crl`: the CRLs;
- `POST /cgi-bin/tsa`: RFC 3161 time-stamping (`application/timestamp-query` in,
  `application/timestamp-reply` out), signed by `tsa`, policy `2.999.1.1`;
- `POST /cgi-bin/ocsp`: OCSP for certificates issued by the intermediate, signed by the
  intermediate, `nextUpdate` five minutes ahead, nonce echoed.

## Generating

The bench does it (`conformance/README.md`): the compose service `pki-init` runs
`generate.sh` in this folder's image, which has OpenSSL 3.5:

```sh
podman compose -f conformance/compose.yaml --profile init run --rm pki-init
```

On the host it needs OpenSSL 3.2 or later (for `-jdktrust`):

```sh
sh conformance/pki/generate.sh
```

Each run replaces every key and certificate. Afterwards restart DSS so it loads the new
`out/anchors.p12`, and sign the reference PDFs again (`conformance/reference/generate.sh`).
