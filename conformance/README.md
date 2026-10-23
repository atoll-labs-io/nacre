# Conformance bench

A replayable bench that judges Nacre's signatures with a local, pinned DSS (ADR-0007), against
a test PKI with its own TSA, OCSP responder and CRL server (ADR-0011).

| Folder | What it holds |
| --- | --- |
| `dss/` | The DSS 6.5.1 image and its configuration |
| `pki/` | The test PKI's generator, and the image serving its CRLs, TSA and OCSP; the PKI itself is generated in `pki/out/` at every start |
| `reference/` | A fictitious reference document, signed with the fresh PKI into `reference/out/` at every start |

## Ports

Everything runs on the host network and listens on `127.0.0.1` only, so the URLs written in
the test certificates work both for DSS inside its container and for tests on the host.

| Port | Service |
| --- | --- |
| `18080` | DSS: web application and REST services (`/services/rest/validation/validateSignature`) |
| `18081` | `GET /crl/root.crl`, `GET /crl/intermediate.crl`, `POST /cgi-bin/tsa` and `POST /cgi-bin/tsa2` (RFC 3161, two distinct TSAs), `POST /cgi-bin/ocsp` |

## Run

From the repository root:

```sh
podman compose -f conformance/compose.yaml down
podman compose -f conformance/compose.yaml --profile init run --rm pki-init
podman compose -f conformance/compose.yaml up -d
sh conformance/check.sh
sh conformance/reference/generate.sh
```

No private key is committed, test keys included. `pki-init` generates a fresh PKI in
`conformance/pki/out/` (ignored by git), every key and serial new; it runs on its own before
`up` because DSS reads its anchors once, at start, and podman-compose does not wait for a
one-shot service to finish. Hence the `down` first: a DSS still running from the previous
start would keep the previous anchors and judge every new signature `INDETERMINATE`.

`check.sh` waits up to 300 s for DSS and the CRL server, then checks with OpenSSL that the
chain verifies, that the CRL lists the revoked certificate, that each TSA returns a verifiable
token signed by its own certificate and that OCSP says `good` for `signer` and `revoked` for `revoked`. It ends with
`bench ready`, or stops at the first failure. `reference/generate.sh` then signs
`reference/unsigned.pdf` with the new `signer` and `revoked` keys into `reference/out/`.

Then the conformance tests:

```sh
cargo test --workspace --all-features -- --ignored
```

They are `#[ignore = "conformance"]`, so `cargo test --workspace` skips them. Each answer of
DSS is kept under `target/conformance/<name>.json` with the ETSI XML report as `<name>.xml`.

Stop with `podman compose -f conformance/compose.yaml down`.

## Environment

| Variable | Default | Use |
| --- | --- | --- |
| `NACRE_DSS_URL` | `http://127.0.0.1:18080` | The DSS the tests and `check.sh` call; only `http://127.0.0.1:<port>` or `http://localhost:<port>` is accepted |
| `CARGO_TARGET_DIR` | `target` | Where `conformance/` reports are written |
| `NACRE_SOFTHSM_MODULE` | set by CI to `/usr/lib/softhsm/libsofthsm2.so` | The SoftHSM module for the PKCS#11 conformance tests of later stories |

`.github/workflows/conformance.yml` runs the same steps on every pull request, on `main` and
once a day, and uploads `target/conformance/` as an artefact.
