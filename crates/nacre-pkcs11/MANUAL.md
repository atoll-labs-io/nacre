# Manual run on a YubiKey

This run is never automated: it needs a person, a YubiKey plugged in and its PIV PIN typed
by hand. It proves that `Pkcs11Signer` signs with the key in PIV slot 9c through Yubico's
`libykcs11`, and that DSS judges the PDF `PAdES-BASELINE-B`. SoftHSM covers everything else
in CI (`tests/softhsm.rs`, `tests/conformance.rs`).

**Never type a wrong PIN on the real key.** The PIV PIN allows few tries before it locks,
and the signer never retries a refused PIN, but each mistake still burns one try. The
wrong-PIN behaviour is tested on SoftHSM only.

## Prerequisites

- `libykcs11` at `/usr/lib/libykcs11.so` (package `yubico-piv-tool`).
- `pcscd` running: `systemctl status pcscd.socket`.
- `ykman` (YubiKey Manager).
- The conformance bench up, as `conformance/README.md` says (`down`, `pki-init`, `up`,
  `check.sh`). Route B changes one step between `pki-init` and `up`.

Read the state of the key first, without changing anything:

```sh
ykman info        # model and firmware, for the results table
ykman piv info    # whether slot 9c holds a key and a certificate, and its PIN policy
```

Then pick a route. If slot 9c holds a key you use (Patelle's signing key, for instance),
take route B: route A destroys the key in 9c.

## Route A: slot 9c free or disposable

A fresh key in 9c with a fictitious subject, certified by the bench's intermediate CA. The
certificate is valid until the next bench start, which replaces the whole PKI.

```sh
ykman piv keys generate --algorithm eccp256 9c 9c.pub.pem
ykman piv certificates request --subject "CN=Nacre Manual Test,O=Nacre tests,C=FR" \
  9c 9c.pub.pem 9c.csr

export PKI_DIR="$PWD/conformance/pki/out"
mkdir -p "$PKI_DIR/.newcerts"
openssl ca -batch -notext -config conformance/pki/out/openssl.cnf -name intermediate_ca \
  -extensions v3_signer -in 9c.csr -out 9c.cert.pem

ykman piv certificates import 9c 9c.cert.pem
```

`ykman` asks for the management key and the PIN. If `openssl ca` cannot write
`intermediate.index`, the bench's container wrote `out/` as another user: run `pki-init`
again rootless, or fix the ownership of `out/`.

The issuer to pass below is `conformance/pki/out/intermediate.cert.pem`.

## Route B: slot 9c holds a key in use

Keep the key and its certificate, and make DSS trust that certificate. Export it once:

```sh
ykman piv certificates export 9c 9c.cert.pem
```

After `pki-init` and before `up`, rebuild DSS's trust store with the bench root and the 9c
certificate (DSS reads it once, at start):

```sh
cat conformance/pki/out/root.cert.pem 9c.cert.pem > anchors.pem
openssl pkcs12 -export -nokeys -in anchors.pem -jdktrust anyExtendedKeyUsage \
  -passout pass:nacre-anchors -out conformance/pki/out/anchors.p12
rm anchors.pem
```

Then `up` and `check.sh` as usual. If the 9c certificate is self-signed, pass `-` as the
issuer below. If a CA of yours issued it, put that CA's certificate in `anchors.pem` instead
of `9c.cert.pem`, and pass it as the issuer.

## Signing

`libykcs11` gives the 9c key and its certificate the PKCS#11 id `02`. The PIN is read from
standard input; `read -s` keeps it off the screen and `printf`, a shell builtin, keeps it
out of the process list:

```sh
read -rsp 'PIV PIN: ' PIN; echo
printf '%s\n' "$PIN" | cargo run -p nacre-pkcs11 --example sign_pdf -- \
  /usr/lib/libykcs11.so 02 <issuer.pem or -> \
  conformance/reference/unsigned.pdf target/s13-yubikey.pdf
unset PIN
```

Touch the key if its touch policy asks for it. The example prints DSS's indication,
sub-indication and format, and the path of the ETSI XML report,
`target/conformance/s13-yubikey-b.xml`.

## Results

| Field | Value |
| --- | --- |
| Date | not run |
| YubiKey model and firmware (`ykman info`) | not run |
| `libykcs11` version | not run |
| Route (A or B) | not run |
| 9c PIN policy (`ykman piv info`) | not run |
| Signed, or the error | not run |
| DSS indication / sub-indication / format | not run |
| Report file | not run |

Only for route A, whose certificate is fictitious, copy the XML report to
`crates/nacre-pkcs11/manual/s13-yubikey-b.xml` and commit it with this table. Never commit
the report of route B: it carries a real name.
