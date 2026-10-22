# DSS, the conformance judge

DSS runs here in a container, pinned to `esig/dss-demonstrations` **6.5.1** (the source
archive is checked by SHA-256 in `Containerfile`), and is called through its REST validation
API (ADR-0007). **Never the Commission's online demo**, not even for a fictitious document.

The `Containerfile` is copied from Patelle's validator (same base images, same version, same
checksum), with Tomcat rewritten to listen on `127.0.0.1:18080` only and its shutdown port
closed, because the bench runs on the host network.

## Build

```sh
podman build -t localhost/nacre-dss:6.5.1 conformance/dss
```

The Maven and JDK stage stays in the build; the final image is Tomcat on a JRE (about
880 MB). Count about ten minutes for a first build. `podman compose` builds it too when the
image is missing.

## Anchors

Trust anchors are server configuration: DSS 6.5.1's REST validation takes no anchor per
request. `dss-custom.properties`, copied into the image, makes DSS read the PKCS#12 store
`nacre-anchors.p12`, password `nacre-anchors`, from Tomcat's `lib/`. The bench mounts
`conformance/pki/out/anchors.p12`, generated at bench start, there read-only; it holds the
bench's test root only. DSS reads the store at start: restart the container after changing it.

`dss-custom.properties` also turns off the download of the EU trusted lists
(`cron.tl.loader.enable = false`): the bench trusts its own root and nothing else. No
validation rule is changed, and the default policy ("QES AES/QC AES TL based") stays.

## Run

Through the bench, `conformance/README.md`. Alone:

```sh
podman run -d --name nacre-dss --network host \
  -v "$PWD/conformance/pki/out/anchors.p12":/usr/local/tomcat/lib/nacre-anchors.p12:ro \
  localhost/nacre-dss:6.5.1
```

Ready when `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/` answers `200`
(about thirty seconds).
