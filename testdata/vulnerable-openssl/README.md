# Known-vulnerable OpenSSL fixture

This fixture builds a Linux x86-64 ELF executable linked to `libcrypto.so.3`
from Debian's `openssl` source package version `3.0.8-1`, in `Debian:12`.
It only prints the OpenSSL version; it does not trigger an exploit.

Expected finding: **CVE-2023-2650**. The OSV record lists the Debian fix as
`3.0.9-1`: https://osv.dev/vulnerability/DEBIAN-CVE-2023-2650.
Other CVEs may also be returned for this old package.

Run these commands from the repository root:

```sh
docker build --platform linux/amd64 \
  -f testdata/vulnerable-openssl/Dockerfile \
  -t binsentry-vulnerable-openssl .

docker run --rm --platform linux/amd64 \
  --mount "type=bind,source=$(pwd),target=/app,readonly" \
  binsentry-vulnerable-openssl
```

To assert the expected CVE using the current BinSentry implementation and
the live OSV API:

```sh
docker run --rm --platform linux/amd64 \
  --mount "type=bind,source=$(pwd),target=/app,readonly" \
  --entrypoint python3 binsentry-vulnerable-openssl \
  testdata/vulnerable-openssl/verify.py
```

The verifier first checks the installed source package version and the raw
OSV response, then asserts BinSentry's extracted finding. Add `--raw-only`
after `verify.py` to verify the fixture without testing BinSentry's parser.

During initial verification, the raw API returned 62 advisories including
`DEBIAN-CVE-2023-2650`, with `upstream: ["CVE-2023-2650"]` and no aliases.
The current BinSentry implementation checks only `id` and `aliases`, so its
end-to-end check fails until it also extracts CVE identifiers from `upstream`:

```python
for identifier in [
    vuln["id"],
    *vuln.get("aliases", []),
    *vuln.get("upstream", []),
]:
```

This is a regression fixture: a failure from the scanner assertion must not be
interpreted as a clean scan. BinSentry may also print a separate library lookup
error for libc because it resolves `/lib` symlinks before calling `dpkg -S`;
the fixture assertion specifically checks `libcrypto.so.3`.

The executable is `/fixture/openssl-probe` inside the image. A copy can be
exported for inspecting its ELF metadata:

```sh
docker run --rm --platform linux/amd64 --entrypoint cat \
  binsentry-vulnerable-openssl /fixture/openssl-probe \
  > testdata/vulnerable-openssl/openssl-probe-linux-x86_64
```

Scan inside this fixture container. BinSentry resolves dependencies using
`ldconfig` and `dpkg` in the scanning environment; scanning the exported binary
in your usual Debian 13 image would check that image's libraries instead.
The container also provides Python dependencies via Debian packages, including
`requests`, which is currently absent from the main `requirements.txt`.

Keep the deliberately outdated library in this disposable test image only.
The scan needs internet access to query OSV; no ports need to be published.
