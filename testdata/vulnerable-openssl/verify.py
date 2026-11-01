"""Verify the real binary-to-package-to-CVE path, using the live OSV API."""

from pathlib import Path
import subprocess
import sys

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from scan.scan_binary import open_binary


source_package, source_version = subprocess.check_output(
    ["dpkg-query", "-W", "-f=${source:Package}\t${source:Version}", "libssl3"],
    text=True,
).split()
if (source_package, source_version) != ("openssl", "3.0.8-1"):
    raise SystemExit(f"FAIL: unexpected library package: {source_package} {source_version}")

response = requests.post(
    "https://api.osv.dev/v1/query",
    json={
        "package": {"name": source_package, "ecosystem": "Debian:12"},
        "version": source_version,
    },
    timeout=30,
)
response.raise_for_status()
data = response.json()
advisories = data.get("vulns", [])
while data.get("next_page_token"):
    response = requests.post(
        "https://api.osv.dev/v1/query",
        json={
            "package": {"name": source_package, "ecosystem": "Debian:12"},
            "version": source_version,
            "page_token": data["next_page_token"],
        },
        timeout=30,
    )
    response.raise_for_status()
    data = response.json()
    advisories.extend(data.get("vulns", []))

expected = next(
    (v for v in advisories if v["id"] == "DEBIAN-CVE-2023-2650"), None
)
if expected is None:
    raise SystemExit("FAIL: live OSV response did not contain the expected advisory")
print(f"PASS: OSV returned {len(advisories)} advisories for openssl {source_version}")
print(f"Expected advisory: {expected['id']}")
print(f"Upstream CVE IDs: {expected.get('upstream', [])}")

# --raw-only verifies the fixture independently of BinSentry's CVE parser.
if "--raw-only" in sys.argv:
    raise SystemExit(0)

report = open_binary(Path("/fixture/openssl-probe"))
library = report.dependencies.get("libcrypto.so.3")
if not isinstance(library, dict):
    raise SystemExit(f"FAIL: libcrypto lookup failed: {library!r}")

cves = sorted({v.cve_id for v in library["vulnerabilities"]})
print(f"Library: {library['resolved_path']}")
print(f"Source version: {library['version']}")
print(f"CVEs: {', '.join(cves) or '(none)'}")
if "CVE-2023-2650" not in cves:
    raise SystemExit(
        "FAIL: BinSentry did not extract CVE-2023-2650. "
        "Debian records put this CVE in upstream; check that field as well as id/aliases."
    )
print("PASS: BinSentry detected the expected CVE for libcrypto.so.3")
