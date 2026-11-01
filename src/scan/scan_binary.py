from elftools.elf.elffile import ELFFile
from pathlib import Path
from .results import BinaryReport, Vulnerability
from elftools.elf.dynamic import DynamicSection, DynamicTag
import subprocess
import requests
import platform

OSV_QUERY="https://api.osv.dev/v1/query"
OSV_VULN="https://api.osv.dev/v1/vulns"

def _get_osv_ecosystem() -> str:
    info = platform.freedesktop_os_release()
    distro = info["ID"]
    version = info.get("VERSION_ID")

    if not version:
        raise ValueError(f"Missing VERSION_ID for {distro}")

    if distro == "debian":
        return f"Debian:{version}"

    if distro == "alpine":
        release = ".".join(version.split(".")[:2])
        return f"Alpine:v{release}"

    if distro == "ubuntu":
        is_lts = "LTS" in info.get("VERSION", "")
        suffix = ":LTS" if is_lts else ""
        return f"Ubuntu:{version}{suffix}"

    raise ValueError(f"Unsupported OSV distribution: {distro}")

def _check_osv(package: str, version: str):
    ecosystem = _get_osv_ecosystem()   
    payload = {
        "package": {
            "name": package,
            "ecosystem": ecosystem
        },
        "version": version
    }
    response = requests.post(
        url=OSV_QUERY,
        json=payload,
        timeout=15
    )
    response.raise_for_status()
    response = response.json()
    vulns = response.get("vulns", [])
    confirmed_vulns = []
    checked_cwe = set()
    for vuln in vulns:
        for identifier in [vuln["id"], *vuln.get("aliases", []), *vuln.get("upstream", [])]: 
            if identifier.startswith("CVE-") and identifier not in checked_cwe:
                cve_id = identifier
                for affected in vuln.get("affected", []):
                    identity = affected.get("package", {})
                    if identity.get("name") == package and identity.get("ecosystem") == ecosystem:
                        confirmed_vulns.append(
                            Vulnerability(
                                cve_id=cve_id,
                                severity=affected.get("severity") or vuln.get("severity") or [],
                                description=vuln.get("summary", "")
                            )
                        )
                        checked_cwe.add(identifier)
                        break
    return confirmed_vulns

def _check_library(tag: DynamicTag, binary_path: Path):
    name = tag.needed
    output = subprocess.run(["ldconfig", "-p"],
                            capture_output=True,
                            text=True)
    ld_config_line = (next(result for result in output.stdout.split("\n") 
                           if name in result))
    library_path = Path(ld_config_line.split()[-1]).resolve()
    output_package = subprocess.run(["dpkg", "-S", library_path],
                            capture_output=True,
                            text=True)
    package = output_package.stdout.split()[0][:-1]
    version_check = subprocess.run([r"dpkg-query", "-W", "-f=${source:Package}\t${source:Version}\n", package],
                                   capture_output=True,
                                   text=True)
    source_package, version = version_check.stdout.split()
    return {
        "resolved_path": str(library_path),
        "version": version,
        "vulnerabilities": _check_osv(source_package, version)
    }


def open_binary(binary_path: Path):
    with open(binary_path, 'rb') as f:
        elf = ELFFile(f)
        file_type = elf.header.e_type
        machine_arch = elf.get_machine_arch()
        dwarf_info = elf.has_dwarf_info()
        dynamic_section = elf.get_section_by_name('.dynamic')
        dependencies = {}
        if isinstance(dynamic_section, DynamicSection):
            tags = dynamic_section.iter_tags()
            for tag in tags:
                if tag.entry.d_tag == 'DT_NEEDED':
                    try:
                        version = _check_library(tag, binary_path)
                    except Exception as e:
                        # DEBUGGING: This catches lookup, HTTP, and parsing errors
                        # and prints only the message, hiding the traceback.
                        # Use a bare raise here temporarily to locate the failure.
                        # A failure produces "unverified", not an empty list.
                        print(e)
                        version = "unverified"
                    dependencies[tag.needed] = version
        return BinaryReport(binary_name=binary_path.name,
                                binary_type=file_type, 
                                machine_arch=machine_arch,
                                dwarf_info=dwarf_info,
                                dependencies=dependencies)
