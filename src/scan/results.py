from dataclasses import dataclass

@dataclass
class BinaryReport:
    binary_name: str
    binary_type: str
    machine_arch: str
    dwarf_info: bool
    dependencies: dict[str, dict|str]

@dataclass
class Vulnerability:
    cve_id: str
    severity: list[dict]
    description: str

@dataclass
class DependenciesCheck:
    name: str
    resolved_path: str
    inferred_version: str | None
    version: str | None
    vulnerabilities: dict[str, list[Vulnerability]]