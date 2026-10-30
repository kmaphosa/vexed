"""
parsers.py -- turn a dependency manifest into a flat list of packages.

Supported inputs
----------------
* requirements.txt          (PyPI)   -- only `==` pins carry a version
* package-lock.json v2/v3   (npm)
* CycloneDX JSON SBOM       (any ecosystem with a purl)
* SPDX JSON SBOM            (any ecosystem with a purl external ref)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import unquote

# purl type -> OSV ecosystem name
PURL_ECOSYSTEMS = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "golang": "Go",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "nuget": "NuGet",
    "composer": "Packagist",
}


@dataclass(frozen=True)
class Package:
    name: str
    version: Optional[str]      # None = unpinned / unknown
    ecosystem: str              # OSV ecosystem name

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{self.name.lower()}@{self.version or '?'}"


# ---------------------------------------------------------------- purl
_PURL_RE = re.compile(r"^pkg:(?P<type>[^/]+)/(?P<rest>[^?#]+)")


def parse_purl(purl: str) -> Optional[Package]:
    m = _PURL_RE.match(purl or "")
    if not m:
        return None
    eco = PURL_ECOSYSTEMS.get(m.group("type").lower())
    if not eco:
        return None
    rest = m.group("rest")
    version = None
    if "@" in rest:
        rest, version = rest.rsplit("@", 1)
        version = unquote(version)
    parts = [unquote(p) for p in rest.split("/")]
    if eco == "Maven" and len(parts) >= 2:
        name = f"{parts[-2]}:{parts[-1]}"
    elif eco == "npm" and len(parts) >= 2:      # scoped package @scope/name
        name = f"{parts[-2]}/{parts[-1]}"
    elif eco == "Go":
        name = "/".join(parts)
    else:
        name = parts[-1]
    return Package(name=name, version=version, ecosystem=eco)


# ---------------------------------------------------------------- requirements.txt
_REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")


def parse_requirements(text: str) -> List[Package]:
    pkgs = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        line = line.split(";", 1)[0].strip()          # drop env markers
        m = _REQ_RE.match(line)
        if not m:
            continue
        name, spec = m.group(1), m.group(3).strip()
        pin = re.match(r"^===?\s*([^\s,]+)$", spec)
        pkgs.append(Package(name=name, version=pin.group(1) if pin else None,
                            ecosystem="PyPI"))
    return pkgs


# ---------------------------------------------------------------- npm lockfile
def parse_package_lock(data: dict) -> List[Package]:
    pkgs = []
    for path, meta in (data.get("packages") or {}).items():
        if not path or "node_modules/" not in path:
            continue                                   # "" is the root project
        name = meta.get("name") or path.rsplit("node_modules/", 1)[1]
        if meta.get("version"):
            pkgs.append(Package(name=name, version=meta["version"], ecosystem="npm"))
    if not pkgs:                                       # lockfile v1
        def walk(deps):
            for name, meta in (deps or {}).items():
                if meta.get("version"):
                    pkgs.append(Package(name=name, version=meta["version"], ecosystem="npm"))
                walk(meta.get("dependencies"))
        walk(data.get("dependencies"))
    return pkgs


# ---------------------------------------------------------------- SBOMs
def parse_cyclonedx(data: dict) -> List[Package]:
    pkgs = []

    def walk(components):
        for c in components or []:
            p = parse_purl(c.get("purl", ""))
            if p:
                pkgs.append(p)
            walk(c.get("components"))
    walk(data.get("components"))
    return pkgs


def parse_spdx(data: dict) -> List[Package]:
    pkgs = []
    for p in data.get("packages") or []:
        for ref in p.get("externalRefs") or []:
            if ref.get("referenceType") == "purl":
                pkg = parse_purl(ref.get("referenceLocator", ""))
                if pkg:
                    pkgs.append(pkg)
    return pkgs


# ---------------------------------------------------------------- dispatcher
def parse_manifest(filename: str, text: str) -> List[Package]:
    """Detect the format from name + content and return unique packages."""
    lower = filename.lower()
    pkgs: List[Package]
    if lower.endswith(".json"):
        data = json.loads(text)
        if data.get("bomFormat") == "CycloneDX":
            pkgs = parse_cyclonedx(data)
        elif "spdxVersion" in data:
            pkgs = parse_spdx(data)
        elif "lockfileVersion" in data:
            pkgs = parse_package_lock(data)
        else:
            raise ValueError("Unrecognised JSON: expected CycloneDX, SPDX or package-lock.json")
    else:
        pkgs = parse_requirements(text)

    seen, unique = set(), []
    for p in pkgs:
        if p.key not in seen:
            seen.add(p.key)
            unique.append(p)
    return unique
