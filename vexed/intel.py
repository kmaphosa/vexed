"""
intel.py -- deterministic vulnerability intelligence (no LLM here).

* OSV.dev      which of my package versions have known vulnerabilities
* FIRST EPSS   probability of exploitation in the next 30 days
* CISA KEV     is it being exploited in the wild right now
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import requests

from .parsers import Package

log = logging.getLogger(__name__)

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"
EPSS_API = "https://api.first.org/data/v1/epss"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

TIMEOUT = 20
_session = requests.Session()
_session.headers["User-Agent"] = "vexed-cve-triage/0.1"


@dataclass
class Vuln:
    id: str                              # CVE id when one exists, else GHSA/PYSEC/...
    package: Package
    summary: str = ""
    details: str = ""
    aliases: List[str] = field(default_factory=list)
    severity: str = "UNKNOWN"            # CRITICAL / HIGH / MODERATE / LOW / UNKNOWN
    fixed_versions: List[str] = field(default_factory=list)
    known_symbols: List[str] = field(default_factory=list)   # from OSV when published
    references: List[str] = field(default_factory=list)
    epss: Optional[float] = None
    epss_percentile: Optional[float] = None
    in_kev: bool = False
    osv_id: str = ""                     # original OSV record id, for the advisory link

    @property
    def cve(self) -> Optional[str]:
        for a in [self.id] + self.aliases:
            if a.startswith("CVE-"):
                return a
        return None

    @property
    def url(self) -> str:
        return f"https://osv.dev/vulnerability/{self.osv_id or self.id}"


# ---------------------------------------------------------------- OSV
def _osv_query(pkg: Package) -> dict:
    q = {"package": {"name": pkg.name, "ecosystem": pkg.ecosystem}}
    if pkg.version:
        q["version"] = pkg.version
    return q


def query_osv(packages: List[Package]) -> Dict[Package, List[str]]:
    """Return {package: [osv ids]} for pinned packages."""
    pinned = [p for p in packages if p.version]
    out: Dict[Package, List[str]] = {}
    for i in range(0, len(pinned), 500):
        chunk = pinned[i:i + 500]
        r = _session.post(OSV_BATCH, json={"queries": [_osv_query(p) for p in chunk]},
                          timeout=TIMEOUT)
        r.raise_for_status()
        for pkg, res in zip(chunk, r.json().get("results", [])):
            ids = [v["id"] for v in res.get("vulns", []) or []]
            if ids:
                out[pkg] = ids
    return out


def fetch_osv_record(vid: str) -> dict:
    r = _session.get(OSV_VULN.format(id=vid), timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()


def _severity(rec: dict) -> str:
    sev = (rec.get("database_specific") or {}).get("severity")
    if sev:
        return str(sev).upper()
    for a in rec.get("affected", []):
        sev = (a.get("ecosystem_specific") or {}).get("severity")
        if sev:
            return str(sev).upper()
    return "UNKNOWN"


def record_to_vuln(rec: dict, pkg: Package) -> Vuln:
    fixed, symbols = [], []
    for a in rec.get("affected", []):
        if (a.get("package") or {}).get("name", "").lower() != pkg.name.lower():
            continue
        for rng in a.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    fixed.append(ev["fixed"])
        for imp in (a.get("ecosystem_specific") or {}).get("imports", []) or []:
            symbols.extend(imp.get("symbols", []) or [])
    aliases = rec.get("aliases", []) or []
    cve = next((a for a in [rec["id"]] + aliases if a.startswith("CVE-")), None)
    return Vuln(
        id=cve or rec["id"],
        package=pkg,
        summary=rec.get("summary", "") or "",
        details=(rec.get("details", "") or "")[:4000],
        aliases=[a for a in [rec["id"]] + aliases if a != (cve or rec["id"])],
        severity=_severity(rec),
        fixed_versions=sorted(set(fixed)),
        known_symbols=sorted(set(symbols)),
        osv_id=rec["id"],
        references=[r["url"] for r in rec.get("references", [])[:5] if "url" in r],
    )


def merge_vulns(vulns: List[Vuln]) -> List[Vuln]:
    """OSV returns GHSA + PYSEC duplicates of one CVE; keep the richest record."""
    best: Dict[tuple, Vuln] = {}
    for v in vulns:
        k = (v.package.key, v.cve or v.id)
        cur = best.get(k)
        if cur is None:
            best[k] = v
            continue
        if len(v.details) > len(cur.details):
            v.aliases = sorted(set(v.aliases + cur.aliases + [cur.id]) - {v.id})
            v.fixed_versions = sorted(set(v.fixed_versions + cur.fixed_versions))
            if v.severity == "UNKNOWN":
                v.severity = cur.severity
            best[k] = v
        else:
            cur.aliases = sorted(set(cur.aliases + v.aliases + [v.id]) - {cur.id})
            cur.fixed_versions = sorted(set(cur.fixed_versions + v.fixed_versions))
            if cur.severity == "UNKNOWN":
                cur.severity = v.severity
    return list(best.values())


# ---------------------------------------------------------------- EPSS
def fetch_epss(cves: List[str]) -> Dict[str, tuple]:
    out: Dict[str, tuple] = {}
    cves = sorted(set(c for c in cves if c))
    for i in range(0, len(cves), 80):
        try:
            r = _session.get(EPSS_API, params={"cve": ",".join(cves[i:i + 80])},
                             timeout=TIMEOUT)
            r.raise_for_status()
            for row in r.json().get("data", []):
                out[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
        except Exception as e:                       # enrichment is best-effort
            log.warning("EPSS lookup failed: %s", e)
    return out


# ---------------------------------------------------------------- KEV
_kev_cache: dict = {"at": 0.0, "ids": set()}


def fetch_kev() -> set:
    if time.time() - _kev_cache["at"] < 6 * 3600 and _kev_cache["ids"]:
        return _kev_cache["ids"]
    try:
        r = _session.get(KEV_FEED, timeout=TIMEOUT)
        r.raise_for_status()
        ids = {v["cveID"] for v in r.json().get("vulnerabilities", [])}
        _kev_cache.update(at=time.time(), ids=ids)
    except Exception as e:
        log.warning("KEV feed failed: %s", e)
    return _kev_cache["ids"]


# ---------------------------------------------------------------- all together
def gather(packages: List[Package]) -> List[Vuln]:
    hits = query_osv(packages)
    vulns: List[Vuln] = []
    records: Dict[str, dict] = {}
    for pkg, ids in hits.items():
        for vid in ids:
            if vid not in records:
                records[vid] = fetch_osv_record(vid)
            vulns.append(record_to_vuln(records[vid], pkg))
    vulns = merge_vulns(vulns)

    epss = fetch_epss([v.cve for v in vulns if v.cve])
    kev = fetch_kev()
    for v in vulns:
        if v.cve in epss:
            v.epss, v.epss_percentile = epss[v.cve]
        v.in_kev = bool(v.cve and v.cve in kev)
    return vulns
