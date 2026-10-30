"""
pipeline.py -- manifest + code in, ranked findings + OpenVEX out.
"""

from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, List, Optional

from . import __version__
from .codebase import Codebase
from .intel import Vuln
from .llm import Nemotron, heuristic_symbols, heuristic_verdict

log = logging.getLogger(__name__)

STATUS_RANK = {"affected": 0, "under_investigation": 1, "not_affected": 2}
SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


@dataclass
class Finding:
    vuln: Vuln
    symbols: List[str] = field(default_factory=list)
    trigger: str = ""
    evidence: str = ""
    verdict: dict = field(default_factory=dict)
    analysed_by: str = "heuristic"

    @property
    def priority(self) -> str:
        s = self.verdict.get("status")
        if self.vuln.in_kev and s != "not_affected":
            return "P0 - fix now"
        if s == "affected" and (self.vuln.epss or 0) >= 0.1:
            return "P0 - fix now"
        if s == "affected":
            return "P1 - fix this sprint"
        if s == "under_investigation":
            return "P2 - review"
        return "P3 - routine upgrade"

    def sort_key(self):
        return (self.priority, STATUS_RANK.get(self.verdict.get("status"), 1),
                -(self.vuln.epss or 0), SEV_RANK.get(self.vuln.severity, 4))


def triage(vulns: List[Vuln], code: Optional[Codebase], llm: Optional[Nemotron],
           max_llm: int = 25, progress: Optional[Callable] = None) -> List[Finding]:
    """Run reachability analysis on each vulnerability (LLM for the top `max_llm`)."""
    # cheapest-first ordering so the LLM budget goes to what matters most
    vulns = sorted(vulns, key=lambda v: (not v.in_kev, -(v.epss or 0),
                                         SEV_RANK.get(v.severity, 4)))

    def analyse(idx_v):
        idx, v = idx_v
        f = Finding(vuln=v)
        use_llm = llm is not None and idx < max_llm
        try:
            if use_llm:
                s = llm.extract_symbols(v)
                f.symbols = s["symbols"] or heuristic_symbols(v)
                f.trigger = s["trigger"]
            else:
                f.symbols = heuristic_symbols(v)
            if code is not None:
                ev = code.evidence(v.package, f.symbols)
                f.evidence = ev.as_text()
            else:
                ev = None
                f.evidence = "No source code supplied; reachability could not be checked."
            if use_llm:
                f.verdict = llm.judge(v, f.trigger, f.evidence)
                f.analysed_by = llm.model
            elif ev is not None:
                f.verdict = heuristic_verdict(ev)
            else:
                f.verdict = {"status": "under_investigation", "justification": None,
                             "confidence": "low", "reasoning": f.evidence,
                             "action": "Upload source code to check reachability."}
        except Exception as e:
            log.exception("analysis failed for %s", v.id)
            f.verdict = {"status": "under_investigation", "justification": None,
                         "confidence": "low", "reasoning": f"Analysis error: {e}",
                         "action": "Review manually."}
        if progress:
            progress(v.id)
        return f

    with ThreadPoolExecutor(max_workers=6) as pool:
        findings = list(pool.map(analyse, enumerate(vulns)))
    return sorted(findings, key=Finding.sort_key)


# ---------------------------------------------------------------- outputs
def _purl(pkg) -> str:
    eco = {"PyPI": "pypi", "npm": "npm", "Maven": "maven", "Go": "golang",
           "crates.io": "cargo", "RubyGems": "gem", "NuGet": "nuget",
           "Packagist": "composer"}.get(pkg.ecosystem, pkg.ecosystem.lower())
    name = pkg.name.replace(":", "/")
    return f"pkg:{eco}/{name}" + (f"@{pkg.version}" if pkg.version else "")


def to_openvex(findings: List[Finding], product: str = "my-application") -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    stmts = []
    for f in findings:
        v = f.verdict
        st = {
            "vulnerability": {"name": f.vuln.id, "aliases": f.vuln.aliases},
            "products": [{"@id": product,
                          "subcomponents": [{"@id": _purl(f.vuln.package)}]}],
            "status": v["status"],
        }
        if v["status"] == "not_affected":
            st["justification"] = v["justification"]
            st["impact_statement"] = v["reasoning"]
        elif v["status"] == "affected":
            st["action_statement"] = v.get("action") or "Upgrade to a fixed version."
        else:
            st["status_notes"] = v["reasoning"]
        stmts.append(st)
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://github.com/kmaphosa/vexed/vex/{now}",
        "author": "VEXed (automated triage, review before publishing)",
        "timestamp": now,
        "version": 1,
        "tooling": f"vexed/{__version__}",
        "statements": stmts,
    }


def to_markdown(findings: List[Finding], packages_scanned: int, unpinned: List[str]) -> str:
    counts = {s: sum(1 for f in findings if f.verdict.get("status") == s)
              for s in STATUS_RANK}
    out = [
        "# VEXed triage report",
        "",
        f"**{packages_scanned}** packages scanned · **{len(findings)}** known vulnerabilities · "
        f"**{counts['affected']}** affect you · **{counts['under_investigation']}** need review · "
        f"**{counts['not_affected']}** not reachable",
        "",
    ]
    if unpinned:
        out += [f"> ⚠️ {len(unpinned)} unpinned package(s) could not be checked: "
                + ", ".join(f"`{u}`" for u in unpinned[:15])
                + ". Pin versions (`pip freeze`) for a full scan.", ""]
    for f in findings:
        v, vu = f.verdict, f.vuln
        icon = {"affected": "🔴", "under_investigation": "🟡", "not_affected": "🟢"}[v["status"]]
        epss = f"{vu.epss:.1%}" if vu.epss is not None else "n/a"
        out += [
            f"## {icon} {vu.id} · `{vu.package.name}` {vu.package.version} · {f.priority}",
            "",
            f"_{vu.summary or 'No summary'}_",
            "",
            f"- **Verdict:** {v['status'].replace('_', ' ')}"
            + (f" ({v['justification'].replace('_', ' ')})" if v.get("justification") else "")
            + f" · confidence {v['confidence']}",
            f"- **Why:** {v['reasoning']}",
            f"- **Next step:** {v.get('action') or '-'}",
            f"- **Severity:** {vu.severity} · **EPSS:** {epss} · "
            f"**CISA KEV:** {'YES' if vu.in_kev else 'no'} · "
            f"**Fixed in:** {', '.join(vu.fixed_versions) or 'no fix listed'}",
            f"- **Vulnerable APIs checked:** {', '.join(f'`{s}`' for s in f.symbols) or '-'}",
            f"- [Advisory]({vu.url}) · analysed by `{f.analysed_by}`",
            "",
        ]
    return "\n".join(out)


def to_rows(findings: List[Finding]) -> List[list]:
    return [[f.priority, f.vuln.id, f.vuln.package.name, f.vuln.package.version,
             f.verdict["status"].replace("_", " "), f.vuln.severity,
             round(f.vuln.epss, 4) if f.vuln.epss is not None else None,
             "YES" if f.vuln.in_kev else "", ", ".join(f.vuln.fixed_versions[:2])]
            for f in findings]


ROW_HEADERS = ["Priority", "Vulnerability", "Package", "Version", "Verdict",
               "Severity", "EPSS", "KEV", "Fixed in"]


def dumps_vex(vex: dict) -> str:
    return json.dumps(vex, indent=2)
