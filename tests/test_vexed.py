import json
import zipfile
from pathlib import Path

import pytest

from vexed import intel
from vexed.codebase import Codebase
from vexed.intel import Vuln, merge_vulns, record_to_vuln
from vexed.llm import normalise_verdict, parse_json
from vexed.parsers import Package, parse_manifest, parse_purl
from vexed.pipeline import to_markdown, to_openvex, triage

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples" / "vulnerable-app"

PYYAML = Package("PyYAML", "5.3.1", "PyPI")
URLLIB3 = Package("urllib3", "1.26.4", "PyPI")

YAML_REC = {
    "id": "GHSA-8q59-q68h-6hv4",
    "aliases": ["CVE-2020-14343"],
    "summary": "Improper Input Validation in PyYAML",
    "details": "A vulnerability was discovered in the PyYAML library in versions before 5.4, "
               "where it is susceptible to arbitrary code execution when it processes untrusted "
               "YAML files through the `full_load` method or with the `FullLoader` loader.",
    "database_specific": {"severity": "CRITICAL"},
    "affected": [{"package": {"name": "pyyaml", "ecosystem": "PyPI"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4"}]}]}],
    "references": [{"url": "https://example.com/a"}],
}
YAML_DUP = {**YAML_REC, "id": "PYSEC-2021-142", "aliases": ["CVE-2020-14343"],
            "details": "short", "database_specific": {}}
URLLIB_REC = {
    "id": "GHSA-v845-jxx5-vc9f", "aliases": ["CVE-2023-43804"],
    "summary": "Cookie request header isn't stripped during cross-origin redirects",
    "details": "urllib3 doesn't treat the `Cookie` HTTP header special on redirect.",
    "database_specific": {"severity": "HIGH"},
    "affected": [{"package": {"name": "urllib3", "ecosystem": "PyPI"},
                  "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.26.17"}]}]}],
}


# ---------------------------------------------------------------- parsers
def test_requirements_pins_and_unpinned():
    pkgs = parse_manifest("requirements.txt",
                          "flask==1.1.2\nrequests>=2\nPyYAML[extra] == 5.3.1 ; python_version>'3'\n# c\n-r x.txt\n")
    assert Package("flask", "1.1.2", "PyPI") in pkgs
    assert Package("requests", None, "PyPI") in pkgs
    assert Package("PyYAML", "5.3.1", "PyPI") in pkgs


def test_purl_variants():
    assert parse_purl("pkg:npm/%40babel/core@7.0.0") == Package("@babel/core", "7.0.0", "npm")
    assert parse_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1").name == \
        "org.apache.logging.log4j:log4j-core"
    assert parse_purl("pkg:golang/golang.org/x/net@v0.1.0").name == "golang.org/x/net"


def test_cyclonedx_and_lockfile():
    bom = {"bomFormat": "CycloneDX", "components": [{"purl": "pkg:pypi/jinja2@2.11.2"}]}
    assert parse_manifest("bom.json", json.dumps(bom)) == [Package("jinja2", "2.11.2", "PyPI")]
    lock = {"lockfileVersion": 3, "packages": {"": {}, "node_modules/lodash": {"version": "4.17.20"}}}
    assert parse_manifest("package-lock.json", json.dumps(lock)) == [Package("lodash", "4.17.20", "npm")]


# ---------------------------------------------------------------- intel
def test_record_merge_prefers_cve_and_rich_details():
    vs = merge_vulns([record_to_vuln(YAML_REC, PYYAML), record_to_vuln(YAML_DUP, PYYAML)])
    assert len(vs) == 1
    v = vs[0]
    assert v.id == "CVE-2020-14343" and v.severity == "CRITICAL"
    assert v.fixed_versions == ["5.4"]
    assert "PYSEC-2021-142" in v.aliases and "GHSA-8q59-q68h-6hv4" in v.aliases


def test_gather_with_mocked_http(monkeypatch):
    class R:
        def __init__(self, data): self._d = data
        def raise_for_status(self): pass
        def json(self): return self._d

    class S:
        def post(self, url, json=None, timeout=None):
            names = [q["package"]["name"] for q in json["queries"]]
            return R({"results": [{"vulns": [{"id": "GHSA-8q59-q68h-6hv4"}]} if n == "PyYAML" else {}
                                  for n in names]})

        def get(self, url, params=None, timeout=None):
            if "osv.dev" in url:
                return R(YAML_REC)
            if "first.org" in url:
                return R({"data": [{"cve": "CVE-2020-14343", "epss": "0.02", "percentile": "0.8"}]})
            return R({"vulnerabilities": [{"cveID": "CVE-2020-14343"}]})

    monkeypatch.setattr(intel, "_session", S())
    intel._kev_cache.update(at=0.0, ids=set())
    vs = intel.gather([PYYAML, Package("flask", None, "PyPI")])
    assert len(vs) == 1 and vs[0].in_kev and vs[0].epss == 0.02


# ---------------------------------------------------------------- codebase
def test_zip_slip_blocked_and_evidence(tmp_path):
    z = tmp_path / "src.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.write(DEMO / "app.py", "app.py")
        zf.writestr("../../evil.py", "import os")
    code = Codebase.from_zip(str(z))
    assert list(code.files) == ["app.py"]
    ev = code.evidence(PYYAML, ["yaml.full_load", "FullLoader"])
    assert ev.imported
    assert ev.symbol_hits["FullLoader"] and not ev.symbol_hits["yaml.full_load"]
    assert not code.evidence(URLLIB3, ["Cookie"]).imported


def test_github_url_validation():
    with pytest.raises(ValueError):
        Codebase.from_github("https://evil.example.com/x/y")
    with pytest.raises(ValueError):
        Codebase.from_github("https://github.com/a/b; rm -rf /")


# ---------------------------------------------------------------- llm helpers
def test_parse_json_handles_think_and_fences():
    assert parse_json('<think>hmm</think>```json\n{"a": 1}\n```') == {"a": 1}
    assert parse_json("Sure! {\"status\": \"affected\"} done") == {"status": "affected"}


def test_normalise_verdict():
    v = normalise_verdict({"status": "not_affected", "justification": "bogus"})
    assert v["justification"] == "vulnerable_code_not_in_execute_path"
    assert normalise_verdict({"status": "weird"})["status"] == "under_investigation"


# ---------------------------------------------------------------- pipeline
class FakeLLM:
    model = "nvidia/fake-nemotron"

    def extract_symbols(self, v):
        return {"symbols": ["FullLoader", "full_load"] if "yaml" in v.package.name.lower()
                else ["Cookie"], "trigger": "x"}

    def judge(self, v, trigger, evidence):
        if "FullLoader" in evidence and "app.py" in evidence:
            return normalise_verdict({"status": "affected", "confidence": "high",
                                      "reasoning": "app.py:14 parses request data", "action": "Upgrade"})
        return normalise_verdict({"status": "not_affected", "confidence": "medium",
                                  "reasoning": "not reachable"})


def test_triage_end_to_end_and_vex():
    code = Codebase(DEMO)
    vulns = [record_to_vuln(YAML_REC, PYYAML), record_to_vuln(URLLIB_REC, URLLIB3)]
    vulns[0].in_kev = True
    findings = triage(vulns, code, FakeLLM())
    assert findings[0].vuln.id == "CVE-2020-14343"
    assert findings[0].verdict["status"] == "affected"
    assert findings[0].priority.startswith("P0")
    assert findings[1].verdict["status"] == "not_affected"

    vex = to_openvex(findings)
    assert vex["@context"].startswith("https://openvex.dev")
    st = {s["vulnerability"]["name"]: s for s in vex["statements"]}
    assert st["CVE-2023-43804"]["justification"] == "vulnerable_code_not_in_execute_path"
    assert st["CVE-2020-14343"]["products"][0]["subcomponents"][0]["@id"] == "pkg:pypi/PyYAML@5.3.1"
    md = to_markdown(findings, 6, [])
    assert "1** affect you" in md


def test_triage_heuristic_mode():
    findings = triage([record_to_vuln(YAML_REC, PYYAML)], Codebase(DEMO), None)
    assert findings[0].verdict["status"] == "affected"     # FullLoader found in app.py
