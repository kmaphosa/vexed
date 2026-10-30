"""
llm.py -- NVIDIA Nemotron on Nebius Token Factory (OpenAI-compatible API).

Two jobs:
  1. extract_symbols()  read an advisory, name the vulnerable functions/modules
  2. judge()            read advisory + code evidence, give a VEX verdict
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
from typing import List, Optional

log = logging.getLogger(__name__)

BASE_URL = os.getenv("NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1/")
API_KEY_ENV = "NEBIUS_API_KEY"

VEX_STATUSES = {"affected", "not_affected", "under_investigation"}
VEX_JUSTIFICATIONS = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}

SYMBOLS_PROMPT = """You are a vulnerability analyst. From the security advisory below, identify the
specific functions, methods, classes or sub-modules of the package `{pkg}` that contain or
trigger the vulnerability. Return ONLY JSON:
{{"symbols": ["name", ...], "trigger": "one sentence: what an app must do to be exploitable"}}
Use the names a developer would write in code (e.g. "yaml.load", "Image.open", "merge").
List at most 6. If the advisory names no specific API, return the most likely entry points.

ADVISORY ({vid}):
{summary}
{details}
"""

JUDGE_PROMPT = """You are triaging whether a vulnerability in a dependency actually affects THIS
application. Decide from the evidence; do not assume exploitability without it.

Package: {pkg} {version} ({eco})
Vulnerability: {vid} -- {summary}
How it is triggered: {trigger}
Fixed in: {fixed}

Advisory details:
{details}

Evidence from scanning the application's source code:
{evidence}

Rules:
- If the package is never imported, it may still be a transitive dependency used by another
  library; prefer "not_affected" with "vulnerable_code_not_in_execute_path" only when the
  vulnerable feature is clearly app-facing, otherwise "under_investigation".
- If the vulnerable API is called, check whether attacker-controlled input could reach it.
- If the package is imported but the vulnerable API is not used, "not_affected" with
  "vulnerable_code_not_in_execute_path" is usually right.

Return ONLY JSON:
{{"status": "affected" | "not_affected" | "under_investigation",
  "justification": one of {justifications} or null (required when not_affected),
  "confidence": "high" | "medium" | "low",
  "reasoning": "2-3 sentences citing file:line evidence",
  "action": "one concrete next step for the developer"}}
"""


class Nemotron:
    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        from openai import OpenAI
        key = api_key or os.getenv(API_KEY_ENV) or ""
        # copy/paste from browsers and chat apps can add invisible characters or quotes
        key = "".join(ch for ch in key if 33 <= ord(ch) <= 126).strip("'\"")
        if not key:
            raise RuntimeError(f"{API_KEY_ENV} is not set")
        self.client = OpenAI(base_url=BASE_URL, api_key=key, timeout=90, max_retries=2)
        self.model = model or os.getenv("NEBIUS_MODEL") or self._discover_model()
        self._cache: dict = {}
        self._lock = threading.Lock()

    def _discover_model(self) -> str:
        """Pick an NVIDIA Nemotron text model from the account's model list."""
        ids = [m.id for m in self.client.models.list().data]
        nemo = [i for i in ids if "nemotron" in i.lower()
                and not re.search(r"embed|rerank|vl|omni|reward|safety|guard", i.lower())]
        if not nemo:
            raise RuntimeError("No NVIDIA Nemotron model available on this Nebius account; "
                               "set NEBIUS_MODEL explicitly")
        for pref in ("super", "nano", "ultra"):          # balance speed vs quality
            for i in nemo:
                if pref in i.lower():
                    return i
        return nemo[0]

    # ------------------------------------------------------------ plumbing
    def _ask(self, prompt: str, max_tokens: int = 2500) -> dict:
        h = hashlib.sha256(f"{self.model}\n{prompt}".encode()).hexdigest()
        with self._lock:
            if h in self._cache:
                return self._cache[h]
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "You are a precise application-security "
                 "engineer. Reply with a single JSON object and nothing else."},
                {"role": "user", "content": prompt},
            ],
            temperature=0,
            max_tokens=max_tokens,
        )
        msg = resp.choices[0].message
        text = msg.content or ""
        if "{" not in text:          # reasoning models may put everything in reasoning_content
            text += "\n" + (getattr(msg, "reasoning_content", None) or "")
        result = parse_json(text)
        with self._lock:
            self._cache[h] = result
        return result

    # ------------------------------------------------------------ tasks
    def extract_symbols(self, vuln) -> dict:
        out = self._ask(SYMBOLS_PROMPT.format(
            pkg=vuln.package.name, vid=vuln.id, summary=vuln.summary,
            details=vuln.details[:3000]), max_tokens=1500)
        syms = [str(s) for s in out.get("symbols", []) if s][:6]
        return {"symbols": syms, "trigger": str(out.get("trigger", ""))}

    def judge(self, vuln, trigger: str, evidence_text: str) -> dict:
        out = self._ask(JUDGE_PROMPT.format(
            pkg=vuln.package.name, version=vuln.package.version, eco=vuln.package.ecosystem,
            vid=vuln.id, summary=vuln.summary, trigger=trigger or "unknown",
            fixed=", ".join(vuln.fixed_versions) or "no fix listed",
            details=vuln.details[:2500], evidence=evidence_text,
            justifications=sorted(VEX_JUSTIFICATIONS)))
        return normalise_verdict(out)


# ---------------------------------------------------------------- helpers
def parse_json(text: str) -> dict:
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()
    text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.M).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = None
        for m in re.finditer(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", text, flags=re.S):
            pass                       # keep the LAST JSON object (the final answer)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                pass
    log.warning("Model returned non-JSON: %.200s", text)
    return {}


def normalise_verdict(out: dict) -> dict:
    status = str(out.get("status", "")).lower().strip()
    if status not in VEX_STATUSES:
        status = "under_investigation"
    just = out.get("justification")
    just = just if just in VEX_JUSTIFICATIONS else None
    if status == "not_affected" and not just:
        just = "vulnerable_code_not_in_execute_path"
    if status != "not_affected":
        just = None
    conf = str(out.get("confidence", "low")).lower()
    return {
        "status": status,
        "justification": just,
        "confidence": conf if conf in {"high", "medium", "low"} else "low",
        "reasoning": str(out.get("reasoning", "")).strip() or "No reasoning returned.",
        "action": str(out.get("action", "")).strip(),
    }


def heuristic_symbols(vuln) -> List[str]:
    """Offline fallback: backticked or dotted identifiers in the advisory."""
    text = f"{vuln.summary}\n{vuln.details}"
    found = re.findall(r"`([A-Za-z_][\w.]*)\(?\)?`", text)
    found += re.findall(r"\b([a-z_]\w*\.[a-z_]\w*)\(", text)
    seen, out = set(), []
    for s in vuln.known_symbols + found:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out[:6]


def heuristic_verdict(evidence) -> dict:
    """Offline fallback used when no API key is configured."""
    if not evidence.imported:
        return normalise_verdict({
            "status": "under_investigation", "confidence": "low",
            "reasoning": "Package is not imported directly; it may be a transitive dependency.",
            "action": "Confirm which library pulls it in, or upgrade to be safe."})
    used = [s for s, h in evidence.symbol_hits.items() if h]
    if used:
        h = evidence.symbol_hits[used[0]][0]
        return normalise_verdict({
            "status": "affected", "confidence": "medium",
            "reasoning": f"Vulnerable API `{used[0]}` is called at {h.path}:{h.line}.",
            "action": "Upgrade to a fixed version."})
    return normalise_verdict({
        "status": "not_affected", "confidence": "low",
        "justification": "vulnerable_code_not_in_execute_path",
        "reasoning": "Package is imported but none of the vulnerable APIs were found.",
        "action": "Upgrade at the next routine dependency bump."})
