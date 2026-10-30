"""
app.py -- VEXed web app (Gradio)
================================
"Is this CVE actually my problem?"

Give it a dependency manifest (requirements.txt / package-lock.json / SBOM) and your
source code (zip or public GitHub URL). It finds known vulnerabilities (OSV), adds
exploit intelligence (EPSS, CISA KEV), then asks NVIDIA Nemotron on Nebius Token Factory
whether your code actually reaches the vulnerable API, and exports OpenVEX.

Run locally:  NEBIUS_API_KEY=... python app.py  ->  http://127.0.0.1:7860
"""

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path

import gradio as gr

from vexed.codebase import Codebase
from vexed.intel import gather
from vexed.parsers import parse_manifest
from vexed.pipeline import (ROW_HEADERS, dumps_vex, to_markdown, to_openvex,
                            to_rows, triage)

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("vexed")

DEMO_DIR = Path(__file__).parent / "examples" / "vulnerable-app"
MANIFEST_NAMES = ["requirements.txt", "package-lock.json", "bom.json",
                  "sbom.json", "cyclonedx.json"]

_llm = None
_llm_error = None


def get_llm():
    """Create the Nemotron client once; fall back to heuristics if unavailable."""
    global _llm, _llm_error
    if _llm is None and _llm_error is None:
        try:
            from vexed.llm import Nemotron
            _llm = Nemotron()
            log.info("Using model %s", _llm.model)
        except Exception as e:
            _llm_error = str(e)
            log.warning("LLM unavailable, using heuristics: %s", e)
    return _llm


def _write_tmp(text: str, suffix: str) -> str:
    with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False,
                                     prefix="vexed-", encoding="utf-8") as fh:
        fh.write(text)
        return fh.name


def run(manifest_file, code_zip, github_url, max_llm, progress=gr.Progress()):
    try:
        progress(0.02, desc="Loading source code")
        code = None
        if github_url and github_url.strip():
            code = Codebase.from_github(github_url)
        elif code_zip is not None:
            code = Codebase.from_zip(code_zip if isinstance(code_zip, str) else code_zip.name)

        # manifest: explicit upload wins, otherwise look inside the code
        if manifest_file is not None:
            mpath = Path(manifest_file if isinstance(manifest_file, str) else manifest_file.name)
        elif code is not None:
            mpath = next((p for p in (code.find_file(n) for n in MANIFEST_NAMES) if p), None)
            if mpath is None:
                raise gr.Error("No requirements.txt / package-lock.json / SBOM found in the repo; upload one.")
        else:
            raise gr.Error("Upload a manifest, a source zip, or give a GitHub URL.")

        packages = parse_manifest(mpath.name, mpath.read_text(errors="ignore"))
        unpinned = [p.name for p in packages if not p.version]
        progress(0.1, desc=f"Querying OSV for {len(packages)} packages")
        vulns = gather(packages)

        llm = get_llm()
        done = {"n": 0}

        def tick(_vid):
            done["n"] += 1
            progress(0.2 + 0.75 * done["n"] / max(len(vulns), 1),
                     desc=f"Nemotron triage {done['n']}/{len(vulns)}")

        findings = triage(vulns, code, llm, max_llm=int(max_llm), progress=tick)

        report = to_markdown(findings, len(packages), unpinned)
        product = (github_url or "").strip() or "my-application"
        vex = to_openvex(findings, product=product)

        engine = (f"🧠 Reasoning model: **{llm.model}** on Nebius Token Factory"
                  if llm else f"⚙️ Heuristic mode (no LLM: {_llm_error})")
        counts = {s: sum(1 for f in findings if f.verdict["status"] == s)
                  for s in ("affected", "under_investigation", "not_affected")}
        noise = (counts["not_affected"] / len(findings)) if findings else 0
        summary = (
            f"### {len(findings)} vulnerabilities found → **{counts['affected']} actually affect you**\n"
            f"🔴 {counts['affected']} affected · 🟡 {counts['under_investigation']} need review · "
            f"🟢 {counts['not_affected']} not reachable "
            f"(**{noise:.0%} of the noise removed**)\n\n{engine}"
        )
        return (summary, to_rows(findings), report,
                _write_tmp(dumps_vex(vex), ".openvex.json"),
                _write_tmp(report, ".md"))
    except gr.Error:
        raise
    except Exception as e:
        log.exception("run failed")
        raise gr.Error(f"Something went wrong: {e}")


def run_demo(max_llm, progress=gr.Progress()):
    """Demo: bundled deliberately-vulnerable Flask app."""
    import shutil
    import zipfile
    zpath = Path(tempfile.mkdtemp(prefix="vexed-demo-")) / "demo.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        for p in DEMO_DIR.rglob("*"):
            if p.is_file():
                zf.write(p, p.relative_to(DEMO_DIR))
    try:
        return run(str(DEMO_DIR / "requirements.txt"), str(zpath), "", max_llm, progress)
    finally:
        shutil.rmtree(zpath.parent, ignore_errors=True)


with gr.Blocks(title="VEXed — is this CVE actually my problem?") as demo:
    gr.Markdown(
        "# VEXed\n"
        "### Is this CVE actually my problem?\n"
        "Scanners list every CVE in your dependency tree. VEXed checks whether **your code "
        "actually reaches the vulnerable function**, using NVIDIA Nemotron on Nebius Token "
        "Factory, ranks what's left by real-world exploitation (CISA KEV, EPSS), and "
        "exports an **OpenVEX** document you can feed back into your scanner.")
    with gr.Row():
        with gr.Column():
            manifest = gr.File(label="Dependency manifest (requirements.txt, package-lock.json, CycloneDX/SPDX JSON)",
                               file_types=[".txt", ".json"])
            code_zip = gr.File(label="Source code (.zip)", file_types=[".zip"])
            github = gr.Textbox(label="…or a public GitHub repo URL",
                                placeholder="https://github.com/owner/repo")
            max_llm = gr.Slider(1, 40, value=20, step=1,
                                label="Max vulnerabilities sent to Nemotron (rest use heuristics)")
            with gr.Row():
                go = gr.Button("Triage", variant="primary")
                demo_btn = gr.Button("Try the demo app")
        with gr.Column():
            summary = gr.Markdown()
            vex_file = gr.File(label="OpenVEX (.json)")
            report_file = gr.File(label="Report (.md)")
    table = gr.Dataframe(headers=ROW_HEADERS, label="Ranked findings", wrap=True)
    report = gr.Markdown()

    outs = [summary, table, report, vex_file, report_file]
    go.click(run, [manifest, code_zip, github, max_llm], outs)
    demo_btn.click(run_demo, [max_llm], outs)

if __name__ == "__main__":
    # Hosting platforms (Render, Railway, Fly, ...) provide $PORT and need 0.0.0.0
    port = os.getenv("PORT")
    if port:
        demo.launch(server_name="0.0.0.0", server_port=int(port))
    else:
        demo.launch()
