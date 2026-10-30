"""
codebase.py -- load the user's source code and search it for evidence.

Sources: a .zip upload or a public GitHub URL (shallow clone).
Extraction is defensive: zip-slip, size and file-count limits.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .parsers import Package

CODE_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".java",
            ".kt", ".rb", ".php", ".cs", ".rs"}
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "env", "__pycache__",
             "dist", "build", "site-packages", "vendor", ".tox"}
MAX_FILES = 4000
MAX_FILE_BYTES = 512 * 1024
MAX_ZIP_BYTES = 200 * 1024 * 1024
GITHUB_RE = re.compile(r"^https://github\.com/[\w.-]+/[\w.-]+?(\.git)?/?$")

# PyPI distribution name -> import name, where they differ
PY_IMPORT_NAMES = {
    "pyyaml": "yaml", "pillow": "PIL", "beautifulsoup4": "bs4",
    "scikit-learn": "sklearn", "python-dateutil": "dateutil",
    "opencv-python": "cv2", "protobuf": "google.protobuf", "pyjwt": "jwt",
    "pycryptodome": "Crypto", "python-jose": "jose", "msgpack-python": "msgpack",
    "attrs": "attr", "pymongo": "pymongo", "setuptools": "setuptools",
    "markupsafe": "markupsafe", "werkzeug": "werkzeug", "jinja2": "jinja2",
}


@dataclass
class Hit:
    path: str
    line: int
    text: str


@dataclass
class Evidence:
    imported: bool
    import_hits: List[Hit] = field(default_factory=list)
    symbol_hits: Dict[str, List[Hit]] = field(default_factory=dict)

    def as_text(self, max_lines: int = 25) -> str:
        lines = []
        if not self.imported:
            lines.append("The package is NOT imported/required anywhere in the scanned source.")
        else:
            lines.append("Package import sites:")
            lines += [f"  {h.path}:{h.line}: {h.text}" for h in self.import_hits[:8]]
        for sym, hits in self.symbol_hits.items():
            if hits:
                lines.append(f"Usages of `{sym}`:")
                lines += [f"  {h.path}:{h.line}: {h.text}" for h in hits[:6]]
            else:
                lines.append(f"No usages of `{sym}` found.")
        return "\n".join(lines[:max_lines])


class Codebase:
    def __init__(self, root: Path):
        self.root = root
        self.files: Dict[str, List[str]] = {}
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                p = Path(dirpath) / fn
                if p.suffix not in CODE_EXT or p.is_symlink():
                    continue
                try:
                    if p.stat().st_size > MAX_FILE_BYTES:
                        continue
                    self.files[str(p.relative_to(root))] = p.read_text(
                        errors="ignore").splitlines()
                except OSError:
                    continue
                if len(self.files) >= MAX_FILES:
                    return

    # ------------------------------------------------------------ loading
    @classmethod
    def from_zip(cls, zip_path: str) -> "Codebase":
        dest = Path(tempfile.mkdtemp(prefix="vexed-src-"))
        total = 0
        with zipfile.ZipFile(zip_path) as zf:
            for info in zf.infolist():
                target = (dest / info.filename).resolve()
                if not str(target).startswith(str(dest.resolve()) + os.sep):
                    continue                                   # zip-slip
                total += info.file_size
                if total > MAX_ZIP_BYTES:
                    raise ValueError("Archive too large (limit 200 MB uncompressed)")
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if Path(info.filename).suffix not in CODE_EXT:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out)
        return cls(dest)

    @classmethod
    def from_github(cls, url: str) -> "Codebase":
        url = url.strip()
        if not GITHUB_RE.match(url):
            raise ValueError("Only public https://github.com/<owner>/<repo> URLs are supported")
        dest = Path(tempfile.mkdtemp(prefix="vexed-git-"))
        subprocess.run(["git", "clone", "--depth", "1", "--quiet", "--", url, str(dest)],
                       check=True, timeout=120,
                       env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
        return cls(dest)

    def find_file(self, name: str) -> Optional[Path]:
        """Locate a manifest (e.g. requirements.txt) inside the repo."""
        for p in sorted(self.root.rglob(name), key=lambda x: len(x.parts)):
            if not any(part in SKIP_DIRS for part in p.parts):
                return p
        return None

    # ------------------------------------------------------------ searching
    def grep(self, pattern: re.Pattern, limit: int = 20) -> List[Hit]:
        hits = []
        for path, lines in self.files.items():
            for i, line in enumerate(lines, 1):
                if pattern.search(line):
                    hits.append(Hit(path, i, line.strip()[:200]))
                    if len(hits) >= limit:
                        return hits
        return hits

    def import_pattern(self, pkg: Package) -> re.Pattern:
        if pkg.ecosystem == "PyPI":
            mod = PY_IMPORT_NAMES.get(pkg.name.lower(),
                                      pkg.name.lower().replace("-", "_"))
            m = re.escape(mod)
            return re.compile(rf"^\s*(import\s+{m}\b|from\s+{m}(\.|\s))", re.I)
        if pkg.ecosystem == "npm":
            n = re.escape(pkg.name)
            return re.compile(rf"""(require\(\s*['"]{n}(/[^'"]*)?['"]\s*\)|from\s+['"]{n}(/[^'"]*)?['"]|import\s+['"]{n}['"])""")
        if pkg.ecosystem == "Go":
            return re.compile(rf'"{re.escape(pkg.name)}(/[^"]*)?"')
        return re.compile(re.escape(pkg.name.split(":")[-1]))

    def evidence(self, pkg: Package, symbols: List[str]) -> Evidence:
        import_hits = self.grep(self.import_pattern(pkg))
        ev = Evidence(imported=bool(import_hits), import_hits=import_hits)
        for sym in symbols[:8]:
            leaf = sym.split(".")[-1].split("(")[0].strip()
            if len(leaf) < 3 or not re.match(r"^[\w$]+$", leaf):
                continue
            ev.symbol_hits[sym] = self.grep(re.compile(rf"\b{re.escape(leaf)}\b"), limit=10)
        return ev
