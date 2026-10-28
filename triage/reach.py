"""도달성: 직접 의존 여부와 1st-party 코드가 그 패키지를 import/require 하는지 확인한다.

본선 설계에서는 어드바이저리가 지목한 취약 함수의 실제 호출 여부를 코드 검색 도구로 확인하는
단계가 추가된다. 여기서는 그 1차 근사로 패키지 수준 import 여부를 쓴다. 근거 파일과 줄을 남긴다.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from .config import PY_IMPORT_NAMES, SERVICES

SKIP_DIRS = {"node_modules", ".git", "venv", ".venv", "__pycache__", "dist", "build", "Solutions", "docs", "test", "tests", "spec"}


def _iter_files(root: Path, exts: tuple[str, ...]):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if fn.endswith(exts):
                yield Path(dirpath) / fn


def _py_import_names(package: str) -> list[str]:
    p = package.lower()
    names = PY_IMPORT_NAMES.get(p)
    if names:
        return names
    return [p.replace("-", "_")]


def python_imports(root: Path) -> dict[str, list[tuple[str, int]]]:
    """import 문에서 최상위 모듈 이름 → (파일, 줄) 목록."""
    pat = re.compile(r"^\s*(?:from\s+([A-Za-z_][\w]*)|import\s+([A-Za-z_][\w]*))")
    found: dict[str, list[tuple[str, int]]] = {}
    for f in _iter_files(root, (".py",)):
        try:
            for i, line in enumerate(f.read_text(errors="ignore").splitlines(), 1):
                m = pat.match(line)
                if m:
                    mod = (m.group(1) or m.group(2))
                    found.setdefault(mod, []).append((str(f.relative_to(root)), i))
        except Exception:
            continue
    return found


def node_requires(root: Path) -> dict[str, list[tuple[str, int]]]:
    pat = re.compile(r"""(?:require\(\s*['"]([^'"./][^'"]*)['"]\s*\)|from\s+['"]([^'"./][^'"]*)['"])""")
    found: dict[str, list[tuple[str, int]]] = {}
    for f in _iter_files(root, (".js", ".mjs", ".ts", ".jsx")):
        try:
            for i, line in enumerate(f.read_text(errors="ignore").splitlines(), 1):
                for m in pat.finditer(line):
                    name = m.group(1) or m.group(2)
                    top = name if not name.startswith("@") else "/".join(name.split("/")[:2])
                    top = top.split("/")[0] if not top.startswith("@") else top
                    found.setdefault(top, []).append((str(f.relative_to(root)), i))
        except Exception:
            continue
    return found


def annotate(findings: list[dict]) -> list[dict]:
    cache: dict[str, dict] = {}
    for f in findings:
        svc = SERVICES[f["project"]]
        root = Path(svc["path"])
        key = f["project"]
        if key not in cache:
            cache[key] = {"py": python_imports(root), "js": node_requires(root)}
        if f["ecosystem"] == "PyPI":
            hits = []
            for name in _py_import_names(f["package"]):
                hits += cache[key]["py"].get(name, [])
        else:
            hits = cache[key]["js"].get(f["package"], [])
        imported = bool(hits)
        if f["direct"] and imported:
            f["reach"] = "direct+imported"
        elif f["direct"]:
            f["reach"] = "direct"
        else:
            f["reach"] = "transitive"
        f["import_sites"] = [f"{p}:{ln}" for p, ln in hits[:5]]
        if hits:
            f["evidence"].append({"id": f"code:{f['package']}", "source": "code_search", "url": None,
                                  "fact": f"1st-party 코드 {len(hits)}곳에서 import, 예: {f['import_sites'][0]}"})
    return findings
