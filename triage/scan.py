"""스캐너 실행과 결과 정규화.

새 스캐너를 만들지 않는다. pip-audit(PyPI/OSV)과 npm audit(npm registry) 출력을 받아
하나의 finding 스키마로 바꾼다. 사내 상용 스캐너도 같은 어댑터 패턴으로 붙인다.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from .config import OUT, SERVICES, SYFT


def run_syft(project: str) -> Path:
    svc = SERVICES[project]
    out = OUT / project / "sbom.cdx.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(SYFT), f"dir:{svc['path']}", "-o", f"cyclonedx-json={out}", "-q"], check=True)
    return out


def run_pip_audit(requirements: Path, out: Path) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    # --no-deps --disable-pip: 고정 핀만 감사, 설치 없음. --desc on: 설명 포함. -s osv: OSV 직접 조회
    cmd = ["pip-audit", "-r", str(requirements), "--no-deps", "--disable-pip", "-f", "json", "-o", str(out),
           "--desc", "on", "-s", "osv", "--progress-spinner", "off"]
    subprocess.run(cmd, check=False, capture_output=True)
    return out


def run_npm_audit(project_dir: Path, out: Path) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(["npm", "audit", "--json"], cwd=project_dir, capture_output=True, text=True)
    out.write_text(r.stdout)
    return out


GHSA_RE = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def _pick_ids(primary: str, aliases: list[str]) -> tuple[str, str | None, str | None]:
    ids = [primary] + list(aliases)
    ghsa = next((i for i in ids if GHSA_RE.fullmatch(i)), None)
    cve = next((i for i in ids if CVE_RE.fullmatch(i)), None)
    vuln_id = ghsa or primary
    return vuln_id, ghsa, cve


def normalize_pip_audit(project: str, path: Path, requirements: Path) -> list[dict]:
    data = json.loads(path.read_text())
    direct_pins = {}
    for line in requirements.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "==" not in line:
            continue
        name, ver = line.split("==", 1)
        direct_pins[name.strip().lower().replace("_", "-")] = ver.strip()

    findings: list[dict] = []
    for dep in data.get("dependencies", []):
        name = dep["name"].lower().replace("_", "-")
        version = dep["version"]
        seen = set()
        for v in dep.get("vulns", []):
            vuln_id, ghsa, cve = _pick_ids(v["id"], v.get("aliases", []))
            key = ghsa or cve or v["id"]
            if key in seen:          # pip-audit는 같은 어드바이저리를 중복 출력하기도 한다
                continue
            seen.add(key)
            findings.append({
                "finding_id": f"{project}:PyPI:{name}@{version}:{vuln_id}",
                "project": project,
                "ecosystem": "PyPI",
                "package": name,
                "installed": version,
                "vuln_id": vuln_id,
                "ghsa": ghsa,
                "cve": cve,
                "aliases": sorted(set([v["id"]] + list(v.get("aliases", [])))),
                "summary": (v.get("description") or "").strip(),
                "fix_versions": v.get("fix_versions", []),
                "direct": name in direct_pins,
                "scanner": "pip-audit 2.10.1 (OSV)",
                "cvss_score": None,
                "cvss_vector": None,
                "severity": None,
                "cwe": [],
            })
    return findings


def _lock_versions(project_dir: Path) -> dict[str, str]:
    lock = json.loads((project_dir / "package-lock.json").read_text())
    versions = {}
    for node_path, info in lock.get("packages", {}).items():
        if node_path:
            versions[node_path] = info.get("version", "")
    return versions


def normalize_npm_audit(project: str, path: Path, project_dir: Path) -> list[dict]:
    data = json.loads(path.read_text())
    lockv = _lock_versions(project_dir)
    findings: list[dict] = []
    seen = set()
    for pkg, entry in data.get("vulnerabilities", {}).items():
        nodes = entry.get("nodes", [])
        installed_versions = sorted({lockv.get(n, "") for n in nodes if lockv.get(n)}) or [entry.get("range", "")]
        for via in entry.get("via", []):
            if not isinstance(via, dict):
                continue  # 문자열 via는 전이 경로 이름일 뿐이다
            url = via.get("url", "")
            ghsa = GHSA_RE.search(url).group(0) if GHSA_RE.search(url) else None
            vuln_id = ghsa or f"NPM-{via.get('source')}"
            for installed in installed_versions:
                key = (pkg, installed, vuln_id)
                if key in seen:
                    continue
                seen.add(key)
                fix = entry.get("fixAvailable")
                findings.append({
                    "finding_id": f"{project}:npm:{pkg}@{installed}:{vuln_id}",
                    "project": project,
                    "ecosystem": "npm",
                    "package": pkg,
                    "installed": installed,
                    "vuln_id": vuln_id,
                    "ghsa": ghsa,
                    "cve": None,                  # npm audit은 CVE를 주지 않는다 → OSV에서 보강
                    "aliases": [vuln_id],
                    "summary": via.get("title", ""),
                    "fix_versions": [],           # OSV에서 보강
                    "fix_available": bool(fix),
                    "fix_is_major": isinstance(fix, dict) and bool(fix.get("isSemVerMajor")),
                    "vulnerable_range": via.get("range"),
                    "direct": bool(entry.get("isDirect")),
                    "scanner": "npm audit 10.9.9 (npm registry)",
                    "cvss_score": (via.get("cvss") or {}).get("score") or None,
                    "cvss_vector": (via.get("cvss") or {}).get("vectorString"),
                    "severity": (via.get("severity") or "").upper() or None,
                    "cwe": via.get("cwe", []),
                })
    return findings


def scan_all(rescan_root: Path | None = None) -> dict[str, list[dict]]:
    """세 프로젝트를 스캔해 정규화한다. rescan_root가 주어지면 패치된 사본을 스캔한다."""
    results: dict[str, list[dict]] = {}
    for project, svc in SERVICES.items():
        base = rescan_root / project if rescan_root else svc["path"]
        outdir = OUT / project / ("rescan" if rescan_root else "")
        if "PyPI" in svc["ecosystems"]:
            req = base / "requirements.txt"
            out = outdir / "pip_audit.json"
            if rescan_root or not out.exists():
                run_pip_audit(req, out)
            results[project] = normalize_pip_audit(project, out, req)
        if "npm" in svc["ecosystems"]:
            out = outdir / "npm_audit.json"
            if rescan_root or not out.exists():
                run_npm_audit(base, out)
            results.setdefault(project, []).extend(normalize_npm_audit(project, out, base))
    return results


if __name__ == "__main__":
    res = scan_all()
    for p, f in res.items():
        print(p, len(f), "findings,", len({x['package'] for x in f}), "packages")
        (OUT / p / "findings_raw.json").write_text(json.dumps(f, ensure_ascii=False, indent=1))
