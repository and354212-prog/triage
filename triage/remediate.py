"""조치: 패키지별 최소 변경 패치 버전을 정하고, 사본에 적용한 뒤, 재스캔으로 소멸을 확인한다."""
from __future__ import annotations

import json
import shutil
import subprocess
from collections import defaultdict
from pathlib import Path

from packaging.version import InvalidVersion, Version

from .config import OUT, SERVICES
from .scan import normalize_npm_audit, normalize_pip_audit, run_npm_audit, run_pip_audit


def _v(s: str):
    try:
        return Version(s)
    except InvalidVersion:
        return None


def plan_python(findings: list[dict]) -> list[dict]:
    """프로젝트 하나의 PyPI finding을 패키지별 조치로 묶는다."""
    by_pkg: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for f in findings:
        if f["ecosystem"] == "PyPI":
            by_pkg[(f["package"], f["installed"])].append(f)
    actions = []
    for (pkg, installed), fs in by_pkg.items():
        cur = _v(installed)
        in_major_targets, major_only, no_fix = [], [], []
        for f in fs:
            fixes = [x for x in (( _v(s), s) for s in f.get("fix_versions", [])) if x[0] and cur and x[0] > cur]
            same_major = [s for v, s in fixes if v.major == cur.major]
            if same_major:
                in_major_targets.append(min(same_major, key=lambda s: _v(s)))
            elif fixes:
                major_only.append((f, min((s for v, s in fixes), key=lambda s: _v(s))))
            else:
                no_fix.append(f)
        target = max(in_major_targets, key=lambda s: _v(s)) if in_major_targets else None
        change = "minor/patch" if target else None
        # KEV 규칙: 악용 확인 취약점은 최소 변경 원칙보다 우선한다. 메이저 업그레이드라도 그 수정을 포함한다.
        kev_fixes = [min((s for s in f.get("fix_versions", []) if _v(s) and cur and _v(s) > cur), key=lambda s: _v(s), default=None)
                     for f in fs if f.get("kev")]
        kev_fixes = [s for s in kev_fixes if s]
        if kev_fixes:
            kev_target = max(kev_fixes, key=lambda s: _v(s))
            if not target or _v(kev_target) > _v(target):
                target, change = kev_target, "major · KEV 규칙"
        resolved = [f for f in fs if target and any(_v(s) and _v(s) <= _v(target) for s in f.get("fix_versions", []))]
        actions.append({
            "project": fs[0]["project"], "ecosystem": "PyPI", "package": pkg, "installed": installed,
            "target": target, "change": change,
            "resolves": [f["finding_id"] for f in resolved],
            "resolves_count": len(resolved),
            "needs_major": [{"finding_id": f["finding_id"], "cve": f.get("cve"), "min_fix": s} for f, s in major_only
                            if not (target and _v(s) and _v(s) <= _v(target))],
            "no_fix": [f["finding_id"] for f in no_fix],
            "top_priority": max(f["priority"] for f in fs),
            "max_rank": min(f["rank"] for f in fs),
            "kev": any(f.get("kev") for f in fs),
            "max_epss": max((f.get("epss") or 0) for f in fs),
            "findings": len(fs),
        })
    actions.sort(key=lambda a: -a["top_priority"])
    return actions


def apply_python(project: str, actions: list[dict]) -> Path:
    svc = SERVICES[project]
    src = Path(svc["path"]) / "requirements.txt"
    dst_dir = OUT / project / "patched"
    dst_dir.mkdir(parents=True, exist_ok=True)
    targets = {a["package"]: a["target"] for a in actions if a.get("target")}
    lines = []
    for line in src.read_text().splitlines():
        s = line.strip()
        if s and not s.startswith("#") and "==" in s:
            name, _ = s.split("==", 1)
            key = name.strip().lower().replace("_", "-")
            if key in targets:
                lines.append(f"{name.strip()}=={targets[key]}")
                continue
        lines.append(line)
    (dst_dir / "requirements.txt").write_text("\n".join(lines) + "\n")
    return dst_dir / "requirements.txt"


def rescan_python(project: str, patched_req: Path) -> list[dict]:
    out = OUT / project / "rescan" / "pip_audit.json"
    run_pip_audit(patched_req, out)
    return normalize_pip_audit(project, out, patched_req)


def plan_and_apply_npm(project: str) -> dict:
    """npm audit fix(비파괴적 변경만)를 사본에 적용하고 재감사한다. 메이저 변경이 필요한 건은 분리 보고."""
    svc = SERVICES[project]
    dst = OUT / project / "patched"
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(svc["path"], dst, ignore=shutil.ignore_patterns("node_modules", ".git"))
    fix = subprocess.run(["npm", "audit", "fix", "--package-lock-only", "--ignore-scripts", "--json"],
                         cwd=dst, capture_output=True, text=True)
    (OUT / project / "npm_audit_fix.json").write_text(fix.stdout)
    out = OUT / project / "rescan" / "npm_audit.json"
    run_npm_audit(dst, out)
    after = normalize_npm_audit(project, out, dst)
    before_meta = json.loads((OUT / project / "npm_audit.json").read_text()).get("metadata", {}).get("vulnerabilities", {})
    after_meta = json.loads(out.read_text()).get("metadata", {}).get("vulnerabilities", {})
    return {"fix_stdout": fix.stdout[:2000], "before_meta": before_meta, "after_meta": after_meta, "after_findings": after}


if __name__ == "__main__":
    summary = {}
    for p in ["pygoat", "netbox"]:
        fs = json.loads((OUT / p / "priority.json").read_text())
        actions = plan_python(fs)
        req = apply_python(p, actions)
        after = rescan_python(p, req)
        (OUT / p / "actions.json").write_text(json.dumps(actions, ensure_ascii=False, indent=1))
        (OUT / p / "rescan" / "findings.json").write_text(json.dumps(after, ensure_ascii=False, indent=1))
        before_ids = {f["finding_id"] for f in fs}
        after_ids = {f["finding_id"] for f in after}
        summary[p] = {"before": len(fs), "after": len(after), "actions": len([a for a in actions if a["target"]]),
                      "needs_major": sum(len(a["needs_major"]) for a in actions),
                      "no_fix": sum(len(a["no_fix"]) for a in actions)}
        print(p, summary[p])
        for a in actions[:6]:
            print(f"   {a['package']} {a['installed']} -> {a['target']} resolves {a['resolves_count']}/{a['findings']} major-only {len(a['needs_major'])} nofix {len(a['no_fix'])}")
    r = plan_and_apply_npm("nodegoat")
    print("nodegoat", r["before_meta"], "->", r["after_meta"], "findings after:", len(r["after_findings"]))
    summary["nodegoat"] = {"before_meta": r["before_meta"], "after_meta": r["after_meta"], "after_findings": len(r["after_findings"])}
    (OUT / "remediation_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1))
