"""'오늘 고칠 열 건' 보고서. 패키지 단위 조치로 묶고, 재스캔 결과로 소멸 여부를 표시한다."""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import date

from packaging.version import InvalidVersion, Version

from .config import OUT, SERVICES
from .remediate import plan_python
from .score import why


def _v(s):
    try:
        return Version(s)
    except (InvalidVersion, TypeError):
        return None


def vkey(f: dict) -> tuple:
    """버전을 뺀 finding 키. 패치 후에는 버전이 바뀌므로 같은 어드바이저리인지로 소멸을 판정한다."""
    return (f["project"], f["ecosystem"], f["package"], f["vuln_id"])


def fid_key(fid: str) -> tuple:
    proj, eco, pkgver, vuln = fid.split(":", 3)
    return (proj, eco, pkgver.rsplit("@", 1)[0], vuln)


def plan_npm(findings: list[dict], after: list[dict]) -> list[dict]:
    after_ids = {vkey(f) for f in after}
    by_pkg: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for f in findings:
        by_pkg[(f["package"], f["installed"])].append(f)
    actions = []
    for (pkg, installed), fs in by_pkg.items():
        cur = _v(installed)
        fixes = sorted({s for f in fs for s in f.get("fix_versions", []) if _v(s) and cur and _v(s) > cur}, key=_v)
        same_major = [s for s in fixes if _v(s).major == cur.major] if cur else []
        # 모든 finding을 해결하는 최소 버전
        need = []
        for f in fs:
            c = [s for s in f.get("fix_versions", []) if _v(s) and cur and _v(s) > cur]
            need.append(min(c, key=_v) if c else None)
        target_all = max((s for s in need if s), key=_v, default=None)
        in_major = target_all if (target_all and cur and _v(target_all).major == cur.major) else (max(same_major, key=_v) if same_major else None)
        resolved_by_rescan = [f["finding_id"] for f in fs if vkey(f) not in after_ids]
        major_flag = any(f.get("fix_is_major") for f in fs)
        actions.append({
            "project": "nodegoat", "ecosystem": "npm", "package": pkg, "installed": installed,
            "target": target_all, "change": ("major" if (target_all and cur and _v(target_all).major != cur.major) else "minor/patch") if target_all else None,
            "in_major_target": in_major,
            "resolves": [f["finding_id"] for f in fs if target_all and any(_v(s) and _v(s) <= _v(target_all) for s in f.get("fix_versions", []))],
            "resolves_count": len(fs) if target_all else 0,
            "resolved_by_nonbreaking_fix": resolved_by_rescan,
            "needs_major": [{"finding_id": f["finding_id"], "cve": f.get("cve")} for f in fs if vkey(f) in after_ids and major_flag],
            "no_fix": [f["finding_id"] for f in fs if not f.get("fix_versions") and not f.get("fix_available")],
            "top_priority": max(f["priority"] for f in fs),
            "max_rank": min(f["rank"] for f in fs),
            "kev": any(f.get("kev") for f in fs),
            "max_epss": max((f.get("epss") or 0) for f in fs),
            "findings": len(fs),
            "direct": any(f["direct"] for f in fs),
            "reach": sorted({f["reach"] for f in fs})[0],
        })
    actions.sort(key=lambda a: -a["top_priority"])
    return actions


def build() -> dict:
    projects = {}
    all_actions = []
    all_findings = []
    for p in ["pygoat", "netbox"]:
        fs = json.loads((OUT / p / "priority.json").read_text())
        after = json.loads((OUT / p / "rescan" / "findings.json").read_text())
        actions = json.loads((OUT / p / "actions.json").read_text())
        after_ids = {vkey(f) for f in after}
        for a in actions:
            a["resolved_by_rescan"] = [fid for fid in a["resolves"] if fid_key(fid) not in after_ids]
            a["direct"] = True
            a["reach"] = sorted({f["reach"] for f in fs if f["package"] == a["package"]})[0]
        projects[p] = _project_stats(p, fs, after, actions)
        all_actions += actions
        all_findings += fs
    fs = json.loads((OUT / "nodegoat" / "priority_prod.json").read_text())
    fs_all = json.loads((OUT / "nodegoat" / "priority.json").read_text())
    after = json.loads((OUT / "nodegoat" / "rescan" / "findings_prod.json").read_text())
    actions = plan_npm(fs, after)
    for a in actions:
        a["resolved_by_rescan"] = a["resolved_by_nonbreaking_fix"]
    (OUT / "nodegoat" / "actions.json").write_text(json.dumps(actions, ensure_ascii=False, indent=1))
    projects["nodegoat"] = _project_stats("nodegoat", fs, after, actions, extra={"findings_all_deps": len(fs_all)})
    all_actions += actions
    all_findings += fs

    all_actions.sort(key=lambda a: -a["top_priority"])
    today = all_actions[:10]
    rows = []
    for i, a in enumerate(today, 1):
        top = next(f for f in all_findings if f["finding_id"] in a["resolves"]) if a["resolves"] else \
            next(f for f in all_findings if f["project"] == a["project"] and f["package"] == a["package"] and f["installed"] == a["installed"])
        if a.get("target") and a["resolved_by_rescan"] and len(a["resolved_by_rescan"]) >= a["resolves_count"] * 0.5:
            status = "재스캔 소멸 확인"
        elif a.get("target") and a["change"] and "major" in a["change"]:
            status = "메이저 업그레이드 필요"
        elif a.get("target"):
            status = "패치 적용 대기"
        else:
            status = "완화책 필요"
        rows.append({
            "no": i, "service": SERVICES[a["project"]]["name"], "owner": SERVICES[a["project"]]["owner"],
            "package": a["package"], "installed": a["installed"], "target": a.get("target"), "change": a.get("change"),
            "resolves_count": a["resolves_count"], "findings": a["findings"], "kev": a["kev"], "max_epss": round(a["max_epss"], 3),
            "top_cve": top.get("cve"), "top_cvss": top.get("cvss_score"), "reach": a.get("reach"),
            "priority": a["top_priority"], "why": why(top), "status": status,
            "resolved_by_rescan": len(a["resolved_by_rescan"]),
        })
    report = {
        "date": date.today().isoformat(),
        "projects": projects,
        "totals": {
            "findings": sum(v["findings"] for v in projects.values()),
            "findings_all_deps_nodegoat": projects["nodegoat"]["findings_all_deps"],
            "actions_total": len(all_actions),
            "today": len(today),
            "kev": sum(v["kev"] for v in projects.values()),
            "epss_ge_0_1": sum(v["epss_ge_0_1"] for v in projects.values()),
            "critical_high": sum(v["critical_high"] for v in projects.values()),
            "after": sum(v["after"] for v in projects.values()),
            "top10_resolved": {p: v["top10_resolved"] for p, v in projects.items()},
        },
        "today": rows,
    }
    (OUT / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=1))
    (OUT / "report.md").write_text(render_md(report))
    return report


def _project_stats(p, fs, after, actions, extra=None):
    after_ids = {vkey(f) for f in after}
    sev = defaultdict(int)
    for f in fs:
        sev[f.get("severity") or "NONE"] += 1
    sbom = json.loads((OUT / p / "sbom.cdx.json").read_text())
    d = {
        "service": SERVICES[p]["name"], "description": SERVICES[p]["description"],
        "sbom_components": len(sbom.get("components", [])),
        "findings": len(fs), "packages": len({f["package"] for f in fs}),
        "severity": dict(sev),
        "critical_high": sev.get("CRITICAL", 0) + sev.get("HIGH", 0),
        "epss_ge_0_1": sum(1 for f in fs if (f.get("epss") or 0) >= 0.1),
        "kev": sum(1 for f in fs if f.get("kev")),
        "p_ge_50": sum(1 for f in fs if f["priority"] >= 50),
        "after": len(after),
        "top10_resolved": sum(1 for f in fs[:10] if vkey(f) not in after_ids),
        "actions_with_target": sum(1 for a in actions if a.get("target")),
        "findings_all_deps": len(fs),
    }
    if extra:
        d.update(extra)
    return d


def render_md(r: dict) -> str:
    L = [f"# 오늘 고칠 열 건 — {r['date']}", ""]
    t = r["totals"]
    L.append(f"스캔 결과 {t['findings']}건을 조치 {t['actions_total']}건으로 묶고, 그중 오늘 처리할 {t['today']}건을 골랐다. "
             f"KEV {t['kev']}건, EPSS 0.1 이상 {t['epss_ge_0_1']}건, CRITICAL·HIGH {t['critical_high']}건.")
    L.append("")
    L.append("| # | 서비스 | 패키지 | 현재 → 목표 | 변경 | 해결 | 근거 | 상태 |")
    L.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for x in r["today"]:
        L.append(f"| {x['no']} | {x['service']} | {x['package']} | {x['installed']} → {x['target'] or '없음'} | {x['change'] or '-'} | "
                 f"{x['resolves_count']}/{x['findings']} | {x['why']} | {x['status']} |")
    L.append("")
    for p, v in r["projects"].items():
        L.append(f"## {v['service']} — {v['description']}")
        L.append(f"SBOM 컴포넌트 {v['sbom_components']}개, 취약점 {v['findings']}건/{v['packages']}패키지, CRITICAL·HIGH {v['critical_high']}건, "
                 f"EPSS≥0.1 {v['epss_ge_0_1']}건, KEV {v['kev']}건, 우선순위 50점 이상 {v['p_ge_50']}건. 패치 후 재스캔 {v['after']}건, 상위 10건 소멸 {v['top10_resolved']}/10.")
        L.append("")
    return "\n".join(L)


if __name__ == "__main__":
    r = build()
    print(json.dumps(r["totals"], ensure_ascii=False, indent=1))
    for x in r["today"]:
        print(f"{x['no']:2d} {x['service']:16s} {x['package']}@{x['installed']} → {x['target']} [{x['change']}] {x['resolves_count']}/{x['findings']} {x['status']} | KEV={x['kev']} EPSS={x['max_epss']}")
