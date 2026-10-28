"""규칙 기반 우선순위 점수. 언어 모델은 이 점수를 만들지 않는다.

P = 100·1[KEV] + w_epss·EPSS + w_cvss·CVSS/10 + w_reach·R + w_expo·X + w_crit·C + w_fix·F
"""
from __future__ import annotations

from .config import CRITICALITY_SCORE, EXPOSURE_SCORE, REACH_SCORE, SERVICES, WEIGHTS


def score(f: dict) -> dict:
    svc = SERVICES[f["project"]]
    kev = 1.0 if f.get("kev") else 0.0
    epss = float(f.get("epss") or 0.0)
    cvss = float(f.get("cvss_score") or 0.0) / 10.0
    r = REACH_SCORE[f.get("reach", "transitive")]
    x = EXPOSURE_SCORE[svc["exposure"]]
    c = CRITICALITY_SCORE[svc["criticality"]]
    fix = 1.0 if f.get("fix_available") else 0.0
    parts = {
        "kev": WEIGHTS["kev"] * kev,
        "epss": WEIGHTS["epss"] * epss,
        "cvss": WEIGHTS["cvss"] * cvss,
        "reach": WEIGHTS["reach"] * r,
        "exposure": WEIGHTS["exposure"] * x,
        "criticality": WEIGHTS["criticality"] * c,
        "fix": WEIGHTS["fix"] * fix,
    }
    f["score_parts"] = {k: round(v, 2) for k, v in parts.items()}
    f["priority"] = round(sum(parts.values()), 2)
    f["service"] = svc["name"]
    f["owner"] = svc["owner"]
    f["exposure"] = svc["exposure"]
    f["criticality"] = svc["criticality"]
    return f


def rank(findings: list[dict]) -> list[dict]:
    for f in findings:
        score(f)
    findings.sort(key=lambda f: (-f["priority"], -(f.get("cvss_score") or 0), f["package"]))
    for i, f in enumerate(findings, 1):
        f["rank"] = i
    return findings


def why(f: dict) -> str:
    """왜 이 순위인지 한 줄. 근거 id를 함께 적는다."""
    bits = []
    if f.get("kev"):
        bits.append(f"CISA 악용 확인 목록 등재 {f['kev']['date_added']} [kev:{f['cve']}]")
    if f.get("epss") is not None:
        bits.append(f"EPSS {f['epss']:.3f} 백분위 {f['epss_percentile']:.2f} [epss:{f['cve']}]")
    if f.get("cvss_score") is not None:
        bits.append(f"CVSS {f['cvss_score']} {f.get('severity')} [osv:{f['vuln_id']}]")
    bits.append({"direct+imported": "직접 의존이며 1st-party 코드에서 import [code]", "direct": "직접 의존", "transitive": "전이 의존"}[f["reach"]])
    bits.append(f"{f['service']} {f['exposure']}/{f['criticality']}")
    bits.append("패치 " + (", ".join(f["fix_versions"][:3]) if f.get("fix_versions") else ("가능" if f.get("fix_available") else "없음")))
    return " · ".join(bits)
