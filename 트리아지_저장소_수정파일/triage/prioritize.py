"""우선순위 단계. 보강된 finding에 도달성을 붙이고 규칙 점수로 줄을 세워 priority.json을 만든다.

- 입력  out/<project>/findings_enriched.json  ← python -m triage.enrich
- 출력  out/<project>/priority.json            → remediate, report, agent가 읽는다
- npm 프로젝트는 운영 의존성만 감사한 결과 npm audit --omit=dev 로 priority_prod.json도 만든다.
  devDependencies는 배포물에 들어가지 않으므로 오늘 고칠 목록은 운영 의존성 기준으로 고른다.

점수는 triage.score의 규칙이 내고, 이 단계에서 언어 모델은 쓰지 않는다.

실행:  python -m triage.prioritize [pygoat netbox nodegoat]
"""
from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

from .config import OUT, SERVICES
from .reach import annotate
from .scan import normalize_npm_audit
from .score import rank

# 감사 범위에 따라 값이 달라지는 필드. 운영 의존성만 감사하면 메이저 업그레이드 필요 여부와 영향 범위가 달라질 수 있다.
# 패치 존재 여부 fix_available은 enrich가 OSV 어드바이저리 기준으로 정한 값이라 범위와 무관하게 그대로 둔다.
AUDIT_SCOPE_FIELDS = ("fix_is_major", "vulnerable_range")


def run_npm_audit_prod(project_dir: Path, out: Path) -> Path:
    """운영 의존성만 감사한다. 결과 JSON을 out에 저장한다."""
    out.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(["npm", "audit", "--omit=dev", "--json"], cwd=project_dir, capture_output=True, text=True)
    out.write_text(r.stdout)
    return out


def prioritize(findings: list[dict]) -> list[dict]:
    """도달성 확인 → 규칙 점수 → 정렬. 순위가 매겨진 목록을 돌려준다."""
    return rank(annotate(findings))


def production_view(project: str, ranked: list[dict], audit_json: Path, project_dir: Path) -> list[dict]:
    """전체 감사로 매긴 결과에서 운영 의존성 감사에 나온 항목만 남기고 다시 줄 세운다.

    보강·도달성·근거는 전체 결과를 그대로 쓰고, 감사 범위에 따라 달라지는 필드만 운영 의존성 감사 값으로 바꾼다.
    """
    prod_raw = {r["finding_id"]: r for r in normalize_npm_audit(project, audit_json, project_dir)}
    prod = []
    for f in ranked:
        r = prod_raw.pop(f["finding_id"], None)
        if r is None:
            continue
        g = copy.deepcopy(f)
        for k in AUDIT_SCOPE_FIELDS:
            g[k] = r[k]
        prod.append(g)
    if prod_raw:  # 전체 감사에 없던 항목은 보강과 도달성부터 다시 한다
        from .enrich import enrich
        prod += annotate(enrich(list(prod_raw.values())))
    return rank(prod)


def _summary(fs: list[dict]) -> str:
    top = fs[0] if fs else None
    kev = sum(1 for f in fs if f.get("kev"))
    head = f"1위 {top['package']} {top['vuln_id']} P={top['priority']}" if top else "finding 없음"
    return f"{len(fs)}건 · KEV {kev}건 · {head}"


def main(projects: list[str]) -> None:
    for p in projects:
        svc = SERVICES[p]
        fs = json.loads((OUT / p / "findings_enriched.json").read_text())
        ranked = prioritize(fs)
        (OUT / p / "priority.json").write_text(json.dumps(ranked, ensure_ascii=False, indent=1))
        print(f"{p}: {_summary(ranked)}")
        if "npm" in svc["ecosystems"]:
            audit = OUT / p / "npm_audit_prod.json"
            if not audit.exists():
                run_npm_audit_prod(Path(svc["path"]), audit)
            prod = production_view(p, ranked, audit, Path(svc["path"]))
            (OUT / p / "priority_prod.json").write_text(json.dumps(prod, ensure_ascii=False, indent=1))
            print(f"{p} 운영 의존성: {_summary(prod)}")


if __name__ == "__main__":
    main(sys.argv[1:] or list(SERVICES))
