"""조치안 작성 에이전트. 사실과 점수는 도구가, 해석과 문장은 모델이 맡는다.

- OpenAI Responses API 함수 호출(function calling)로 동작한다. OPENAI_API_KEY 가 없으면 --dry-run 으로
  규칙 기반 초안을 만든다(초안에는 '규칙 기반'이라고 표시된다).
- 모델 출력은 JSON 스키마로 강제하고, 근거 문장마다 evidence_ids 를 요구한다. 도구가 돌려준 적 없는
  근거 id가 섞이면 검증기가 반려한다 → 환각이 조치안에 들어오지 못한다.

실행:  python -m triage.agent --top 10 [--dry-run] [--model gpt-4.1]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import urllib.request
from pathlib import Path

from .config import OUT, SERVICES

# ---------- 도구 (모든 사실의 출처) ----------

class Tools:
    def __init__(self):
        self.evidence: dict[str, dict] = {}
        self.actions = {}
        self.findings = {}
        for p in SERVICES:
            fs_path = OUT / p / ("priority_prod.json" if p == "nodegoat" else "priority.json")
            for f in json.loads(fs_path.read_text()):
                self.findings[f["finding_id"]] = f
            for a in json.loads((OUT / p / "actions.json").read_text()):
                a_id = f"{p}:{a['package']}@{a['installed']}"
                self.actions[a_id] = a
        self.rescan = {}
        for p in SERVICES:
            path = OUT / p / "rescan" / ("findings_prod.json" if p == "nodegoat" else "findings.json")
            self.rescan[p] = {(f["package"], f["vuln_id"]) for f in json.loads(path.read_text())}

    def _ev(self, eid: str, source: str, fact: str, url: str | None = None) -> dict:
        self.evidence[eid] = {"id": eid, "source": source, "fact": fact, "url": url}
        return self.evidence[eid]

    def get_action(self, action_id: str) -> dict:
        a = self.actions[action_id]
        out = {k: a[k] for k in ("project", "package", "installed", "target", "change", "resolves_count", "findings", "kev", "max_epss")}
        out["service"] = SERVICES[a["project"]]
        out["service"] = {k: v for k, v in out["service"].items() if k != "path"}
        out["finding_ids"] = a["resolves"][:10]
        out["needs_major"] = a.get("needs_major", [])[:10]
        out["no_fix"] = a.get("no_fix", [])[:10]
        self._ev(f"action:{action_id}", "triage.remediate", f"{a['package']} {a['installed']} → {a['target']} ({a['change']}), 해결 {a['resolves_count']}/{a['findings']}")
        return out

    def get_finding(self, finding_id: str) -> dict:
        f = self.findings[finding_id]
        for e in f.get("evidence", []):
            self._ev(e["id"], e["source"], e["fact"], e.get("url"))
        keys = ("package", "installed", "vuln_id", "cve", "cvss_score", "severity", "epss", "epss_percentile", "kev", "reach",
                "import_sites", "fix_versions", "summary", "details", "references", "priority", "rank")
        return {k: f.get(k) for k in keys} | {"evidence_ids": [e["id"] for e in f.get("evidence", [])]}

    def code_search(self, project: str, pattern: str, max_hits: int = 10) -> dict:
        root = Path(SERVICES[project]["path"])
        r = subprocess.run(["grep", "-rnI", "--exclude-dir=node_modules", "--exclude-dir=.git", "--exclude-dir=Solutions", "-E", pattern, str(root)],
                           capture_output=True, text=True)
        hits = [line.replace(str(root) + "/", "") for line in r.stdout.splitlines()[:max_hits]]
        eid = f"code:{project}:{re.sub(r'[^A-Za-z0-9_]+', '_', pattern)[:40]}"
        self._ev(eid, "code_search", f"'{pattern}' {len(r.stdout.splitlines())}건, 예 {hits[0] if hits else '없음'}")
        return {"evidence_id": eid, "count": len(r.stdout.splitlines()), "hits": hits}

    def release_info(self, ecosystem: str, package: str, version: str) -> dict:
        """패키지 저장소 메타데이터(릴리스 일자, 변경 이력 링크). 레지스트리 API만 쓴다."""
        try:
            if ecosystem == "PyPI":
                with urllib.request.urlopen(f"https://pypi.org/pypi/{package}/{version}/json", timeout=20) as r:
                    d = json.loads(r.read().decode())
                info = d.get("info", {})
                urls = info.get("project_urls") or {}
                change = next((v for k, v in urls.items() if "change" in k.lower() or "release" in k.lower()), None)
                uploaded = (d.get("urls") or [{}])[0].get("upload_time", "")[:10]
                out = {"version": version, "released": uploaded, "requires_python": info.get("requires_python"), "changelog": change,
                       "homepage": info.get("home_page") or urls.get("Homepage")}
            else:
                with urllib.request.urlopen(f"https://registry.npmjs.org/{package}/{version}", timeout=20) as r:
                    d = json.loads(r.read().decode())
                out = {"version": version, "deprecated": d.get("deprecated"), "engines": d.get("engines"),
                       "homepage": d.get("homepage"), "repository": (d.get("repository") or {}).get("url")}
        except Exception as e:
            out = {"version": version, "error": str(e)}
        eid = f"release:{ecosystem}:{package}@{version}"
        self._ev(eid, "registry", json.dumps(out, ensure_ascii=False)[:200])
        out["evidence_id"] = eid
        return out

    def rescan_status(self, action_id: str) -> dict:
        a = self.actions[action_id]
        p = a["project"]
        left = [fid for fid in a["resolves"] if (a["package"], fid.rsplit(":", 1)[1]) in self.rescan[p]]
        gone = len(a["resolves"]) - len(left)
        eid = f"rescan:{action_id}"
        self._ev(eid, "rescan", f"목표 버전 적용 후 재스캔: 예상 {len(a['resolves'])}건 중 {gone}건 소멸, 잔존 {len(left)}건")
        return {"evidence_id": eid, "expected": len(a["resolves"]), "gone": gone, "left": left[:10]}


TOOL_SPECS = [
    {"type": "function", "name": "get_action", "description": "패키지 단위 조치 후보와 서비스 정보를 가져온다.",
     "parameters": {"type": "object", "properties": {"action_id": {"type": "string"}}, "required": ["action_id"]}},
    {"type": "function", "name": "get_finding", "description": "취약점 finding 하나의 사실(CVSS, EPSS, KEV, 도달성, 패치 버전)과 근거 id를 가져온다.",
     "parameters": {"type": "object", "properties": {"finding_id": {"type": "string"}}, "required": ["finding_id"]}},
    {"type": "function", "name": "code_search", "description": "1st-party 코드에서 정규식을 검색해 취약 API 사용 여부를 확인한다.",
     "parameters": {"type": "object", "properties": {"project": {"type": "string"}, "pattern": {"type": "string"}}, "required": ["project", "pattern"]}},
    {"type": "function", "name": "release_info", "description": "패키지 저장소에서 목표 버전의 릴리스 정보와 변경 이력 링크를 가져온다.",
     "parameters": {"type": "object", "properties": {"ecosystem": {"type": "string"}, "package": {"type": "string"}, "version": {"type": "string"}}, "required": ["ecosystem", "package", "version"]}},
    {"type": "function", "name": "rescan_status", "description": "목표 버전을 사본에 적용해 재스캔한 결과(소멸/잔존)를 가져온다.",
     "parameters": {"type": "object", "properties": {"action_id": {"type": "string"}}, "required": ["action_id"]}},
]

OUTPUT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "action_id": {"type": "string"},
        "decision": {"type": "string", "enum": ["upgrade", "major_upgrade", "mitigate", "accept_risk"]},
        "target_version": {"type": ["string", "null"]},
        "rationale": {"type": "array", "items": {"type": "object", "additionalProperties": False,
                                                 "properties": {"text": {"type": "string"}, "evidence_ids": {"type": "array", "items": {"type": "string"}}},
                                                 "required": ["text", "evidence_ids"]}},
        "compatibility_risk": {"type": "object", "additionalProperties": False,
                               "properties": {"level": {"type": "string", "enum": ["low", "medium", "high"]}, "notes": {"type": "string"},
                                              "evidence_ids": {"type": "array", "items": {"type": "string"}}},
                               "required": ["level", "notes", "evidence_ids"]},
        "mitigation": {"type": ["string", "null"]},
        "pr": {"type": "object", "additionalProperties": False,
               "properties": {"title": {"type": "string"}, "body": {"type": "string"}}, "required": ["title", "body"]},
        "owner": {"type": "string"},
        "estimated_effort": {"type": "string", "enum": ["1시간 이내", "반나절", "하루", "며칠"]},
    },
    "required": ["action_id", "decision", "target_version", "rationale", "compatibility_risk", "mitigation", "pr", "owner", "estimated_effort"],
}

SYSTEM = """너는 SW 공급망 취약점 조치 담당 에이전트 '트리아지'다.
규칙:
1. 사실은 도구 결과에서만 가져온다. 도구가 말하지 않은 수치, 버전, 날짜를 쓰지 않는다.
2. rationale의 모든 항목에 그 사실을 준 evidence_ids 를 적는다. 근거 없는 문장은 쓰지 않는다.
3. 최소 변경 원칙: 같은 메이저 안의 패치를 먼저 제안한다. 단, KEV 등재 취약점은 메이저 업그레이드라도 수정 버전을 포함한다.
4. 패치가 없으면 완화책(설정 변경, 입력 검증, 기능 비활성화, 대체 패키지)을 제안하고 decision=mitigate 로 둔다.
5. 병합과 배포는 사람이 한다. 너는 조치안과 PR 초안까지만 만든다.
6. 한국어로 쓴다. 괄호를 쓰지 않는다."""


def validate(out: dict, evidence: dict[str, dict]) -> list[str]:
    """근거 검증기: 도구가 돌려준 적 없는 evidence id → 반려 사유."""
    errors = []
    for i, r in enumerate(out.get("rationale", [])):
        if not r.get("evidence_ids"):
            errors.append(f"rationale[{i}] 근거 없음: {r.get('text', '')[:60]}")
        for eid in r.get("evidence_ids", []):
            if eid not in evidence:
                errors.append(f"rationale[{i}] 알 수 없는 근거 id {eid}")
    for eid in out.get("compatibility_risk", {}).get("evidence_ids", []):
        if eid not in evidence:
            errors.append(f"compatibility_risk 알 수 없는 근거 id {eid}")
    return errors


def run_llm(action_id: str, tools: Tools, model: str) -> dict:
    from openai import OpenAI
    client = OpenAI()
    input_items = [{"role": "user", "content": f"조치 후보 {action_id} 에 대한 조치안을 만들어라. 먼저 get_action, 상위 finding 몇 개의 get_finding, "
                                                 f"필요하면 code_search 와 release_info, 마지막에 rescan_status 를 호출한 뒤 결과를 JSON으로 내라."}]
    resp = client.responses.create(model=model, instructions=SYSTEM, input=input_items, tools=TOOL_SPECS,
                                   text={"format": {"type": "json_schema", "name": "remediation", "schema": OUTPUT_SCHEMA, "strict": True}})
    for _ in range(12):
        calls = [item for item in resp.output if item.type == "function_call"]
        if not calls:
            break
        input_items += resp.output
        for call in calls:
            args = json.loads(call.arguments or "{}")
            result = getattr(tools, call.name)(**args)
            input_items.append({"type": "function_call_output", "call_id": call.call_id, "output": json.dumps(result, ensure_ascii=False)})
        resp = client.responses.create(model=model, instructions=SYSTEM, input=input_items, tools=TOOL_SPECS,
                                       text={"format": {"type": "json_schema", "name": "remediation", "schema": OUTPUT_SCHEMA, "strict": True}})
    out = json.loads(resp.output_text)
    errors = validate(out, tools.evidence)
    if errors:  # 한 번 더 기회: 반려 사유를 돌려주고 고치게 한다
        input_items += resp.output
        input_items.append({"role": "user", "content": "검증기 반려: " + "; ".join(errors) + ". 도구 결과에 있는 근거 id만 써서 다시 내라."})
        resp = client.responses.create(model=model, instructions=SYSTEM, input=input_items, tools=TOOL_SPECS,
                                       text={"format": {"type": "json_schema", "name": "remediation", "schema": OUTPUT_SCHEMA, "strict": True}})
        out = json.loads(resp.output_text)
        errors = validate(out, tools.evidence)
    out["_validation"] = {"ok": not errors, "errors": errors, "mode": f"llm:{model}"}
    return out


def run_dry(action_id: str, tools: Tools) -> dict:
    """규칙 기반 초안. 모델 없이 도구 결과만으로 같은 스키마를 채운다."""
    a = tools.get_action(action_id)
    top = [tools.get_finding(fid) for fid in a["finding_ids"][:3]]
    rs = tools.rescan_status(action_id)
    rel = tools.release_info(a["project"] and ("npm" if action_id.split(":")[0] == "nodegoat" else "PyPI"), a["package"], a["target"]) if a["target"] else None
    rationale = []
    for f in top:
        bits = []
        if f.get("kev"):
            bits.append(f"CISA 악용 확인 목록에 {f['kev']['date_added']} 등재")
        if f.get("epss") is not None:
            bits.append(f"EPSS {f['epss']:.3f}")
        if f.get("cvss_score") is not None:
            bits.append(f"CVSS {f['cvss_score']} {f.get('severity')}")
        rationale.append({"text": f"{f['cve'] or f['vuln_id']}: {f['summary'][:80]} — " + ", ".join(bits) + f", 도달성 {f['reach']}",
                          "evidence_ids": f["evidence_ids"]})
    rationale.append({"text": f"목표 버전 적용 후 재스캔에서 예상 {rs['expected']}건 중 {rs['gone']}건이 소멸했다.", "evidence_ids": [rs["evidence_id"]]})
    major = a["change"] and "major" in a["change"]
    decision = "major_upgrade" if major else ("upgrade" if a["target"] else "mitigate")
    out = {
        "action_id": action_id,
        "decision": decision,
        "target_version": a["target"],
        "rationale": rationale,
        "compatibility_risk": {"level": "medium" if major else "low",
                               "notes": ("메이저 변경이므로 제거된 API 사용 여부를 code_search 로 확인하고 스테이징에서 회귀 테스트 후 병합한다."
                                         if major else "같은 메이저 안의 패치 변경이라 호환성 위험은 낮다. 테스트 통과 후 병합한다."),
                               "evidence_ids": [f"action:{action_id}"] + ([rel["evidence_id"]] if rel else [])},
        "mitigation": None if a["target"] else "패치 버전이 없다. 해당 기능 비활성화, 입력 검증 강화, 대체 패키지 검토를 완화책으로 둔다.",
        "pr": {"title": f"chore: {a['package']} {a['installed']} → {a['target'] or '완화책'} · 취약점 {a['resolves_count']}건 조치",
               "body": f"트리아지가 제안한 조치안입니다.\n\n- 해결 대상 {a['resolves_count']}건 / 해당 패키지 전체 {a['findings']}건\n- 근거: " +
                       "; ".join(r["text"] for r in rationale) + "\n- 병합 전 체크: CI 통과, 스테이징 배포, 재스캔 0건 확인"},
        "owner": a["service"]["owner"],
        "estimated_effort": "하루" if major else "1시간 이내",
    }
    out["_validation"] = {"ok": not validate(out, tools.evidence), "errors": validate(out, tools.evidence), "mode": "dry-run(rule-based)"}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--model", default="gpt-4.1")
    args = ap.parse_args()
    tools = Tools()
    report = json.loads((OUT / "report.json").read_text())
    results = []
    for row in report["today"][: args.top]:
        project = next(p for p, s in SERVICES.items() if s["name"] == row["service"])
        action_id = f"{project}:{row['package']}@{row['installed']}"
        dry = args.dry_run or not os.environ.get("OPENAI_API_KEY")
        out = run_dry(action_id, tools) if dry else run_llm(action_id, tools, args.model)
        results.append(out)
        print(f"{row['no']:2d} {action_id:40s} {out['decision']:14s} → {out['target_version']} | 검증 {'통과' if out['_validation']['ok'] else '반려'} [{out['_validation']['mode']}]")
    (OUT / "remediations.json").write_text(json.dumps({"evidence": tools.evidence, "results": results}, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
