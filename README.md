# 트리아지 — SW 공급망 스캐닝 AI 에이전트

수천 개의 경고 가운데 오늘 고쳐야 할 열 개를 골라, 조치와 검증까지 이어 주는 에이전트입니다.
롯데 AX 챌린지 2026 예선, 롯데이노베이트 과제 「SW 공급망 스캐닝 AI 에이전트 기획」 포트폴리오로 만들었습니다.

## 무엇을 하나

| 층 | 하는 일 | 쓰는 도구 |
| --- | --- | --- |
| 연결 | SBOM, 스캔 결과, 서비스 정보를 하나의 finding 스키마로 묶는다 | Syft, pip-audit, npm audit |
| 우선순위 | KEV 최상위, EPSS·CVSS·도달성·노출면·중요도·패치 가용성 가중합으로 정렬 | OSV.dev, FIRST EPSS, CISA KEV, code_search |
| 조치 | 패키지별 최소 변경 패치 버전 결정, 조치안과 PR 초안 작성 | OpenAI function calling, JSON 스키마, 근거 검증기 |
| 검증 | 사본에 적용 후 재스캔으로 소멸 확인, 예상과 실제의 차이를 기록 | pip-audit, npm audit 재실행 |

우선순위 점수는 규칙이 냅니다. 언어 모델은 점수를 만들지 않고, 어드바이저리 해석과 조치안 문장을 맡으며 문장마다 근거 id를 달아야 합니다.

```
P = 100·1[KEV] + 40·EPSS + 20·CVSS/10 + 15·R + 10·X + 10·C + 5·F
```

## 실행 순서

```
pip install pip-audit cvss packaging openai playwright
# Node.js와 npm이 필요하다. NodeGoat 감사와 수정에 쓴다
# Syft 바이너리를 bin/syft 에 둔다 (https://github.com/anchore/syft/releases)
# data/kev.json  ← https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
# data/epss.csv  ← https://epss.cyentia.com/epss_scores-current.csv.gz 를 풀어서 둔다
# targets/ 에 대상 프로젝트를 클론한다 (아래 참고)

python -m triage.scan        # Syft SBOM 생성, pip-audit · npm audit 실행과 정규화 → out/<project>/sbom.cdx.json, findings_raw.json
python -m triage.enrich      # OSV · EPSS · KEV 보강 → findings_enriched.json
python -m triage.prioritize  # 도달성 확인과 규칙 점수로 정렬 → priority.json, NodeGoat는 운영 의존성 기준 priority_prod.json도
python -m triage.remediate   # priority.json을 바탕으로 패치 버전 결정, 사본 적용, 재스캔 → actions.json, rescan/
python -m triage.report      # out/report.md, out/report.json — 오늘 고칠 열 건
python -m triage.agent       # out/remediations.json — 조치안. OPENAI_API_KEY 가 없으면 --dry-run 규칙 기반 초안
python portfolio/build_portfolio.py   # 포트폴리오 PDF
```

도달성과 점수는 `triage.reach`, `triage.score` 에 있고 `triage.prioritize` 가 둘을 묶어 실행합니다. 점수 근거 문장을 만드는 `score.why` 는 `triage.report` 도 씁니다.

저장소의 out/ 은 2026-10-28 실행 결과입니다. 아래 버전의 대상 프로젝트와 2026-10-27 일자 EPSS 파일 `epss_scores-2026-10-27.csv.gz` 를 쓰면, 저장된 감사 결과에서 scan · enrich · prioritize · report를 다시 돌려도 보고서 날짜 한 줄을 빼고 같은 파일이 나옵니다.

## 대상 프로젝트

- OWASP PyGoat — https://github.com/adeyosemanputra/pygoat · main 브랜치 2026-10-22 커밋 46fef968f3f4
- NetBox v3.0.0 — https://github.com/netbox-community/netbox · tag v3.0.0, 커밋 fd16c47d2e1d
- OWASP NodeGoat — https://github.com/OWASP/NodeGoat · main 브랜치 커밋 c5cb68a7084e

```
git clone https://github.com/adeyosemanputra/pygoat targets/pygoat && git -C targets/pygoat checkout 46fef968f3f4
git clone --depth 1 --branch v3.0.0 https://github.com/netbox-community/netbox targets/netbox
git clone https://github.com/OWASP/NodeGoat targets/NodeGoat && git -C targets/NodeGoat checkout c5cb68a7084e
```

## 실측 결과 요약 (2026-10-28)

- SBOM 컴포넌트 1,898개, 취약점 661건. 운영 의존성 기준 384건 중 CVSS CRITICAL·HIGH 220건, EPSS 0.1 이상 20건, KEV 등재 1건.
- 조치 65건으로 묶고 오늘 고칠 10건을 선정. 최소 변경 패치 후 재스캔: 상위 10건 소멸 pygoat 9건, netbox 8건, nodegoat 4건.
- NetBox의 Pillow 8.3.1을 10.0.1로 올리자 10.x 범위의 새 어드바이저리 6건이 재스캔에서 잡혔다. 검증 루프가 필요한 이유.

## 한계와 가정

- 서비스 인벤토리(`triage/config.py` 의 SERVICES)의 노출면·중요도·담당은 데모용 가정값이다.
- 도달성은 패키지 수준 import 확인까지만 구현했다. 함수 수준 호출 확인은 본선에서 추가한다.
- Python은 고정 핀만 감사했고, 전이 의존성은 npm 쪽에서만 다뤘다.
- 조치안은 OPENAI_API_KEY 없이 규칙 기반 초안으로 생성했다. 같은 도구와 스키마로 모델 실행본을 만들 수 있다.
