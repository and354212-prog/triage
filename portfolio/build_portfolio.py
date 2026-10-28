"""포트폴리오 PDF 생성: out/ 의 실측 결과를 HTML로 조판하고 Chromium으로 PDF를 찍는다."""
import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "out"
HERE = Path(__file__).resolve().parent

r = json.loads((OUT / "report.json").read_text())
rem = json.loads((OUT / "remediations.json").read_text())
P = r["projects"]
T = r["totals"]
sb = {p: json.loads((OUT / p / "sbom.cdx.json").read_text()) for p in P}
sbom_total = sum(len(s.get("components", [])) for s in sb.values())
all_deps = P["pygoat"]["findings"] + P["netbox"]["findings"] + T["findings_all_deps_nodegoat"]
prod_total = T["findings"]
top1 = rem["results"][0]
ev = rem["evidence"]


def svg(name):
    return (HERE / name).read_text()


def esc(s):
    return html.escape(str(s))


rows = ""
for x in r["today"]:
    flag = "KEV" if x["kev"] else ""
    rows += f"""<tr>
      <td class="num">{x['no']}</td><td>{esc(x['service'])}<br><span class="dim">{esc(x['owner'])}</span></td>
      <td><b>{esc(x['package'])}</b><br><span class="dim">{esc(x['installed'])} → {esc(x['target'])}</span></td>
      <td>{esc(x['change'])}</td>
      <td class="num">{x['resolves_count']} / {x['findings']}</td>
      <td class="num">{'<span class="kev">KEV</span>' if x['kev'] else ''} {x['max_epss']:.3f}</td>
      <td class="num">{x['top_cvss'] if x['top_cvss'] is not None else '-'}</td>
      <td>{esc({'direct+imported':'직접·import 확인','direct':'직접 의존','transitive':'전이 의존'}[x['reach']])}</td>
      <td class="ok">{esc(x['status'])}<br><span class="dim">재스캔 소멸 {x['resolved_by_rescan']}건</span></td>
    </tr>"""

rationale_html = "".join(
    f"<li>{esc(it['text'])} <span class='evid'>{' '.join('['+esc(e)+']' for e in it['evidence_ids'])}</span></li>"
    for it in top1["rationale"])
evidence_rows = "".join(
    f"<tr><td class='mono'>{esc(eid)}</td><td>{esc(ev[eid]['source'])}</td><td>{esc(ev[eid]['fact'])}</td></tr>"
    for it in top1["rationale"] for eid in it["evidence_ids"] if eid in ev)

proj_rows = "".join(f"""<tr><td><b>{esc(v['service'])}</b><br><span class="dim">{esc(v['description'])}</span></td>
   <td class="num">{v['sbom_components']}</td><td class="num">{v['findings']}{' <span class="dim">· 개발 의존성 포함 '+str(T['findings_all_deps_nodegoat'])+'</span>' if p=='nodegoat' else ''}</td>
   <td class="num">{v['critical_high']} <span class="dim">· {v['critical_high']*100//v['findings']}%</span></td>
   <td class="num">{v['epss_ge_0_1']}</td><td class="num">{v['kev']}</td><td class="num">{v['after']}</td><td class="num">{v['top10_resolved']} / 10</td></tr>"""
                    for p, v in P.items())

page_css = """
@page { size: A4 landscape; margin: 0; }
* { box-sizing: border-box; }
body { margin:0; font-family: 'Noto Sans CJK KR', 'Noto Sans KR', sans-serif; color:#1d2730; }
.page { width:297mm; height:210mm; padding:14mm 16mm 12mm 16mm; page-break-after: always; position:relative; overflow:hidden; background:#fff; }
.page:last-child { page-break-after: auto; }
h1 { font-size:26pt; margin:0 0 6mm 0; line-height:1.25; letter-spacing:-0.3px; }
h2 { font-size:19pt; margin:0 0 4mm 0; line-height:1.3; }
h3 { font-size:12pt; margin:5mm 0 2mm 0; color:#1f6f8b; }
p, li { font-size:10.5pt; line-height:1.55; margin:0 0 2.5mm 0; }
.lead { font-size:12.5pt; color:#2f4858; }
.kicker { font-size:9.5pt; letter-spacing:2px; color:#b4231f; font-weight:700; text-transform:uppercase; margin-bottom:3mm; }
.footer { position:absolute; bottom:7mm; left:16mm; right:16mm; font-size:8.5pt; color:#7a8691; display:flex; justify-content:space-between; border-top:1px solid #e3e8ec; padding-top:2mm; }
.cols { display:flex; gap:10mm; }
.col { flex:1; min-width:0; }
.big { font-size:34pt; font-weight:700; color:#b4231f; line-height:1; }
.big small { font-size:11pt; color:#1d2730; font-weight:400; display:block; margin-top:2mm; }
.stat { background:#f4f7f9; border-left:4px solid #1f6f8b; padding:4mm 5mm; margin-bottom:4mm; }
.stat .v { font-size:22pt; font-weight:700; color:#1f6f8b; line-height:1.1; }
.stat .l { font-size:9.5pt; color:#4a5560; }
table { border-collapse:collapse; width:100%; font-size:9pt; }
th { background:#1d2730; color:#fff; text-align:left; padding:2mm 2.2mm; font-weight:600; font-size:8.6pt; white-space:nowrap; }
td { border-bottom:1px solid #e3e8ec; padding:1.8mm 2.2mm; vertical-align:top; }
td.num { text-align:right; font-variant-numeric: tabular-nums; }
.dim { color:#7a8691; font-size:8.3pt; }
.kev { background:#b4231f; color:#fff; font-size:7.5pt; padding:0.3mm 1.2mm; border-radius:2px; font-weight:700; }
.ok { color:#1f6f8b; font-weight:600; }
.evid { color:#1f6f8b; font-size:8.3pt; font-family: 'DejaVu Sans Mono', monospace; }
.mono { font-family:'DejaVu Sans Mono', monospace; font-size:8.3pt; }
.box { border:1px solid #d7dee4; border-radius:3px; padding:4mm 5mm; background:#fbfcfd; }
.flow { display:flex; align-items:stretch; gap:0; margin:4mm 0; }
.layer { flex:1; background:#f4f7f9; border:1.5px solid #c9d3db; border-radius:4px; padding:3.5mm 4mm; position:relative; }
.layer h4 { margin:0 0 1.5mm 0; font-size:11pt; color:#1d2730; }
.layer .tools { font-size:8.3pt; color:#1f6f8b; font-family:'DejaVu Sans Mono', monospace; margin-top:2mm; }
.layer p { font-size:9.2pt; margin:0; }
.arrow { width:9mm; display:flex; align-items:center; justify-content:center; font-size:20pt; color:#b4231f; }
.tag { display:inline-block; background:#e8f1f5; color:#1f6f8b; font-size:8pt; padding:0.5mm 2mm; border-radius:2px; margin-right:1.5mm; }
.cover { background:#1d2730; color:#fff; }
.cover h1 { font-size:34pt; color:#fff; margin-top:34mm; }
.cover .sub { font-size:14pt; color:#c9d3db; margin-bottom:12mm; }
.cover .meta { position:absolute; bottom:18mm; left:16mm; font-size:11pt; color:#c9d3db; line-height:1.7; }
.cover .brand { position:absolute; top:14mm; left:16mm; font-size:10pt; letter-spacing:3px; color:#f0a35e; font-weight:700; }
.cover .right { position:absolute; right:16mm; bottom:18mm; text-align:right; font-size:10pt; color:#9aa5b1; line-height:1.6; }
svg { max-width:100%; height:auto; }
.chart { width:100%; }
.note { font-size:8.8pt; color:#4a5560; background:#fff7ed; border-left:3px solid #d98b3a; padding:2.5mm 4mm; margin-top:3mm; }
code, pre { font-family:'DejaVu Sans Mono', monospace; }
pre { font-size:7.6pt; line-height:1.4; background:#1d2730; color:#e6edf3; padding:3.5mm 4mm; border-radius:3px; margin:0; white-space:pre-wrap; }
ul { padding-left:5mm; margin:0; }
"""

footer = lambda n: f'<div class="footer"><span>트리아지 — SW 공급망 스캐닝 AI 에이전트 · 롯데 AX 챌린지 2026 예선 포트폴리오 · 김근홍</span><span>{n} / 8</span></div>'

pages = []

# 1 표지
pages.append(f"""<div class="page cover">
<div class="brand">LOTTE AX CHALLENGE 2026 · 롯데이노베이트 과제 · 예선 포트폴리오</div>
<h1>수천 개의 경고 가운데<br>오늘 고쳐야 할 열 개를 골라,<br>조치까지 끝내는 에이전트</h1>
<div class="sub">트리아지 — SBOM과 취약점 스캔 결과를 <b style="color:#f0a35e">조치 가능한 작업 목록</b>으로 바꾸는 SW 공급망 스캐닝 AI 에이전트</div>
<div class="meta">김근홍 · 국립창원대학교 전자공학과<br>공개 오픈소스 프로젝트 3개에 실제 적용 · 2026년 10월 28일 실측</div>
<div class="right">SBOM 컴포넌트 {sbom_total:,}개 · 취약점 {all_deps}건 분석<br>오늘 고칠 조치 10건 도출 · 재스캔으로 소멸 검증<br>데이터: Syft · pip-audit · npm audit · OSV · FIRST EPSS · CISA KEV</div>
</div>""")

# 2 문제
pages.append(f"""<div class="page">
<div class="kicker">문제</div>
<h2>스캐너는 {all_deps}건을 뱉었고, CVSS는 그중 절반을 HIGH 이상이라 불렀다</h2>
<p class="lead">세 공개 프로젝트의 SBOM을 만들고 스캔했다. 결과는 많았고, 점수만으로는 순서가 나오지 않았다. 실제로 악용될 가능성이 높은 것은 극히 일부였다.</p>
<div class="cols">
 <div class="col" style="flex:1.25">{svg('chart_funnel.svg')}</div>
 <div class="col">
  <div class="stat"><div class="v">{T['critical_high']} / {prod_total}</div><div class="l">운영 의존성 취약점 중 CVSS CRITICAL·HIGH. 57%가 높음이면 높음은 순서가 아니다</div></div>
  <div class="stat"><div class="v">{T['epss_ge_0_1']}건</div><div class="l">FIRST EPSS 악용 확률 0.1 이상. 전체의 5%</div></div>
  <div class="stat" style="border-color:#b4231f"><div class="v" style="color:#b4231f">1건</div><div class="l">CISA 악용 확인 목록 KEV 등재 — NetBox의 Pillow 8.3.1, CVE-2023-4863. 수백 건 사이에 묻혀 있었다</div></div>
  <p class="dim">운영 의존성 기준 {prod_total}건. NodeGoat는 개발 의존성까지 포함하면 {T['findings_all_deps_nodegoat']}건이라 전체 {all_deps}건이다.</p>
 </div>
</div>
<div class="note">같은 결과를 사람이 손으로 추렸다면 어떨까. 어드바이저리 {all_deps}건을 읽고, 악용 여부를 확인하고, 우리 코드가 그 라이브러리를 쓰는지 찾고, 고쳐진 버전을 고르는 일이다. 현업에서 조치가 늦어지는 이유는 스캐너가 없어서가 아니라 이 번역 작업이 사람 손에 남아 있기 때문이다.</div>
{footer(2)}
</div>""")

# 3 데이터로 본 문제
pages.append(f"""<div class="page">
<div class="kicker">데이터</div>
<h2>같은 CVSS 8.8이어도 악용 확률은 백 배 넘게 차이 난다</h2>
<div class="cols">
 <div class="col" style="flex:1.35">{svg('chart_scatter.svg')}</div>
 <div class="col">
  <p class="lead">가로축이 CVSS, 세로축이 EPSS다. 점수 7 이상 오른쪽에 점이 몰려 있지만 대부분 바닥에 붙어 있다.</p>
  <ul>
   <li>CVSS 7 이상 취약점 209건 가운데 EPSS 0.1을 넘는 것은 20건이다.</li>
   <li>별표 하나가 KEV 등재 취약점이다. CVSS 8.8은 흔하지만 EPSS 0.9998은 하나뿐이다.</li>
   <li>그래서 점수는 규칙이 낸다. KEV 등재는 다른 항과 무관하게 최상위로 올리고, 나머지는 EPSS·CVSS·도달성·노출면·서비스 중요도·패치 가용성의 가중합으로 정렬한다.</li>
  </ul>
  <div class="box"><span class="mono">P = 100·1[KEV] + 40·EPSS + 20·CVSS/10 + 15·R + 10·X + 10·C + 5·F</span><br>
  <span class="dim">R 도달성: 직접 의존이며 1st-party 코드가 import하면 1, 직접 의존 0.6, 전이 의존 0.2 · X 외부 노출 · C 서비스 중요도 · F 패치 가용성. 가중치는 설정 파일로 조직마다 조정</span></div>
 </div>
</div>
<div class="note">EPSS는 FIRST가 매일 갱신하는 악용 확률 모델이고 KEV는 CISA가 실제 악용을 확인한 취약점 목록이다. 둘 다 공개 데이터라 사내 환경에서도 일일 스냅샷으로 캐시해 쓸 수 있다. 이번 실측은 2026년 10월 27일자 EPSS 점수표 396,259건과 KEV 카탈로그 1,760건을 썼다.</div>
{footer(3)}
</div>""")

# 4 아키텍처
pages.append(f"""<div class="page">
<div class="kicker">설계</div>
<h2>네 층으로 연결한다. 사실과 점수는 도구가, 해석과 문장은 모델이</h2>
<div class="flow">
 <div class="layer"><h4>연결</h4><p>SBOM, 스캔 결과, 서비스 정보를 하나의 그래프로 묶는다. 컴포넌트가 어느 서비스에 들어가고 외부에 노출되는지, 담당 조직이 어디인지가 취약점과 한 줄로 이어진다.</p><div class="tools">Syft → CycloneDX · pip-audit · npm audit · 서비스 인벤토리</div></div>
 <div class="arrow">→</div>
 <div class="layer"><h4>우선순위</h4><p>규칙 기반 점수로 줄을 세운다. KEV는 즉시 최상위. 도달성은 직접 의존 여부와 1st-party 코드의 import를 확인한다. 모델은 점수를 만들지 않는다.</p><div class="tools">OSV.dev · FIRST EPSS · CISA KEV · code_search</div></div>
 <div class="arrow">→</div>
 <div class="layer"><h4>조치</h4><p>패키지마다 최소 변경 패치 버전을 정한다. 같은 메이저 안의 수정을 먼저, KEV는 메이저라도 수정 버전을 포함한다. 모델이 근거를 달아 조치안과 PR 초안을 쓴다.</p><div class="tools">OpenAI function calling · JSON 스키마 · 근거 검증기</div></div>
 <div class="arrow">→</div>
 <div class="layer"><h4>검증</h4><p>목표 버전을 사본에 적용하고 재스캔해 취약점이 사라졌는지 확인한다. 예상과 실제가 다르면 그 자체가 보고 대상이다. 병합과 배포는 사람이 승인한다.</p><div class="tools">pip-audit · npm audit 재실행 · 감사 로그</div></div>
</div>
<div class="cols">
 <div class="col">
  <h3>모델이 쓰는 도구</h3>
  <p><span class="tag">get_action</span><span class="tag">get_finding</span><span class="tag">code_search</span><span class="tag">release_info</span><span class="tag">rescan_status</span></p>
  <p>모델은 도구가 돌려준 결과만 근거로 말한다. 출력은 JSON 스키마로 강제하고, rationale의 항목마다 evidence_ids를 요구한다. 도구가 돌려준 적 없는 근거 id가 섞이면 검증기가 반려하고 한 번 더 기회를 준 뒤 그래도 실패하면 사람에게 넘긴다.</p>
 </div>
 <div class="col">
  <h3>운영 흐름</h3>
  <p>매일 새벽 스캔이 끝나면 아침에 「오늘 고칠 열 건」 보고서가 올라온다. 왜 이 열 건인지의 근거, 예상 소요, 담당자가 함께 적혀 있고 개발자는 PR 초안을 검토해 적용한다. 재스캔이 0건을 확인하면 티켓이 닫힌다.</p>
  <p class="dim">본선 1박 2일 구현 범위: 제공 데이터 어댑터 → 우선순위 엔진 → 상위 열 건 조치안 → 한 건 이상 실제 패치와 재스캔 시연. 이 포트폴리오의 코드가 그 출발점이다.</p>
 </div>
</div>
<h3>신뢰성과 안정성 장치</h3>
<div class="flow" style="margin-top:2mm">
 <div class="layer"><h4>스키마 강제</h4><p>모델 출력은 JSON 스키마로만 받는다. 형식이 어긋나면 파싱 단계에서 거부된다.</p></div>
 <div class="layer" style="margin-left:4mm"><h4>근거 검증기</h4><p>문장마다 근거 id. 도구가 돌려준 적 없는 id는 반려. 한 번 재시도 후 실패하면 사람에게 넘긴다.</p></div>
 <div class="layer" style="margin-left:4mm"><h4>승인 게이트</h4><p>에이전트는 조치안과 PR 초안까지. 병합과 배포는 사람이 승인한다.</p></div>
 <div class="layer" style="margin-left:4mm"><h4>스냅샷 캐시</h4><p>KEV와 EPSS는 일일 스냅샷, OSV는 로컬 캐시. 외부 API가 멈춰도 아침 보고서는 나온다.</p></div>
 <div class="layer" style="margin-left:4mm"><h4>감사 로그</h4><p>모든 점수 구성 요소와 근거 id, 재스캔 결과를 기록해 나중에 왜 그 순서였는지 설명할 수 있다.</p></div>
</div>
{footer(4)}
</div>""")

# 5 오늘 고칠 열 건
pages.append(f"""<div class="page">
<div class="kicker">데모 결과 · 오늘 고칠 열 건</div>
<h2>{prod_total}건을 조치 {T['actions_total']}건으로 묶고, 오늘 처리할 10건을 골랐다</h2>
<table>
<thead><tr><th>#</th><th>서비스 · 담당</th><th>패키지 · 현재 → 목표</th><th>변경</th><th>해결 / 해당</th><th>KEV · EPSS</th><th>CVSS</th><th>도달성</th><th>재스캔 결과</th></tr></thead>
<tbody>{rows}</tbody>
</table>
<p class="dim" style="margin-top:3mm">해결 / 해당 = 이 조치가 없애는 취약점 수 / 그 패키지의 전체 취약점 수. 나머지는 메이저 업그레이드가 필요한 건으로 별도 계획에 넘긴다. 모든 행은 실제 재스캔으로 확인된 수치다. 서비스 이름·노출면·담당은 데모용 가정값이다.</p>
{footer(5)}
</div>""")

# 6 1위 조치안
pages.append(f"""<div class="page">
<div class="kicker">데모 결과 · 조치안</div>
<h2>1위 조치안: NetBox의 Pillow 8.3.1 → 10.0.1, 메이저 변경이지만 KEV가 우선한다</h2>
<div class="cols">
 <div class="col" style="flex:1.1">
  <div class="box">
   <p><b>결정</b> {esc(top1['decision'])} · <b>목표</b> {esc(top1['target_version'])} · <b>담당</b> {esc(top1['owner'])} · <b>예상 소요</b> {esc(top1['estimated_effort'])}</p>
   <p><b>근거</b></p><ul>{rationale_html}</ul>
   <p style="margin-top:2mm"><b>호환성 위험</b> {esc(top1['compatibility_risk']['level'])} — {esc(top1['compatibility_risk']['notes'])}</p>
   <p><b>PR 초안</b> <span class="mono">{esc(top1['pr']['title'])}</span></p>
   <p class="dim">검증기: {'통과' if top1['_validation']['ok'] else '반려'} · 모드 {esc(top1['_validation']['mode'])}</p>
  </div>
 </div>
 <div class="col">
  <h3>이 조치안이 인용한 근거 — 전부 도구 출력</h3>
  <table><thead><tr><th>근거 id</th><th>출처</th><th>사실</th></tr></thead><tbody>{evidence_rows}</tbody></table>
  <div class="note">최소 변경 원칙대로면 8.3.2가 목표였고 그 버전은 1건만 없앤다. KEV 규칙이 개입해 CVE-2023-4863의 수정 버전 10.0.1을 목표로 올렸고, 재스캔에서 해당 취약점의 소멸을 확인했다. 조치안의 문장 하나하나가 근거 id를 달고 있어서, 모델이 근거 없이 쓴 문장은 검증기 단계에서 걸러진다.</div>
 </div>
</div>
{footer(6)}
</div>""")

# 7 검증 루프
pages.append(f"""<div class="page">
<div class="kicker">데모 결과 · 검증 루프</div>
<h2>고쳤다고 말하지 않는다. 재스캔이 확인한 것만 닫는다</h2>
<div class="cols">
 <div class="col" style="flex:1.25">{svg('chart_before_after.svg')}</div>
 <div class="col">
  <h3>재스캔이 잡아낸 것</h3>
  <ul>
   <li><b>상위 10건 소멸 pygoat 9건, netbox 8건, nodegoat 4건.</b> 소멸하지 않은 건은 전부 메이저 업그레이드가 필요한 취약점이었다. Django 3.2는 지원이 끝난 브랜치라 2025년 이후 CVE는 4.2·5.x에서만 고쳐졌고, Pillow 12의 2026년 10월 신규 어드바이저리 41건은 13.0.0이 수정 버전이다.</li>
   <li><b>업그레이드가 새 취약점을 들여오기도 한다.</b> NetBox의 Pillow를 10.0.1로 올리자 10.x 범위에서 시작하는 어드바이저리 6건이 새로 잡혔다. 예상 10건 소멸은 맞았지만 잔존 수는 예상보다 많았고, 이 차이가 다음 조치 라운드의 입력이 된다.</li>
   <li><b>NodeGoat는 비파괴적 변경만 적용했다.</b> 운영 의존성 취약 패키지 52개 중 22개가 semver 호환 범위 안에서 해결됐고, 남은 30개는 메이저 변경이거나 패치가 없다. marked 0.3.5는 4.0.10으로, 유지보수가 끝난 swig는 대체 패키지 검토가 완화책이다.</li>
  </ul>
 </div>
</div>
<div class="note">검증 루프가 없었다면 "Pillow 10.0.1로 올리면 10건이 해결된다"는 보고서는 사실이지만 불완전했다. 재스캔은 조치의 효과를 숫자로 닫고, 예상과 실제의 차이를 다음 우선순위 규칙과 프롬프트를 고치는 데 다시 쓴다.</div>
{footer(7)}
</div>""")

# 8 지표·계획·한계
pages.append(f"""<div class="page">
<div class="kicker">지표와 계획</div>
<h2>프로젝트별 실측 지표와 본선 계획</h2>
<table>
<thead><tr><th>서비스</th><th>SBOM 컴포넌트</th><th>취약점</th><th>CRITICAL·HIGH</th><th>EPSS≥0.1</th><th>KEV</th><th>패치 후 재스캔</th><th>상위 10건 소멸</th></tr></thead>
<tbody>{proj_rows}</tbody>
</table>
<div class="cols" style="margin-top:4mm">
 <div class="col">
  <h3>본선에서 더할 것</h3>
  <ul>
   <li>제공되는 현장 데이터 어댑터. 사내 상용 스캐너 출력도 같은 finding 스키마로 받는다.</li>
   <li>함수 수준 도달성. 어드바이저리가 지목한 취약 API의 실제 호출 여부를 code_search로 확인해 R 값을 정밀화한다.</li>
   <li>OpenAI 모델 기반 조치안 생성 실행본. 이번 포트폴리오의 조치안은 같은 도구와 스키마를 쓰는 규칙 기반 초안이며, 본선 환경에서 모델 실행본으로 교체한다.</li>
   <li>평가셋 지표: 상위 열 건 정확도, 재스캔 통과율, 근거 없는 문장 비율을 회귀 테스트로 추적.</li>
  </ul>
 </div>
 <div class="col">
  <h3>정직하게 적는 한계</h3>
  <ul>
   <li>서비스 인벤토리의 노출면·중요도·담당은 데모용 가정값이다.</li>
   <li>도달성은 패키지 수준 import 확인까지만 구현했다.</li>
   <li>Python은 고정 핀만 감사했고 전이 의존성은 npm 쪽에서만 다뤘다.</li>
  </ul>
  <h3>재현과 출처</h3>
  <p class="dim">대상: OWASP PyGoat main 2026-10-22, NetBox v3.0.0, OWASP NodeGoat main. 데이터: OSV.dev API, FIRST EPSS 2026-10-27 점수표, CISA KEV 카탈로그 2026.10.27, PyPI·npm 레지스트리. 도구: Syft 1.14.0, pip-audit 2.10.1, npm 10.9.9, Python 3.13.</p>
<pre>python -m triage.scan        # SBOM 생성, pip-audit · npm audit 실행과 정규화
python -m triage.enrich      # OSV · EPSS · KEV 보강
python -m triage.remediate   # 패치 버전 결정, 사본 적용, 재스캔
python -m triage.report      # 오늘 고칠 열 건 보고서
python -m triage.agent       # 조치안 생성 · 키가 없으면 --dry-run 규칙 기반 초안</pre>
 </div>
</div>
{footer(8)}
</div>""")

doc = f"""<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>트리아지 포트폴리오</title><style>{page_css}</style></head><body>{''.join(pages)}</body></html>"""
(HERE / "portfolio.html").write_text(doc)

from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page()
    pg.goto((HERE / "portfolio.html").as_uri())
    pg.wait_for_timeout(500)
    pg.pdf(path=str(HERE / "트리아지_포트폴리오_김근홍.pdf"), width="297mm", height="210mm", print_background=True, prefer_css_page_size=True)
    b.close()
print("pdf written")
