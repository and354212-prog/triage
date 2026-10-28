# 오늘 고칠 열 건 — 2026-10-28

스캔 결과 384건을 조치 65건으로 묶고, 그중 오늘 처리할 10건을 골랐다. KEV 1건, EPSS 0.1 이상 20건, CRITICAL·HIGH 220건.

| # | 서비스 | 패키지 | 현재 → 목표 | 변경 | 해결 | 근거 | 상태 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | netbox-ipam | pillow | 8.3.1 → 10.0.1 | major · KEV 규칙 | 10/55 | CISA 악용 확인 목록 등재 2023-09-13 [kev:CVE-2023-4863] · EPSS 1.000 백분위 1.00 [epss:CVE-2023-4863] · CVSS 8.8 HIGH [osv:GHSA-j7hp-h8jx-5ppr] · 직접 의존 · netbox-ipam internal/high · 패치 10.0.1 | 재스캔 소멸 확인 |
| 2 | netbox-ipam | django | 3.2.6 → 3.2.25 | minor/patch | 20/33 | EPSS 0.736 백분위 0.99 [epss:CVE-2022-34265] · CVSS 9.3 CRITICAL [osv:GHSA-p64x-8rxx-wf6q] · 직접 의존이며 1st-party 코드에서 import [code] · netbox-ipam internal/high · 패치 3.2.14, 4.0.6 | 재스캔 소멸 확인 |
| 3 | pygoat-web | django | 4.2 → 4.2.30 | minor/patch | 43/51 | EPSS 0.498 백분위 0.99 [epss:CVE-2023-46695] · CVSS 8.7 HIGH [osv:GHSA-qmf9-6jqf-j8fq] · 직접 의존이며 1st-party 코드에서 import [code] · pygoat-web internet/medium · 패치 3.2.23, 4.1.13, 4.2.7 | 재스캔 소멸 확인 |
| 4 | nodegoat-portal | y18n | 3.2.1 → 3.2.2 | minor/patch | 1/1 | EPSS 0.694 백분위 0.99 [epss:CVE-2020-7774] · CVSS 7.3 HIGH [osv:GHSA-c4w7-xm78-47vh] · 전이 의존 · nodegoat-portal internet/low · 패치 3.2.2, 4.0.1, 5.0.5 | 재스캔 소멸 확인 |
| 5 | pygoat-web | pyyaml | 5.1 → 5.4 | minor/patch | 3/3 | EPSS 0.060 백분위 0.93 [epss:CVE-2020-14343] · CVSS 9.3 CRITICAL [osv:GHSA-8q59-q68h-6hv4] · 직접 의존이며 1st-party 코드에서 import [code] · pygoat-web internet/medium · 패치 5.4 | 재스캔 소멸 확인 |
| 6 | pygoat-web | pillow | 12.1.0 → 12.3.0 | minor/patch | 19/60 | EPSS 0.007 백분위 0.52 [epss:CVE-2026-40192] · CVSS 8.7 HIGH [osv:GHSA-whj4-6x5x-4v2j] · 직접 의존이며 1st-party 코드에서 import [code] · pygoat-web internet/medium · 패치 12.2.0 | 재스캔 소멸 확인 |
| 7 | pygoat-web | pyjwt | 2.4.0 → 2.15.0 | minor/patch | 13/14 | EPSS 0.002 백분위 0.14 [epss:CVE-2026-102268] · CVSS 9.1 CRITICAL [osv:GHSA-ffc3-869f-jxw9] · 직접 의존이며 1st-party 코드에서 import [code] · pygoat-web internet/medium · 패치 2.14.0 | 재스캔 소멸 확인 |
| 8 | nodegoat-portal | underscore | 1.9.1 → 1.13.8 | minor/patch | 2/2 | EPSS 0.042 백분위 0.91 [epss:CVE-2021-23358] · CVSS 9.8 CRITICAL [osv:GHSA-cf4h-3jhx-xvhq] · 직접 의존이며 1st-party 코드에서 import [code] · nodegoat-portal internet/low · 패치 1.12.1 | 재스캔 소멸 확인 |
| 9 | pygoat-web | requests | 2.28.2 → 2.33.0 | minor/patch | 4/4 | EPSS 0.030 백분위 0.87 [epss:CVE-2023-32681] · CVSS 6.1 MEDIUM [osv:GHSA-j8r2-6x86-q33q] · 직접 의존이며 1st-party 코드에서 import [code] · pygoat-web internet/medium · 패치 2.31.0 | 재스캔 소멸 확인 |
| 10 | netbox-ipam | djangorestframework | 3.12.4 → 3.18.2 | minor/patch | 6/6 | EPSS 0.005 백분위 0.44 [epss:CVE-2026-114138] · CVSS 7.5 HIGH [osv:GHSA-33wh-fxxf-88vv] · 직접 의존이며 1st-party 코드에서 import [code] · netbox-ipam internal/high · 패치 3.18.2 | 재스캔 소멸 확인 |

## pygoat-web — OWASP PyGoat, 의도적으로 취약한 Django 교육용 앱 · main 브랜치 2026-10-22 커밋
SBOM 컴포넌트 125개, 취약점 187건/15패키지, CRITICAL·HIGH 94건, EPSS≥0.1 7건, KEV 0건, 우선순위 50점 이상 62건. 패치 후 재스캔 84건, 상위 10건 소멸 9/10.

## netbox-ipam — NetBox v3.0.0, 실제 운영용 IPAM/DCIM 오픈소스의 2021년 8월 릴리스
SBOM 컴포넌트 543개, 취약점 105건/9패키지, CRITICAL·HIGH 64건, EPSS≥0.1 9건, KEV 1건, 우선순위 50점 이상 19건. 패치 후 재스캔 67건, 상위 10건 소멸 8/10.

## nodegoat-portal — OWASP NodeGoat, 의도적으로 취약한 Node.js 교육용 앱 · main 브랜치
SBOM 컴포넌트 1230개, 취약점 92건/34패키지, CRITICAL·HIGH 62건, EPSS≥0.1 4건, KEV 0건, 우선순위 50점 이상 2건. 패치 후 재스캔 28건, 상위 10건 소멸 4/10.
