"""트리아지(Triage): SBOM + 취약점 스캔 결과를 '오늘 고칠 열 건'으로 바꾸는 공급망 스캐닝 에이전트 데모.

파이프라인
  sbom      Syft로 CycloneDX SBOM 생성
  scan      pip-audit / npm audit 실행 → 정규화된 finding 목록
  enrich    OSV(어드바이저리·CVSS), FIRST EPSS, CISA KEV로 보강
  reach     직접 의존 여부 + 1st-party 코드의 import/require 여부로 도달성 산정
  score     규칙 기반 우선순위 점수 (KEV 최상위 고정)
  remediate 패치 버전 결정 → 사본에 적용 → 재스캔으로 소멸 확인
  agent     OpenAI 도구 호출 기반 조치안 작성 (근거 없는 문장은 자동 반려)
  report    '오늘 고칠 열 건' 보고서
"""
