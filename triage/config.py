"""서비스 인벤토리와 가중치 설정. 조직마다 바꾸는 값은 전부 여기에 둔다."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
OUT = ROOT / "out"
TARGETS = ROOT / "targets"
SYFT = ROOT / "bin" / "syft"

# 서비스 인벤토리 (데모용 가정값). 실제 조직에서는 CMDB나 배포 메타데이터에서 가져온다.
SERVICES = {
    "pygoat": {
        "name": "pygoat-web",
        "path": TARGETS / "pygoat",
        "ecosystems": ["PyPI"],
        "exposure": "internet",      # internet | internal
        "criticality": "medium",     # high | medium | low
        "owner": "웹서비스개발팀",
        "description": "OWASP PyGoat, 의도적으로 취약한 Django 교육용 앱 · main 브랜치 2026-10-22 커밋",
    },
    "netbox": {
        "name": "netbox-ipam",
        "path": TARGETS / "netbox",
        "ecosystems": ["PyPI"],
        "exposure": "internal",
        "criticality": "high",
        "owner": "인프라운영팀",
        "description": "NetBox v3.0.0, 실제 운영용 IPAM/DCIM 오픈소스의 2021년 8월 릴리스",
    },
    "nodegoat": {
        "name": "nodegoat-portal",
        "path": TARGETS / "NodeGoat",
        "ecosystems": ["npm"],
        "exposure": "internet",
        "criticality": "low",
        "owner": "디지털채널팀",
        "description": "OWASP NodeGoat, 의도적으로 취약한 Node.js 교육용 앱 · main 브랜치",
    },
}

# 우선순위 점수 가중치. P = 100*KEV + w_epss*EPSS + w_cvss*CVSS/10 + w_reach*R + w_expo*X + w_crit*C + w_fix*F
WEIGHTS = {
    "kev": 100.0,
    "epss": 40.0,
    "cvss": 20.0,
    "reach": 15.0,
    "exposure": 10.0,
    "criticality": 10.0,
    "fix": 5.0,
}

EXPOSURE_SCORE = {"internet": 1.0, "internal": 0.3}
CRITICALITY_SCORE = {"high": 1.0, "medium": 0.5, "low": 0.2}
# 도달성: 직접 의존이면서 1st-party 코드가 import → 1.0, 직접 의존만 → 0.6, 전이 의존 → 0.2
REACH_SCORE = {"direct+imported": 1.0, "direct": 0.6, "transitive": 0.2}

# 배포 이름과 import 이름이 다른 파이썬 패키지
PY_IMPORT_NAMES = {
    "pillow": ["PIL"],
    "pyyaml": ["yaml"],
    "django-allauth": ["allauth"],
    "djangorestframework": ["rest_framework"],
    "pyjwt": ["jwt"],
    "python3-openid": ["openid"],
    "pycryptodome": ["Crypto"],
    "beautifulsoup4": ["bs4"],
    "python-dateutil": ["dateutil"],
    "django-crispy-forms": ["crispy_forms"],
    "crispy-bootstrap4": ["crispy_bootstrap4"],
    "dj-database-url": ["dj_database_url"],
    "requests-oauthlib": ["requests_oauthlib"],
    "argon2-cffi": ["argon2"],
    "markdown": ["markdown"],
    "mkdocs-material": ["material"],
    "django-filter": ["django_filters"],
    "django-tables2": ["django_tables2"],
    "django-mptt": ["mptt"],
    "django-cors-headers": ["corsheaders"],
    "django-debug-toolbar": ["debug_toolbar"],
    "django-prometheus": ["django_prometheus"],
    "django-rq": ["django_rq"],
    "django-taggit": ["taggit"],
    "django-timezone-field": ["timezone_field"],
    "drf-yasg": ["drf_yasg"],
    "psycopg2-binary": ["psycopg2"],
}
