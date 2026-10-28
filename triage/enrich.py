"""OSV 어드바이저리, FIRST EPSS, CISA KEV로 finding을 보강한다. 모든 값은 출처 id와 함께 기록된다."""
from __future__ import annotations

import csv
import json
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cvss import CVSS3, CVSS4
from packaging.version import InvalidVersion, Version

from .config import DATA

OSV_CACHE = DATA / "osv_cache"
OSV_CACHE.mkdir(parents=True, exist_ok=True)


def osv_get(vuln_id: str) -> dict | None:
    cache = OSV_CACHE / f"{vuln_id}.json"
    if cache.exists():
        return json.loads(cache.read_text())
    url = f"https://api.osv.dev/v1/vulns/{vuln_id}"
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            data = json.loads(r.read().decode())
    except Exception as e:  # 404 등
        data = {"_error": str(e)}
    cache.write_text(json.dumps(data))
    return data


def load_epss() -> dict[str, tuple[float, float]]:
    out = {}
    with open(DATA / "epss.csv", newline="") as f:
        for row in csv.reader(f):
            if not row or row[0].startswith("#") or row[0] == "cve":
                continue
            out[row[0]] = (float(row[1]), float(row[2]))
    return out


def load_kev() -> dict[str, dict]:
    d = json.loads((DATA / "kev.json").read_text())
    return {v["cveID"]: v for v in d.get("vulnerabilities", [])}


def _cvss_from_osv(rec: dict) -> tuple[float | None, str | None, str | None]:
    """OSV severity 배열에서 CVSS 벡터를 찾아 점수를 계산한다. 4.0 > 3.1 순으로 고른다."""
    vectors = {s.get("type"): s.get("score") for s in rec.get("severity", []) if s.get("score")}
    try:
        if "CVSS_V4" in vectors:
            c = CVSS4(vectors["CVSS_V4"])
            return float(c.base_score), vectors["CVSS_V4"], c.severities()[0].upper()
        if "CVSS_V3" in vectors:
            c = CVSS3(vectors["CVSS_V3"])
            return float(c.base_score), vectors["CVSS_V3"], c.severities()[0].upper()
    except Exception:
        pass
    sev = (rec.get("database_specific") or {}).get("severity")
    return None, None, (sev.upper() if sev else None)


def _fixed_versions(rec: dict, ecosystem: str, package: str) -> list[str]:
    """affected[].ranges[].events 의 fixed 값들."""
    eco = {"PyPI": "PyPI", "npm": "npm"}[ecosystem]
    fixed = []
    for aff in rec.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem") != eco:
            continue
        if pkg.get("name", "").lower().replace("_", "-") != package.lower().replace("_", "-"):
            continue
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    fixed.append(ev["fixed"])
    return sorted(set(fixed), key=_vkey)


def _vkey(v: str):
    try:
        return (0, Version(v))
    except InvalidVersion:
        return (1, v)


def enrich(findings: list[dict], workers: int = 8) -> list[dict]:
    epss = load_epss()
    kev = load_kev()
    ids = sorted({f["vuln_id"] for f in findings})
    with ThreadPoolExecutor(workers) as ex:
        recs = dict(zip(ids, ex.map(osv_get, ids)))

    for f in findings:
        rec = recs.get(f["vuln_id"]) or {}
        f["evidence"] = []
        if rec and "_error" not in rec:
            aliases = set(f.get("aliases", [])) | set(rec.get("aliases", [])) | {rec.get("id", "")}
            f["aliases"] = sorted(a for a in aliases if a)
            if not f.get("cve"):
                f["cve"] = next((a for a in f["aliases"] if a.startswith("CVE-")), None)
            if not f.get("ghsa"):
                f["ghsa"] = next((a for a in f["aliases"] if a.startswith("GHSA-")), None)
            score, vector, sev = _cvss_from_osv(rec)
            if f.get("cvss_score") is None and score is not None:
                f["cvss_score"], f["cvss_vector"] = score, vector
            if not f.get("severity") and sev:
                f["severity"] = sev
            f["summary"] = f.get("summary") or rec.get("summary", "")
            f["details"] = (rec.get("details") or "")[:1500]
            f["published"] = rec.get("published")
            f["cwe"] = f.get("cwe") or (rec.get("database_specific") or {}).get("cwe_ids", [])
            osv_fixed = _fixed_versions(rec, f["ecosystem"], f["package"])
            if osv_fixed:
                f["fix_versions"] = osv_fixed
            f["references"] = [r.get("url") for r in rec.get("references", [])][:8]
            f["evidence"].append({"id": f"osv:{rec.get('id')}", "source": "OSV.dev", "url": f"https://osv.dev/vulnerability/{rec.get('id')}",
                                  "fact": f"CVSS {f.get('cvss_score')} {f.get('severity')}, fixed in {', '.join(f['fix_versions']) or '없음'}"})
        else:
            f["details"] = ""
            f["references"] = []

        cve = f.get("cve")
        if cve and cve in epss:
            f["epss"], f["epss_percentile"] = epss[cve]
            f["evidence"].append({"id": f"epss:{cve}", "source": "FIRST EPSS 2026-10-27", "url": f"https://api.first.org/data/v1/epss?cve={cve}",
                                  "fact": f"악용 확률 {f['epss']:.4f}, 백분위 {f['epss_percentile']:.3f}"})
        else:
            f["epss"], f["epss_percentile"] = None, None
        if cve and cve in kev:
            k = kev[cve]
            f["kev"] = {"date_added": k.get("dateAdded"), "due_date": k.get("dueDate"),
                        "ransomware": k.get("knownRansomwareCampaignUse"), "action": k.get("requiredAction")}
            f["evidence"].append({"id": f"kev:{cve}", "source": "CISA KEV 2026.10.27", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                                  "fact": f"악용 확인 목록 등재 {k.get('dateAdded')}, 랜섬웨어 사용 {k.get('knownRansomwareCampaignUse')}"})
        else:
            f["kev"] = None
        f["fix_available"] = bool(f.get("fix_versions")) or bool(f.get("fix_available"))
    return findings


if __name__ == "__main__":
    import sys
    from .config import OUT
    for p in sys.argv[1:] or ["pygoat", "netbox", "nodegoat"]:
        fs = json.loads((OUT / p / "findings_raw.json").read_text())
        fs = enrich(fs)
        (OUT / p / "findings_enriched.json").write_text(json.dumps(fs, ensure_ascii=False, indent=1))
        n_cve = sum(1 for f in fs if f.get("cve"))
        n_epss = sum(1 for f in fs if f.get("epss") is not None)
        n_kev = sum(1 for f in fs if f.get("kev"))
        n_cvss = sum(1 for f in fs if f.get("cvss_score") is not None)
        print(f"{p}: {len(fs)} findings | CVE {n_cve} | EPSS {n_epss} | KEV {n_kev} | CVSS {n_cvss}")
