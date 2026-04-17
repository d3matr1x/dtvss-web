# DTVSS — API Clients for NVD and EPSS
# Copyright © 2026 Andrew Broglio. All rights reserved.
# Licensed under BSL 1.1

"""
Direct API clients for NVD v2 and EPSS.
All public data sources.
"""

import json
import os
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import date
from typing import Optional

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
MITRE_CVE_URL = "https://cveawg.mitre.org/api/cve"

# CVSS v3.1 exploitability sub-score computation from vector string
CVSS31_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
CVSS31_AC = {"L": 0.77, "H": 0.44}
CVSS31_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
CVSS31_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
CVSS31_UI = {"N": 0.85, "R": 0.62}


def parse_cvss31_exploitability(vector: str) -> Optional[float]:
    if not vector:
        return None

    if "CVSS:3" not in vector and "CVSS:4" not in vector:
        return None

    parts = {}
    for segment in vector.split("/"):
        if ":" in segment:
            k, v = segment.split(":", 1)
            parts[k] = v

    try:
        av = CVSS31_AV.get(parts.get("AV", ""), None)
        ui = CVSS31_UI.get(parts.get("UI", ""), None)

        ac = CVSS31_AC.get(parts.get("AC", ""), None)
        if ac is None and "AT" in parts:
            at_map = {"N": "L", "P": "H"}
            ac = CVSS31_AC.get(at_map.get(parts["AT"], ""), None)

        scope = parts.get("S", "U")
        pr_table = CVSS31_PR_C if scope == "C" else CVSS31_PR_U
        pr = pr_table.get(parts.get("PR", ""), None)

        if None in (av, ac, pr, ui):
            return None

        return round(8.22 * av * ac * pr * ui, 1)
    except Exception:
        return None


ICS_URL_FRAGMENTS = (
    "ics-cert.us-cert.gov",
    "us-cert.cisa.gov/ics",
    "cisa.gov/news-events/ics-medical-advisories",
    "cisa.gov/news-events/ics-advisories",
    "/icsma-",
    "/icsa-",
)


# ═══════════════════════════════════════════════════════════════════════
# FIXED SEARCH LOGIC 1 — NVD keyword search (improved recall + pagination)
# ═══════════════════════════════════════════════════════════════════════

def nvd_search_keyword(keyword: str, api_key: str = None, max_results: int = 50) -> list[dict]:
    import time as _time

    def build_queries(q: str) -> list[str]:
        q = q.strip()
        queries = [q]

        if q.upper().startswith("CVE-"):
            return [q.upper()]

        tokens = [t for t in q.split() if len(t) > 2]
        if len(tokens) > 1:
            queries.append(" ".join(tokens[:2]))
            queries.append(tokens[0])

        return list(dict.fromkeys(queries))

    headers = {"Accept": "application/json", "User-Agent": "DTVSS/6.0"}
    if api_key:
        headers["apiKey"] = api_key

    results = []
    seen = set()

    for q in build_queries(keyword):
        start = 0

        while len(results) < max_results:
            params = {
                "keywordSearch": q,
                "resultsPerPage": min(100, max_results - len(results)),
                "startIndex": start,
                "noRejected": ""
            }

            url = f"{NVD_URL}?{urllib.parse.urlencode(params)}"

            _time.sleep(0.6 if api_key else 5.5)

            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=30) as resp:
                    raw = resp.read().decode("utf-8")

                if raw.strip().startswith("<"):
                    break

                data = json.loads(raw)

            except Exception:
                break

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break

            for v in vulns:
                cve = v.get("cve", {})
                cve_id = cve.get("id")
                if not cve_id or cve_id in seen:
                    continue

                parsed = _parse_nvd_cve(cve)
                if parsed and "error" not in parsed:
                    results.append(parsed)
                    seen.add(cve_id)

                if len(results) >= max_results:
                    break

            start += 100

    return results


def mitre_lookup_cve(cve_id: str) -> Optional[dict]:
    url = f"{MITRE_CVE_URL}/{cve_id}"

    try:
        req = urllib.request.Request(url, headers={
            "Accept": "application/json",
            "User-Agent": "DTVSS/6.0"
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return {"error": f"MITRE CVE API error: {str(e)}"}

    cna = data.get("containers", {}).get("cna", {})
    if not cna:
        return {"error": f"No CNA data for {cve_id}"}

    desc = ""
    for d in cna.get("descriptions", []):
        if d.get("lang", "").startswith("en"):
            desc = d.get("value", "")
            break

    B = 0.0
    cvss_ver = ""
    cvss_vec = ""
    sev = ""

    version_keys = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]
    version_labels = {
        "cvssV4_0": "4.0",
        "cvssV3_1": "3.1",
        "cvssV3_0": "3.0",
        "cvssV2_0": "2.0"
    }

    for metric_block in cna.get("metrics", []):
        for ver_key in version_keys:
            if ver_key in metric_block:
                cvss_data = metric_block[ver_key]
                cvss_vec = cvss_data.get("vectorString", "")
                sev = cvss_data.get("baseSeverity", "")
                cvss_ver = version_labels[ver_key]

                if ver_key == "cvssV2_0":
                    base = float(cvss_data.get("baseScore", 0))
                    B = round(min(base * 0.5, 10.0), 1) if base else 0.0
                else:
                    B = parse_cvss31_exploitability(cvss_vec) or 0.0
                    if not B and ver_key == "cvssV4_0":
                        base = float(cvss_data.get("baseScore", 0))
                        B = round(min(base * 0.5, 10.0), 1) if base else 0.0
                break
        if B > 0:
            break

    for adp in data.get("containers", {}).get("adp", []):
        if B > 0:
            break
        for metric_block in adp.get("metrics", []):
            for ver_key in version_keys:
                if ver_key in metric_block:
                    cvss_data = metric_block[ver_key]
                    cvss_vec = cvss_data.get("vectorString", "")
                    sev = cvss_data.get("baseSeverity", "")
                    cvss_ver = version_labels[ver_key]

                    if ver_key == "cvssV2_0":
                        base = float(cvss_data.get("baseScore", 0))
                        B = round(min(base * 0.5, 10.0), 1) if base else 0.0
                    else:
                        B = parse_cvss31_exploitability(cvss_vec) or 0.0
                        if not B and ver_key == "cvssV4_0":
                            base = float(cvss_data.get("baseScore", 0))
                            B = round(min(base * 0.5, 10.0), 1) if base else 0.0
                    break
            if B > 0:
                break

    if not B:
        return {"error": f"No CVSS scoring data published for {cve_id}"}

    refs = [r.get("url", "") for r in cna.get("references", [])]
    ics = any(frag in url for url in refs for frag in ICS_URL_FRAGMENTS)
    ics_urls = [u for u in refs if any(f in u for f in ICS_URL_FRAGMENTS)]

    published = data.get("cveMetadata", {}).get("datePublished", "")

    return {
        "cve_id": cve_id,
        "description": desc[:300] + ("..." if len(desc) > 300 else ""),
        "B": round(float(B), 3),
        "cvss_version": cvss_ver,
        "cvss_vector": cvss_vec,
        "severity": sev,
        "published": published,
        "kev": False,
        "kev_added": "",
        "kev_due": "",
        "kev_name": "",
        "ics_advisory": ics,
        "ics_urls": ics_urls,
        "impact_score": 0.0,
        "source": "mitre_cve",
    }


def nvd_lookup_cve(cve_id: str, api_key: str = None) -> Optional[dict]:
    url = f"{NVD_URL}?cveId={cve_id}"

    headers = {"Accept": "application/json", "User-Agent": "DTVSS/6.0"}
    if api_key:
        headers["apiKey"] = api_key

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        mitre = mitre_lookup_cve(cve_id)
        if mitre and "error" not in mitre:
            return mitre
        return {"error": f"NVD API error: {str(e)}"}

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        mitre = mitre_lookup_cve(cve_id)
        if mitre and "error" not in mitre:
            return mitre
        return {"error": f"CVE {cve_id} not found"}

    return _parse_nvd_cve(vulns[0].get("cve", {}))


def _parse_nvd_cve(cve: dict) -> Optional[dict]:
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")

    B = 0.0
    cvss_ver = cvss_vec = sev = ""
    impact = 0.0
    m = cve.get("metrics", {})

    if m.get("cvssMetricV31"):
        x = m["cvssMetricV31"][0]
        B = float(x.get("exploitabilityScore", 0))
        impact = float(x.get("impactScore", 0))
        cvss_ver = "3.1"
        cvss_vec = x.get("cvssData", {}).get("vectorString", "")
        sev = x.get("cvssData", {}).get("baseSeverity", "")
    elif m.get("cvssMetricV30"):
        x = m["cvssMetricV30"][0]
        B = float(x.get("exploitabilityScore", 0))
        impact = float(x.get("impactScore", 0))
        cvss_ver = "3.0"
        cvss_vec = x.get("cvssData", {}).get("vectorString", "")
        sev = x.get("cvssData", {}).get("baseSeverity", "")
    elif m.get("cvssMetricV40"):
        x = m["cvssMetricV40"][0]
        cvss_ver = "4.0"
        cvss_vec = x.get("cvssData", {}).get("vectorString", "")
        sev = x.get("cvssData", {}).get("baseSeverity", "")
        base_score = float(x.get("cvssData", {}).get("baseScore", 0))
        B = parse_cvss31_exploitability(cvss_vec) or 0.0
        if not B and base_score:
            B = round(min(base_score * 0.5, 10.0), 1)
        impact = base_score - B if B else 0.0
    elif m.get("cvssMetricV2"):
        x = m["cvssMetricV2"][0]
        cvss_ver = "2.0"
        cvss_vec = x.get("cvssData", {}).get("vectorString", "")
        sev = x.get("cvssData", {}).get("baseSeverity", "")
        B = float(x.get("exploitabilityScore", 0))
        impact = float(x.get("impactScore", 0))
        if not B:
            return {"cve_id": cve_id, "error": "No v2 exploitability"}
    else:
        return {"cve_id": cve_id, "error": "No CVSS score"}

    if not B:
        return {"cve_id": cve_id, "error": "No exploitability"}

    kev = bool(cve.get("cisaExploitAdd"))
    refs = [r.get("url", "") for r in cve.get("references", [])]
    ics = any(frag in url for url in refs for frag in ICS_URL_FRAGMENTS)
    ics_urls = [u for u in refs if any(f in u for f in ICS_URL_FRAGMENTS)]

    return {
        "cve_id": cve_id,
        "description": desc[:300],
        "B": round(B, 3),
        "cvss_version": cvss_ver,
        "cvss_vector": cvss_vec,
        "severity": sev,
        "published": cve.get("published", ""),
        "kev": kev,
        "ics_advisory": ics,
        "ics_urls": ics_urls,
        "impact_score": round(impact, 3),
    }


def epss_lookup(cve_ids: list[str]) -> dict:
    results = {}
    batch = ",".join(cve_ids[:100])

    try:
        req = urllib.request.Request(
            EPSS_URL + f"?cve={batch}",
            headers={"Accept": "application/json", "User-Agent": "DTVSS/6.0"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        for row in data.get("data", []):
            results[row["cve"]] = {
                "epss": float(row["epss"]),
                "percentile": float(row["percentile"]),
                "date": row.get("date", ""),
            }
    except Exception:
        pass

    for cve_id in cve_ids:
        results.setdefault(cve_id, {"epss": 0.0, "percentile": 0.0, "date": date.today().isoformat()})

    return results