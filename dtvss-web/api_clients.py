# DTVSS — API Clients for NVD and EPSS
# Copyright © 2026 Andrew Broglio. All rights reserved.
# Licensed under BSL 1.1

"""
Direct API clients for NVD v2 and EPSS.
No Anthropic API dependency. All public data sources.
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
# Used as fallback when NVD hasn't enriched the CVE (backlog)
CVSS31_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
CVSS31_AC = {"L": 0.77, "H": 0.44}
CVSS31_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}  # Scope Unchanged
CVSS31_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}  # Scope Changed
CVSS31_UI = {"N": 0.85, "R": 0.62}


def parse_cvss31_exploitability(vector: str) -> Optional[float]:
    """
    Parse a CVSS v3.1 vector string and compute the exploitability sub-score.
    Exploitability = 8.22 × AV × AC × PR × UI
    Returns None if vector cannot be parsed.
    """
    if not vector or "CVSS:3" not in vector:
        return None

    parts = {}
    for segment in vector.split("/"):
        if ":" in segment:
            k, v = segment.split(":", 1)
            parts[k] = v

    try:
        av = CVSS31_AV.get(parts.get("AV", ""), None)
        ac = CVSS31_AC.get(parts.get("AC", ""), None)
        ui = CVSS31_UI.get(parts.get("UI", ""), None)
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


def nvd_lookup_cve(cve_id: str, api_key: str = None) -> Optional[dict]:
    """
    Look up a single CVE by ID from NVD API v2.
    Falls back to MITRE CVE.org API if NVD hasn't enriched the CVE (backlog).
    """
    params = {"cveId": cve_id}
    query = urllib.parse.urlencode(params)
    url = f"{NVD_URL}?{query}"

    headers = {"Accept": "application/json", "User-Agent": "DTVSS/6.0"}
    if api_key:
        headers["apiKey"] = api_key

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        # NVD unreachable — try MITRE fallback
        mitre = mitre_lookup_cve(cve_id)
        if mitre and "error" not in mitre:
            return mitre
        return {"error": f"NVD API error: {str(e)}"}

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        # CVE not in NVD — try MITRE
        mitre = mitre_lookup_cve(cve_id)
        if mitre and "error" not in mitre:
            return mitre
        return {"error": f"CVE {cve_id} not found in NVD or MITRE"}

    cve = vulns[0].get("cve", {})
    result = _parse_nvd_cve(cve)

    # If NVD returned the CVE but has no CVSS (unenriched/backlog), try MITRE
    if result and "error" in result and "No CVSS" in result.get("error", ""):
        mitre = mitre_lookup_cve(cve_id)
        if mitre and "error" not in mitre:
            # Preserve KEV data from NVD if available
            if cve.get("cisaExploitAdd"):
                mitre["kev"] = True
                mitre["kev_added"] = cve.get("cisaExploitAdd", "")
                mitre["kev_due"] = cve.get("cisaActionDue", "")
                mitre["kev_name"] = cve.get("cisaVulnerabilityName", "")
            return mitre

    return result


def mitre_lookup_cve(cve_id: str) -> Optional[dict]:
    """
    Fallback: look up CVE from MITRE CVE.org API when NVD hasn't enriched it.
    Extracts CVSS vector from CNA-provided metrics and computes exploitability.
    Addresses the NVD backlog where 72%+ of CVEs remain unenriched.
    """
    url = f"{MITRE_CVE_URL}/{cve_id}"

    try:
        req = urllib.request.Request(url, headers={
            "Accept": "application/json", "User-Agent": "DTVSS/6.0"
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return {"error": f"MITRE CVE API error: {str(e)}"}

    cna = data.get("containers", {}).get("cna", {})
    if not cna:
        return {"error": f"No CNA data for {cve_id}"}

    # Extract description
    desc = ""
    for d in cna.get("descriptions", []):
        if d.get("lang", "").startswith("en"):
            desc = d.get("value", "")
            break

    # Extract CVSS vector from CNA metrics
    B = 0.0
    cvss_ver = ""
    cvss_vec = ""
    sev = ""

    for metric_block in cna.get("metrics", []):
        # Try cvssV3_1 first, then cvssV3_0
        for ver_key in ("cvssV3_1", "cvssV3_0"):
            if ver_key in metric_block:
                cvss_data = metric_block[ver_key]
                cvss_vec = cvss_data.get("vectorString", "")
                sev = cvss_data.get("baseSeverity", "")
                cvss_ver = "3.1" if "3_1" in ver_key else "3.0"

                # Compute exploitability from vector
                B = parse_cvss31_exploitability(cvss_vec) or 0.0
                break
        if B > 0:
            break

    # Also check adp containers (CISA Vulnrichment provides CVSS here)
    for adp in data.get("containers", {}).get("adp", []):
        if B > 0:
            break
        for metric_block in adp.get("metrics", []):
            for ver_key in ("cvssV3_1", "cvssV3_0"):
                if ver_key in metric_block:
                    cvss_data = metric_block[ver_key]
                    cvss_vec = cvss_data.get("vectorString", "")
                    sev = cvss_data.get("baseSeverity", "")
                    cvss_ver = "3.1" if "3_1" in ver_key else "3.0"
                    B = parse_cvss31_exploitability(cvss_vec) or 0.0
                    break
            if B > 0:
                break

    if not B:
        return {"error": f"No CVSS v3.x vector available for {cve_id} from MITRE"}

    # KEV — not available from MITRE API, will be checked separately
    # ICS — check references
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
        "kev": False,  # KEV checked separately via NVD or CISA catalog
        "kev_added": "",
        "kev_due": "",
        "kev_name": "",
        "ics_advisory": ics,
        "ics_urls": ics_urls,
        "impact_score": 0.0,  # not available from MITRE
        "source": "mitre_cve",  # flag that this came from MITRE fallback
    }


def nvd_search_keyword(keyword: str, api_key: str = None, max_results: int = 50) -> list[dict]:
    """Search NVD by keyword, return parsed CVE list."""
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": min(max_results, 100),
        "startIndex": 0,
        "noRejected": "",
    }
    query = urllib.parse.urlencode(params)
    url = f"{NVD_URL}?{query}"

    headers = {"Accept": "application/json", "User-Agent": "DTVSS/6.0"}
    if api_key:
        headers["apiKey"] = api_key

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return [{"error": f"NVD search error: {str(e)}"}]

    results = []
    for vuln in data.get("vulnerabilities", []):
        parsed = _parse_nvd_cve(vuln.get("cve", {}))
        if parsed and "error" not in parsed:
            results.append(parsed)

    return results


def _parse_nvd_cve(cve: dict) -> Optional[dict]:
    """Extract B, KEV, ICS advisory from NVD CVE object."""
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    desc = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        ""
    )

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
    elif m.get("cvssMetricV2"):
        # v2.0 — outside calibration scope, flag but don't score
        return {
            "cve_id": cve_id,
            "error": "CVSS v2.0 only — outside DTVSS calibration scope",
            "cvss_version": "2.0",
        }
    else:
        return {"cve_id": cve_id, "error": "No CVSS score available"}

    if not B:
        return {"cve_id": cve_id, "error": "Exploitability sub-score is 0"}

    # KEV — embedded in NVD response
    kev = bool(cve.get("cisaExploitAdd"))
    kev_added = cve.get("cisaExploitAdd", "")
    kev_due = cve.get("cisaActionDue", "")
    kev_name = cve.get("cisaVulnerabilityName", "")

    # ICS advisory — from reference URLs
    refs = [r.get("url", "") for r in cve.get("references", [])]
    ics = any(frag in url for url in refs for frag in ICS_URL_FRAGMENTS)
    ics_urls = [u for u in refs if any(f in u for f in ICS_URL_FRAGMENTS)]

    return {
        "cve_id": cve_id,
        "description": desc[:300] + ("..." if len(desc) > 300 else ""),
        "B": round(float(B), 3),
        "cvss_version": cvss_ver,
        "cvss_vector": cvss_vec,
        "severity": sev,
        "published": cve.get("published", ""),
        "kev": kev,
        "kev_added": kev_added,
        "kev_due": kev_due,
        "kev_name": kev_name,
        "ics_advisory": ics,
        "ics_urls": ics_urls,
        "impact_score": round(float(impact), 3),
    }


def epss_lookup(cve_ids: list[str]) -> dict:
    """Batch lookup EPSS scores. Returns dict of cve_id -> {epss, percentile, date}."""
    if not cve_ids:
        return {}

    results = {}
    # EPSS API supports comma-separated CVE IDs
    batch = ",".join(cve_ids[:100])  # max 100 per request
    params = f"?cve={batch}"

    try:
        req = urllib.request.Request(
            EPSS_URL + params,
            headers={"Accept": "application/json", "User-Agent": "DTVSS/6.0"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        if data and data.get("data"):
            for row in data["data"]:
                results[row["cve"]] = {
                    "epss": float(row["epss"]),
                    "percentile": float(row["percentile"]),
                    "date": row.get("date", ""),
                }
    except Exception as e:
        pass  # EPSS failure is non-fatal; L(t) defaults to 0.0

    # Fill missing
    for cve_id in cve_ids:
        if cve_id not in results:
            results[cve_id] = {"epss": 0.0, "percentile": 0.0, "date": date.today().isoformat()}

    return results


# ═══════════════════════════════════════════════════════════════════════
# openFDA Device Classification (server-side only — never exposed to frontend)
# ═══════════════════════════════════════════════════════════════════════

OPENFDA_DEVICE_URL = "https://api.fda.gov/device/classification.json"

# FDA device class → TGA equivalent mapping
FDA_TO_TGA = {
    "1": None,   # Class I — no network-connected devices with CVEs
    "2": "IIb",  # FDA Class II ≈ TGA Class IIb for network-connected therapeutic devices
    "3": "III",  # FDA Class III = TGA Class III
}


def openfda_classify_device(device_name: str) -> Optional[dict]:
    """
    Look up device classification from openFDA.
    Returns TGA-equivalent class and FDA product details, or None.
    This runs server-side only — the user never sees the API call.
    """
    params = urllib.parse.urlencode({
        "search": f'device_name:"{device_name}"',
        "limit": 5,
    })
    url = f"{OPENFDA_DEVICE_URL}?{params}"

    try:
        req = urllib.request.Request(url, headers={
            "Accept": "application/json", "User-Agent": "DTVSS/6.0"
        })
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None

    results = data.get("results", [])
    if not results:
        return None

    # Find highest-risk classification among results
    best = None
    for r in results:
        fda_class = str(r.get("device_class", ""))
        tga_class = FDA_TO_TGA.get(fda_class)
        if tga_class is None:
            continue

        entry = {
            "fda_class": fda_class,
            "tga_class": tga_class,
            "device_name": r.get("device_name", ""),
            "medical_specialty": r.get("medical_specialty_description", ""),
            "product_code": r.get("product_code", ""),
            "definition": r.get("definition", "")[:200],
        }

        # Prefer highest risk class
        if best is None or fda_class > best["fda_class"]:
            best = entry

    return best


# ═══════════════════════════════════════════════════════════════════════
# CISA KEV Catalog — Direct check (fallback when NVD hasn't enriched)
# ═══════════════════════════════════════════════════════════════════════

_kev_cache = {"data": None, "fetched_at": 0}
KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_TTL = 3600  # refresh hourly


def cisa_kev_check(cve_id: str) -> Optional[dict]:
    """
    Check if a CVE is in the CISA KEV catalog directly.
    Caches the full catalog in memory, refreshes hourly.
    Returns KEV details or None.
    """
    import time as _time
    now = _time.time()

    # Refresh cache if stale
    if _kev_cache["data"] is None or (now - _kev_cache["fetched_at"]) > KEV_CACHE_TTL:
        try:
            req = urllib.request.Request(KEV_CATALOG_URL, headers={
                "Accept": "application/json", "User-Agent": "DTVSS/6.0"
            })
            with urllib.request.urlopen(req, timeout=15) as resp:
                catalog = json.loads(resp.read().decode("utf-8"))

            # Index by CVE ID for O(1) lookup
            indexed = {}
            for vuln in catalog.get("vulnerabilities", []):
                indexed[vuln.get("cveID", "")] = vuln

            _kev_cache["data"] = indexed
            _kev_cache["fetched_at"] = now
        except Exception:
            # If fetch fails and we have stale data, use it
            if _kev_cache["data"] is None:
                return None

    entry = _kev_cache["data"].get(cve_id)
    if not entry:
        return None

    return {
        "kev": True,
        "kev_added": entry.get("dateAdded", ""),
        "kev_due": entry.get("dueDate", ""),
        "kev_name": entry.get("vulnerabilityName", ""),
        "kev_action": entry.get("requiredAction", ""),
    }
