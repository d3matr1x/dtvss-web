# DTVSS - API Clients for NVD and EPSS
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
    Parse a CVSS v3.x or v4.0 vector string and compute the exploitability sub-score.
    v3.x: Exploitability = 8.22 × AV × AC × PR × UI
    v4.0: Uses same AV/AC/PR/UI components with AT mapped to AC equivalent.
    Returns None if vector cannot be parsed.
    """
    if not vector:
        return None

    # Accept both v3.x and v4.0 vectors
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

        # CVSS v4.0 uses AT (Attack Requirements) alongside AC
        # Map AT:N → AC:L equivalent, AT:P → AC:H equivalent
        ac = CVSS31_AC.get(parts.get("AC", ""), None)
        if ac is None and "AT" in parts:
            at_map = {"N": "L", "P": "H"}  # None→Low complexity, Present→High complexity
            ac = CVSS31_AC.get(at_map.get(parts["AT"], ""), None)

        # CVSS v4.0 doesn't have Scope - default to Unchanged for PR lookup
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
        # NVD unreachable - try MITRE fallback
        mitre = mitre_lookup_cve(cve_id)
        if mitre and "error" not in mitre:
            return mitre
        return {"error": f"NVD API error: {str(e)}"}

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        # CVE not in NVD - try MITRE
        mitre = mitre_lookup_cve(cve_id)
        if mitre and "error" not in mitre:
            return mitre
        return {"error": f"CVE {cve_id} not found in NVD or MITRE"}

    cve = vulns[0].get("cve", {})
    result = _parse_nvd_cve(cve)

    # If NVD returned the CVE but has no usable CVSS data (unenriched/backlog), try MITRE
    if result and ("error" in result or result.get("B", 0) == 0):
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

    # Try CNA metrics - check all CVSS versions, prefer newer
    version_keys = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]
    version_labels = {"cvssV4_0": "4.0", "cvssV3_1": "3.1", "cvssV3_0": "3.0", "cvssV2_0": "2.0"}

    for metric_block in cna.get("metrics", []):
        for ver_key in version_keys:
            if ver_key in metric_block:
                cvss_data = metric_block[ver_key]
                cvss_vec = cvss_data.get("vectorString", "")
                sev = cvss_data.get("baseSeverity", "")
                cvss_ver = version_labels[ver_key]

                if ver_key == "cvssV2_0":
                    # v2.0 exploitabilityScore is provided directly in MITRE data
                    B = float(cvss_data.get("exploitabilityScore", 0))
                else:
                    B = parse_cvss31_exploitability(cvss_vec) or 0.0
                    # No approximation for v4.0 - if vector parse fails, B stays 0
                break
        if B > 0:
            break

    # Check ADP containers (CISA Vulnrichment provides CVSS here when CNA doesn't)
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
                        B = float(cvss_data.get("exploitabilityScore", 0))
                    else:
                        B = parse_cvss31_exploitability(cvss_vec) or 0.0
                    break
            if B > 0:
                break

    if not B:
        return {"error": f"No CVSS scoring data published for {cve_id}"}

    # KEV - not available from MITRE API, will be checked separately
    # ICS advisory detection - walk references from CNA AND every ADP container.
    # CISA Vulnrichment lives in ADP and often adds the ICSMA URL that the CNA
    # didn't, which is exactly the signal we want for a medical-device tool.
    refs = [r.get("url", "") for r in cna.get("references", []) if r.get("url")]
    for adp in data.get("containers", {}).get("adp", []):
        for r in adp.get("references", []):
            url = r.get("url", "")
            if url:
                refs.append(url)

    # De-duplicate while preserving order (CNA refs first, then ADP)
    seen = set()
    refs = [u for u in refs if not (u in seen or seen.add(u))]

    ics_urls = [u for u in refs if any(f in u for f in ICS_URL_FRAGMENTS)]
    ics = bool(ics_urls)

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
    import time as _time
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
            raw = resp.read().decode("utf-8")
            # Guard against HTML error pages
            if raw.strip().startswith("<"):
                return []
            data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    except Exception:
        return []
    finally:
        # Rate limit AFTER request: NVD allows 50 req/30s with key, 5 without
        _time.sleep(0.7 if api_key else 6.0)

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

    # Helper: prefer "Primary" (NVD-assigned) over "Secondary" (CNA-assigned)
    def pick_best(metrics_list):
        primary = [x for x in metrics_list if x.get("type") == "Primary"]
        return primary[0] if primary else metrics_list[0]

    if m.get("cvssMetricV31"):
        x = pick_best(m["cvssMetricV31"])
        B = float(x.get("exploitabilityScore", 0))
        impact = float(x.get("impactScore", 0))
        cvss_ver = "3.1"
        cvss_vec = x.get("cvssData", {}).get("vectorString", "")
        sev = x.get("cvssData", {}).get("baseSeverity", "")
    elif m.get("cvssMetricV30"):
        x = pick_best(m["cvssMetricV30"])
        B = float(x.get("exploitabilityScore", 0))
        impact = float(x.get("impactScore", 0))
        cvss_ver = "3.0"
        cvss_vec = x.get("cvssData", {}).get("vectorString", "")
        sev = x.get("cvssData", {}).get("baseSeverity", "")
    elif m.get("cvssMetricV40"):
        # CVSS v4.0 - no exploitabilityScore in NVD response
        # Parse exploitability from vector using v3.1-compatible AV/AC/PR/UI components
        x = pick_best(m["cvssMetricV40"])
        cvss_ver = "4.0"
        cvss_vec = x.get("cvssData", {}).get("vectorString", "")
        sev = x.get("cvssData", {}).get("baseSeverity", "")

        B = parse_cvss31_exploitability(cvss_vec) or 0.0
        # No approximation - if the vector can't be parsed, B stays 0
        # and the CVE is flagged as unscorable rather than guessing

        impact = float(x.get("cvssData", {}).get("baseScore", 0)) - B if B else 0.0
    elif m.get("cvssMetricV2"):
        # v2.0 - compute exploitability from vector if available
        x = pick_best(m["cvssMetricV2"])
        cvss_ver = "2.0"
        cvss_vec = x.get("cvssData", {}).get("vectorString", "")
        sev = x.get("cvssData", {}).get("baseSeverity", "")
        B = float(x.get("exploitabilityScore", 0))
        impact = float(x.get("impactScore", 0))

        # v2.0 exploitabilityScore is on 0-10 scale already
        if B:
            # Flag as v2.0 but still score it - better than returning nothing
            pass
        else:
            return {
                "cve_id": cve_id,
                "error": "CVSS v2.0 only with no exploitability score",
                "cvss_version": "2.0",
            }
    else:
        return {"cve_id": cve_id, "error": "No CVSS score available"}

    if not B:
        return {"cve_id": cve_id, "error": "Exploitability sub-score is 0"}

    # KEV - embedded in NVD response
    kev = bool(cve.get("cisaExploitAdd"))
    kev_added = cve.get("cisaExploitAdd", "")
    kev_due = cve.get("cisaActionDue", "")
    kev_name = cve.get("cisaVulnerabilityName", "")

    # ICS advisory - from reference URLs
    refs = [r.get("url", "") for r in cve.get("references", [])]
    ics = any(frag in ref_url for ref_url in refs for frag in ICS_URL_FRAGMENTS)
    ics_urls = [ref_url for ref_url in refs if any(f in ref_url for f in ICS_URL_FRAGMENTS)]

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
# openFDA Device Classification (server-side only - never exposed to frontend)
# ═══════════════════════════════════════════════════════════════════════

OPENFDA_DEVICE_URL = "https://api.fda.gov/device/classification.json"

# FDA device class → TGA equivalent mapping
FDA_TO_TGA = {
    "1": None,   # Class I - no network-connected devices with CVEs
    "2": "IIb",  # FDA Class II ≈ TGA Class IIb for network-connected therapeutic devices
    "3": "III",  # FDA Class III = TGA Class III
}


def openfda_classify_device(device_name: str) -> Optional[dict]:
    """
    Look up device classification from openFDA.
    Returns TGA-equivalent class and FDA product details, or None.
    This runs server-side only - the user never sees the API call.
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
# CISA KEV Catalog - Direct check (fallback when NVD hasn't enriched)
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


# ═══════════════════════════════════════════════════════════════════════
# Dynamic Device Keyword Refresh from openFDA (daily auto-update)
# ═══════════════════════════════════════════════════════════════════════

_device_cache = {"keywords": {}, "fetched_at": 0}
DEVICE_CACHE_TTL = 86400  # refresh daily (24 hours)

# openFDA medical specialty codes relevant to network-connected devices
FDA_SPECIALTIES = [
    "AN",  # Anesthesiology
    "CV",  # Cardiovascular
    "SU",  # General/Plastic Surgery (infusion)
]

# openFDA product codes for known network-connected device categories
FDA_PRODUCT_CODES = [
    "FRN",  # Infusion pump
    "MEB",  # Infusion pump, programmable
    "FPA",  # Insulin pump
    "DXY",  # Pacemaker
    "DTB",  # Implantable defibrillator
    "LWS",  # Patient monitor
    "MHX",  # Ventilator
    "QBJ",  # Continuous glucose monitor
    "OYC",  # External defibrillator
    "DSQ",  # Cardiac resynchronization
    "DQA",  # Telemetry system, physiological
]


def refresh_device_keywords() -> dict:
    """
    Fetch device names from openFDA classification API for known
    network-connected medical device product codes.
    Returns dict of {lowercase_device_name: tga_class}.
    Cached daily.
    """
    import time as _time
    now = _time.time()

    if _device_cache["keywords"] and (now - _device_cache["fetched_at"]) < DEVICE_CACHE_TTL:
        return _device_cache["keywords"]

    keywords = {}

    for product_code in FDA_PRODUCT_CODES:
        try:
            params = urllib.parse.urlencode({
                "search": f'product_code:"{product_code}"',
                "limit": 10,
            })
            url = f"{OPENFDA_DEVICE_URL}?{params}"
            req = urllib.request.Request(url, headers={
                "Accept": "application/json", "User-Agent": "DTVSS/6.0"
            })
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            for result in data.get("results", []):
                device_name = result.get("device_name", "").strip().lower()
                fda_class = str(result.get("device_class", ""))

                if not device_name or fda_class not in ("2", "3"):
                    continue

                tga_class = "III" if fda_class == "3" else "IIb"
                keywords[device_name] = tga_class

                # Also add shorter forms (first two words) for matching
                words = device_name.split()
                if len(words) >= 2:
                    short = " ".join(words[:2]).lower()
                    if len(short) > 4:  # avoid overly generic matches
                        keywords[short] = tga_class

        except Exception:
            continue  # non-fatal - keep existing cache

        # Rate limit: openFDA allows ~240 requests/minute without key
        import time as _time2
        _time2.sleep(0.3)

    if keywords:
        _device_cache["keywords"] = keywords
        _device_cache["fetched_at"] = now

    return keywords
