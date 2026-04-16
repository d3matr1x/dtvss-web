# DTVSS — API Clients for NVD and EPSS
# Copyright © 2026 Andrew Broglio. All rights reserved.
# Licensed under BSL 1.1

"""
Direct API clients for NVD v2 and EPSS.
No Anthropic API dependency. All public data sources.
"""

import json
import os
import re
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import date
from typing import Optional

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
MITRE_CVE_URL = "https://cveawg.mitre.org/api/cve"

# ── NVD rate limiter ────────────────────────────────────────────────────
# NVD allows 50 req/30 s with API key, 5 req/30 s without.
# Sleep only the remaining gap since the last call instead of always sleeping.
_nvd_last_call: float = 0.0

def _nvd_rate_limit(api_key: bool) -> None:
    """Sleep only as long as needed to respect NVD rate limits."""
    global _nvd_last_call
    min_gap = 0.7 if api_key else 6.0
    elapsed = time.time() - _nvd_last_call
    if elapsed < min_gap:
        time.sleep(min_gap - elapsed)
    _nvd_last_call = time.time()

# ── CVE response cache ──────────────────────────────────────────────────
# NVD data (B score, KEV flag) changes at most daily.
# Cache assembled lookup results for 1 hour to avoid repeat round-trips.
CVE_CACHE_TTL = 3600       # 1 hour
MAX_CVE_CACHE = 2000       # max entries before LRU eviction
_CVE_CACHE_FILE = "/tmp/dtvss_cve_cache.json"
_cve_write_buffer: dict = {}  # in-process buffer to avoid disk read on repeat hits

def _load_cve_cache() -> dict:
    try:
        with open(_CVE_CACHE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

def _save_cve_cache(cache: dict) -> None:
    try:
        if len(cache) > MAX_CVE_CACHE:
            sorted_keys = sorted(cache, key=lambda k: cache[k][1])
            for k in sorted_keys[:len(cache) - MAX_CVE_CACHE]:
                del cache[k]
        with open(_CVE_CACHE_FILE, "w") as f:
            json.dump(cache, f)
    except Exception:
        pass

def _get_cached_cve(cve_id: str) -> dict | None:
    now = time.time()
    entry = _cve_write_buffer.get(cve_id)
    if entry and (now - entry[1]) < CVE_CACHE_TTL:
        return entry[0]
    cache = _load_cve_cache()
    entry = cache.get(cve_id)
    if entry and (now - entry[1]) < CVE_CACHE_TTL:
        _cve_write_buffer[cve_id] = entry
        return entry[0]
    return None

def _set_cached_cve(cve_id: str, result: dict) -> None:
    entry = (result, time.time())
    _cve_write_buffer[cve_id] = entry
    cache = _load_cve_cache()
    cache[cve_id] = entry
    _save_cve_cache(cache)

# ── EPSS daily cache ────────────────────────────────────────────────────
# EPSS publishes one update per day. Cache by (sorted CVE list, date).
_epss_cache: dict = {}  # {cache_key: (result_dict, iso_date)}
MAX_EPSS_CACHE = 1000   # max entries before LRU eviction

def _epss_cache_key(cve_ids: list[str]) -> str:
    return ",".join(sorted(cve_ids))

# ── Search results cache ────────────────────────────────────────────────
# Caches /api/search keyword results for 5 minutes.
# Shared across all users — same query string hits cache regardless of who asks.
SEARCH_CACHE_TTL = 300      # 5 minutes
MAX_SEARCH_CACHE = 500      # max entries before LRU eviction
_SEARCH_CACHE_FILE = "/tmp/dtvss_search_cache.json"

# Small in-process write buffer — avoids disk read on every hit within same worker
_search_write_buffer: dict = {}

def _search_cache_key(query: str, tga_class: str = "") -> str:
    """Normalised cache key — lowercase, collapsed whitespace, plus optional class."""
    normalised = " ".join(query.lower().split())
    return f"{normalised}|{tga_class}"

def _load_search_cache() -> dict:
    """Load full cache from disk. Returns {} on any error."""
    try:
        with open(_SEARCH_CACHE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

def _save_search_cache(cache: dict) -> None:
    """Persist cache to disk atomically. Trims to MAX_SEARCH_CACHE entries."""
    try:
        if len(cache) > MAX_SEARCH_CACHE:
            # Evict oldest entries
            sorted_keys = sorted(cache, key=lambda k: cache[k][1])
            for k in sorted_keys[:len(cache) - MAX_SEARCH_CACHE]:
                del cache[k]
        with open(_SEARCH_CACHE_FILE, "w") as f:
            json.dump(cache, f)
    except Exception:
        pass

def get_cached_search(query: str, tga_class: str = "") -> list | None:
    """Check disk cache — shared across all gunicorn workers."""
    key = _search_cache_key(query, tga_class)
    now = time.time()

    # Check in-process buffer first (avoids disk read for repeat hits in same worker)
    entry = _search_write_buffer.get(key)
    if entry and (now - entry[1]) < SEARCH_CACHE_TTL:
        return entry[0]

    # Check disk cache (written by any worker)
    cache = _load_search_cache()
    entry = cache.get(key)
    if entry and (now - entry[1]) < SEARCH_CACHE_TTL:
        _search_write_buffer[key] = entry  # warm the in-process buffer
        return entry[0]

    return None

def set_cached_search(query: str, results: list, tga_class: str = "") -> None:
    """Write to disk cache so all gunicorn workers can read it."""
    key = _search_cache_key(query, tga_class)
    entry = (results, time.time())

    # Update in-process buffer
    _search_write_buffer[key] = entry

    # Load, merge, save to disk
    cache = _load_search_cache()
    cache[key] = entry
    _save_search_cache(cache)

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

        # CVSS v4.0 doesn't have Scope — default to Unchanged for PR lookup
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
    Results cached for 1 hour.
    """
    cached = _get_cached_cve(cve_id)
    if cached is not None:
        return cached

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
            _set_cached_cve(cve_id, mitre)
            return mitre
        return {"error": f"NVD API error: {str(e)}"}

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        # CVE not in NVD — try MITRE
        mitre = mitre_lookup_cve(cve_id)
        if mitre and "error" not in mitre:
            _set_cached_cve(cve_id, mitre)
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
            _set_cached_cve(cve_id, mitre)
            return mitre

    if result and "error" not in result:
        _set_cached_cve(cve_id, result)
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

    # Try CNA metrics — check all CVSS versions, prefer newer
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
                    # v2.0 — use vector components (AV, AC, Au)
                    # fall through: the parser won't handle v2.0, so approximate from base score
                    base = float(cvss_data.get("baseScore", 0))
                    B = round(min(base * 0.5, 10.0), 1) if base else 0.0
                else:
                    B = parse_cvss31_exploitability(cvss_vec) or 0.0
                    # v4.0 fallback: approximate from base score if vector parse fails
                    if not B and ver_key == "cvssV4_0":
                        base = float(cvss_data.get("baseScore", 0))
                        B = round(min(base * 0.5, 10.0), 1) if base else 0.0
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

    # Rate limit: NVD allows 50 requests per 30 seconds with API key, 5 without
    _nvd_rate_limit(bool(api_key))

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8")
            # Guard against HTML error pages
            if raw.strip().startswith("<"):
                return []
            data = json.loads(raw)
    except json.JSONDecodeError:
        return []  # Silent fail — caller continues with other queries
    except Exception:
        return []

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
    elif m.get("cvssMetricV40"):
        # CVSS v4.0 — no exploitabilityScore sub-score in NVD response
        # Extract vector and compute exploitability from v3.1-equivalent components
        x = m["cvssMetricV40"][0]
        cvss_ver = "4.0"
        cvss_vec = x.get("cvssData", {}).get("vectorString", "")
        sev = x.get("cvssData", {}).get("baseSeverity", "")
        base_score = float(x.get("cvssData", {}).get("baseScore", 0))

        # CVSS v4.0 vectors contain AV/AC/AT/PR/UI like v3.1
        # Parse exploitability from vector using v3.1-compatible components
        B = parse_cvss31_exploitability(cvss_vec) or 0.0

        # If vector parsing failed, estimate B from base score
        # Exploitability typically represents ~40-60% of base score
        if not B and base_score > 0:
            B = round(min(base_score * 0.5, 10.0), 1)

        impact = float(x.get("cvssData", {}).get("baseScore", 0)) - B if B else 0.0
    elif m.get("cvssMetricV2"):
        # v2.0 — compute exploitability from vector if available
        x = m["cvssMetricV2"][0]
        cvss_ver = "2.0"
        cvss_vec = x.get("cvssData", {}).get("vectorString", "")
        sev = x.get("cvssData", {}).get("baseSeverity", "")
        B = float(x.get("exploitabilityScore", 0))
        impact = float(x.get("impactScore", 0))

        # v2.0 exploitabilityScore is on 0-10 scale already
        if B:
            # Flag as v2.0 but still score it — better than returning nothing
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
    """Batch lookup EPSS scores. Returns dict of cve_id -> {epss, percentile, date}.
    Results cached for the calendar day (EPSS publishes one update per day)."""
    if not cve_ids:
        return {}

    today = date.today().isoformat()
    cache_key = _epss_cache_key(cve_ids)
    cached = _epss_cache.get(cache_key)
    if cached and cached[1] == today:
        return cached[0]

    results = {}
    # EPSS API supports comma-separated CVE IDs — chunk into batches of 100
    chunk_size = 100
    for i in range(0, len(cve_ids), chunk_size):
        chunk = cve_ids[i:i + chunk_size]
        params = f"?cve={','.join(chunk)}"
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
        except Exception:
            pass  # EPSS failure is non-fatal; L(t) defaults to 0.0 for this chunk

    # Fill missing
    for cve_id in cve_ids:
        if cve_id not in results:
            results[cve_id] = {"epss": 0.0, "percentile": 0.0, "date": today}

    if len(_epss_cache) >= MAX_EPSS_CACHE:
        oldest = min(_epss_cache, key=lambda k: _epss_cache[k][1] if isinstance(_epss_cache[k][1], float) else 0)
        del _epss_cache[oldest]
    _epss_cache[cache_key] = (results, today)
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
    now = time.time()

    KEV_DISK_CACHE = "/tmp/dtvss_kev_cache.json"

    # Refresh cache if stale
    if _kev_cache["data"] is None or (now - _kev_cache["fetched_at"]) > KEV_CACHE_TTL:
        # Try disk cache first (survives restarts, not deploys)
        if _kev_cache["data"] is None:
            try:
                with open(KEV_DISK_CACHE) as f:
                    disk = json.load(f)
                if now - disk.get("fetched_at", 0) < KEV_CACHE_TTL:
                    _kev_cache["data"] = disk["data"]
                    _kev_cache["fetched_at"] = disk["fetched_at"]
            except Exception:
                pass

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
                # Persist to disk for next cold start
                try:
                    with open(KEV_DISK_CACHE, "w") as f:
                        json.dump({"data": indexed, "fetched_at": now}, f)
                except Exception:
                    pass
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
    now = time.time()

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
            continue  # non-fatal — keep existing cache

        # Rate limit: openFDA allows ~240 requests/minute without key
        time.sleep(0.3)

    if keywords:
        _device_cache["keywords"] = keywords
        _device_cache["fetched_at"] = now

    return keywords


# ═══════════════════════════════════════════════════════════════════════
# FDA Manufacturer Registry — Daily cached from openFDA Registration API
# ═══════════════════════════════════════════════════════════════════════

OPENFDA_REG_URL = "https://api.fda.gov/device/registrationlisting.json"

# ISO 3166-1 alpha-2 country codes for the 5 target regulatory markets:
# FDA (US), TGA (AU), Medsafe (NZ), MHRA (GB), EU MDR (all 27 EU member states)
_TARGET_MARKETS = {
    "US",  # FDA
    "AU",  # TGA
    "NZ",  # Medsafe
    "GB",  # MHRA
    # EU MDR — all 27 member states
    "AT","BE","BG","CY","CZ","DE","DK","EE","ES","FI",
    "FR","GR","HR","HU","IE","IT","LT","LU","LV","MT",
    "NL","PL","PT","RO","SE","SI","SK",
}

# Product codes for network-connected medical devices (Class II and III)
# Comprehensive list covering all IoMT-relevant categories
CONNECTED_PRODUCT_CODES = [
    # Infusion / drug delivery
    "FRN",   # Pump, infusion
    "MEB",   # Pump, infusion, programmable
    "FPA",   # Pump, infusion, insulin
    "BSX",   # Pump, infusion, enteral
    "FLL",   # Pump, infusion, syringe
    "JAK",   # Drug delivery, implantable programmable
    "MYN",   # Drug infusion controller
    "OZO",   # Insulin pump system
    # Cardiac implantable / rhythm
    "DXY",   # Pacemaker, cardiac
    "DTB",   # Defibrillator, implantable
    "DSQ",   # Cardiac resynchronization therapy
    "DXX",   # Pacemaker programmer
    "OYC",   # Defibrillator, external / AED
    # Monitoring
    "LWS",   # Monitor, physiological, patient
    "DQA",   # Telemetry, physiological
    "DPS",   # Recorder, cardiac event
    "DRE",   # Monitor, cardiac / ECG
    "PIB",   # Monitoring system, physiological
    "PIE",   # Bedside monitor
    "NBW",   # Wearable monitoring
    "PEI",   # Remote patient monitoring
    "QIH",   # Home monitoring system
    # Glucose / diabetes
    "QBJ",   # Monitor, glucose, continuous (CGM)
    "KZH",   # Blood glucose meter, connected
    "NBE",   # Continuous glucose monitor
    # Respiratory
    "MHX",   # Ventilator, continuous
    "BRY",   # Ventilator, non-continuous / CPAP
    "MHY",   # Ventilator, high frequency
]

_manufacturer_cache = {"manufacturers": [], "lookup": {}, "fetched_at": 0}
MANUFACTURER_CACHE_TTL = 86400  # 24 hours


# Canonical name map: FDA raw name fragment → (display_name, nvd_search_term)
# Used for dedup and normalisation of known major MDMs.
# Firms not in this map pass through with their cleaned FDA name.
_CANONICAL_NAMES = {
    "medtronic":         ("Medtronic",             "Medtronic"),
    "abbott":            ("Abbott",                "Abbott"),
    "biotronik":         ("Biotronik",             "Biotronik"),
    "boston scientific": ("Boston Scientific",     "Boston Scientific"),
    "philips":           ("Philips",               "Philips"),
    "baxter":            ("Baxter",                "Baxter"),
    "draeger":           ("Dräger",                "Draeger"),
    "drager":            ("Dräger",                "Draeger"),
    "dräger":            ("Dräger",                "Draeger"),
    "draegerwerk":       ("Dräger",                "Draeger"),
    "icu medical":       ("ICU Medical",           "ICU Medical"),
    "zoll":              ("Zoll",                  "Zoll"),
    "becton dickinson":  ("BD (Becton Dickinson)", "BD"),
    "becton, dickinson": ("BD (Becton Dickinson)", "BD"),
    "becton":            ("BD (Becton Dickinson)", "BD"),
    "dexcom":            ("Dexcom",                "Dexcom"),
    "fresenius vial":    ("Fresenius Kabi",        "Fresenius"),
    "fresenius kabi":    ("Fresenius Kabi",        "Fresenius"),
    "fresenius":         ("Fresenius Kabi",        "Fresenius"),
    "mindray":           ("Mindray",               "Mindray"),
    "nihon kohden":      ("Nihon Kohden",          "Nihon Kohden"),
    "resmed":            ("ResMed",                "ResMed"),
    "tandem":            ("Tandem Diabetes",       "Tandem"),
    "smiths medical":    ("Smiths Medical",        "Smiths Medical"),
    "smiths":            ("Smiths Medical",        "Smiths Medical"),
    "hamilton medical":  ("Hamilton Medical",      "Hamilton Medical"),
    "hamilton":          ("Hamilton Medical",      "Hamilton Medical"),
    "ge healthcare":     ("GE Healthcare",         "GE Healthcare"),
    "general electric":  ("GE Healthcare",         "GE Healthcare"),
    "b. braun":          ("B. Braun",              "B. Braun"),
    "b braun":           ("B. Braun",              "B. Braun"),
    "braun":             ("B. Braun",              "B. Braun"),
    "hospira":           ("Hospira",               "Hospira"),
    "insulet":           ("Insulet",               "Omnipod"),
    "getinge":           ("Getinge",               "Getinge"),
    "st jude":           ("St. Jude Medical",      "St. Jude"),
    "st. jude":          ("St. Jude Medical",      "St. Jude"),
    "carestream":        ("Carestream",            "Carestream"),
    "eitan":             ("Eitan Medical",         "Eitan"),
    "ivenix":            ("Ivenix",                "Ivenix"),
    "moog":              ("Moog",                  "Moog"),
    "carefusion":        ("CareFusion",            "CareFusion"),
    "alaris":            ("BD Alaris",             "Alaris"),
    "spacelabs":         ("Spacelabs Healthcare",  "Spacelabs"),
    "welch allyn":       ("Welch Allyn",           "Welch Allyn"),
    "masimo":            ("Masimo",                "Masimo"),
    "nellcor":           ("Nellcor",               "Nellcor"),
    "covidien":          ("Covidien",              "Covidien"),
    "hill-rom":          ("Hill-Rom",              "Hill-Rom"),
    "hillrom":           ("Hill-Rom",              "Hill-Rom"),
    "stryker":           ("Stryker",               "Stryker"),
    "omron":             ("Omron",                 "Omron"),
    "roche":             ("Roche",                 "Roche"),
    "siemens":           ("Siemens Healthineers",  "Siemens"),
    "abbott diabetes":   ("Abbott",                "Abbott"),
    "abbott vascular":   ("Abbott",                "Abbott"),
    "st. jude medical":  ("St. Jude Medical",      "St. Jude"),
    "cardiac science":   ("Cardiac Science",       "Cardiac Science"),
    "physio-control":    ("Physio-Control",        "Physio-Control"),
    "lifepoint":         ("LifePoint",             "LifePoint"),
    "natus":             ("Natus Medical",         "Natus"),
    "criticare":         ("Criticare",             "Criticare"),
    "datascope":         ("Datascope",             "Datascope"),
    "datex":             ("Datex-Ohmeda",          "Datex"),
    "ohmeda":            ("Datex-Ohmeda",          "Datex"),
    "criticare":         ("Criticare",             "Criticare"),
    "nonin":             ("Nonin Medical",         "Nonin"),
    "natus":             ("Natus Medical",         "Natus"),
    "shenzhen mindray":  ("Mindray",               "Mindray"),
    "edan":              ("Edan Instruments",      "Edan"),
    "contec":            ("Contec Medical",        "Contec"),
    "biotelemetry":      ("BioTelemetry",          "BioTelemetry"),
    "irhythm":           ("iRhythm",               "iRhythm"),
    "livanova":          ("LivaNova",              "LivaNova"),
    "nuvectra":          ("Nuvectra",              "Nuvectra"),
    "nevro":             ("Nevro",                 "Nevro"),
    "integer":           ("Integer Holdings",      "Integer"),
    "greatbatch":        ("Integer Holdings",      "Integer"),
}


def refresh_manufacturer_registry() -> list[dict]:
    """
    Fetch manufacturers of network-connected Class II/III medical devices
    from openFDA Registration & Listing API. Cached daily.
    Returns list of {name, nvd_term, product_codes, count} dicts, sorted by product breadth.
    Unknown firms (not in _CANONICAL_NAMES) pass through with their cleaned FDA name.
    """
    now = time.time()

    MDM_DISK_CACHE = "/tmp/dtvss_mdm_cache.json"

    if _manufacturer_cache["manufacturers"] and (now - _manufacturer_cache["fetched_at"]) < MANUFACTURER_CACHE_TTL:
        # Invalidate cache if entries are missing nvd_term (stale pre-deploy cache)
        if all("nvd_term" in m for m in _manufacturer_cache["manufacturers"]):
            return _manufacturer_cache["manufacturers"]

    # Try disk cache first — survives process restarts
    if not _manufacturer_cache["manufacturers"]:
        try:
            with open(MDM_DISK_CACHE) as f:
                disk = json.load(f)
            if (now - disk.get("fetched_at", 0)) < MANUFACTURER_CACHE_TTL and                all("nvd_term" in m for m in disk.get("manufacturers", [])):
                _manufacturer_cache["manufacturers"] = disk["manufacturers"]
                _manufacturer_cache["fetched_at"] = disk["fetched_at"]
                _manufacturer_cache["lookup"] = {m["name"].lower(): m for m in disk["manufacturers"]}
                print(f"[mdm cache] loaded {len(disk['manufacturers'])} manufacturers from disk")
                return _manufacturer_cache["manufacturers"]
        except Exception:
            pass

    manufacturers = {}  # name -> {product_codes, device_classes}

    _reg_deadline = time.time() + 120  # 120-second budget — 28 product codes × up to 3 pages each

    for pc in CONNECTED_PRODUCT_CODES:
        if time.time() > _reg_deadline:
            print(f"[manufacturer registry] deadline reached after {len(manufacturers)} entries — returning partial result")
            break
        try:
            # Filter to establishments that are MANUFACTURERS (not distributors, sterilisers, etc.)
            # Paginate: fetch up to 3 pages of 100 to capture all manufacturers
            all_results = []
            for page_skip in range(0, 300, 100):
                if time.time() > _reg_deadline:
                    break
                params = urllib.parse.urlencode({
                    "search": f'products.product_code:"{pc}" AND establishment_type:"Manufacture Medical Device"',
                    "limit": 100,
                    "skip": page_skip,
                })
                url = f"{OPENFDA_REG_URL}?{params}"
                req = urllib.request.Request(url, headers={
                    "Accept": "application/json", "User-Agent": "DTVSS/6.0"
                })
                with urllib.request.urlopen(req, timeout=15) as resp:
                    page_data = json.loads(resp.read().decode("utf-8"))
                page_results = page_data.get("results", [])
                all_results.extend(page_results)
                total_available = page_data.get("meta", {}).get("results", {}).get("total", 0)
                if len(all_results) >= total_available or len(page_results) < 100:
                    break  # got everything
                time.sleep(0.15)  # brief pause between pages

            for result in all_results:
                # Double-check establishment type at record level
                estab_types = result.get("establishment_type", [])
                if not any(e == "Manufacture Medical Device" for e in estab_types):
                    continue

                # Filter to 5 target markets: FDA, TGA, Medsafe, MHRA, EU MDR
                reg = result.get("registration", {})
                country = reg.get("iso_country_code", "").upper().strip()
                if country and country not in _TARGET_MARKETS:
                    continue

                # Extract manufacturer name from proprietor or establishment
                prop = result.get("proprietor", {})
                firm_name = prop.get("firm_name", "").strip()
                if not firm_name:
                    firm_name = result.get("registration", {}).get("name", "").strip()

                if not firm_name or len(firm_name) < 3:
                    continue

                # Skip obvious non-manufacturers
                skip_keywords = [
                    "distribution", "logistics", "supply chain", "sterilization",
                    "sterilisation", "sterigenics", "isomedix", "synergy health",
                    "dhl", "ups ", "ceva ", "flash global", "repair", "services",
                    "warehouse", "operations center", "distripark", "donnelley",
                    "sterile", "sterilis",
                ]
                if any(kw in firm_name.lower() for kw in skip_keywords):
                    continue

                # ── Name normalisation ──────────────────────────────────
                # CANONICAL_NAMES: known firms that need display name cleanup
                # or dedup (e.g. "Becton, Dickinson" → "BD (Becton Dickinson)").
                # Firms NOT in this map pass through with their cleaned FDA name.
                # Values: (display_name, nvd_search_term)
                firm_lower = firm_name.lower().strip()
                cleanmatch = re.sub(
                    r',?\s*(inc\.?|llc|ltd\.?|gmbh|ag|corp\.?|corporation|co\.?|'
                    r'limited|healthcare|medical|diabetes\s*care|usa|technology|'
                    r'systems|cardiovascular|diagnostics|services|international|'
                    r'americas|europe|global|north\s*america|holdings?).*$',
                    '', firm_lower, flags=re.IGNORECASE
                ).strip(",. ")

                if len(cleanmatch) < 2:
                    continue

                matched = _CANONICAL_NAMES.get(cleanmatch)
                if not matched:
                    for key in sorted(_CANONICAL_NAMES.keys(), key=len, reverse=True):
                        if cleanmatch.startswith(key) or key in cleanmatch.split():
                            matched = _CANONICAL_NAMES[key]
                            break

                if matched:
                    display_name, nvd_term = matched
                else:
                    # Unknown firm — pass through with title-cased cleaned name
                    # Capitalise each word, preserve known acronyms
                    display_name = " ".join(
                        w.upper() if w in ("bd","ge","icu","ecg","cgm","aed","mri","ct")
                        else w.capitalize()
                        for w in cleanmatch.split()
                    )
                    nvd_term = display_name  # use same for NVD search

                clean = display_name.upper()
                if clean not in manufacturers:
                    manufacturers[clean] = {
                        "name": display_name,
                        "nvd_term": nvd_term,
                        "product_codes": set(),
                    }
                manufacturers[clean]["product_codes"].add(pc)

        except Exception:
            continue

        # Rate limit
        time.sleep(0.3)

    # Build canonical name set for fast lookup
    canonical_display_names = {v[0].lower() for v in _CANONICAL_NAMES.values()}

    # Filter and sort:
    # - Always include known canonical manufacturers (in _CANONICAL_NAMES)
    # - Unknown manufacturers only if registered for 2+ product codes
    #   (proxy for a real multi-product IoMT company likely to have NVD CVEs)
    all_entries = [
        {"name": v["name"], "nvd_term": v.get("nvd_term", v["name"]),
         "product_codes": list(v["product_codes"]), "count": len(v["product_codes"])}
        for v in manufacturers.values()
    ]

    is_canonical = lambda e: e["name"].lower() in canonical_display_names
    result_list = sorted(
        [e for e in all_entries if is_canonical(e) or e["count"] >= 2],
        key=lambda x: (0 if is_canonical(x) else 1, x["name"].lower())
    )

    print(f"[mdm registry] {len(all_entries)} total → {len(result_list)} after filtering (canonical + 2+ product codes)")

    # Build quick lookup dict: lowercase display name -> entry
    lookup = {}
    for entry in result_list:
        lookup[entry["name"].lower()] = entry

    if result_list:
        _manufacturer_cache["manufacturers"] = result_list
        _manufacturer_cache["lookup"] = lookup
        _manufacturer_cache["fetched_at"] = now
        # Persist to disk for next cold start
        try:
            with open(MDM_DISK_CACHE, "w") as f:
                json.dump({
                    "manufacturers": [
                        {k: v for k, v in m.items() if k != "product_codes"}
                        | {"product_codes": m.get("product_codes", [])}
                        for m in result_list
                    ],
                    "fetched_at": now,
                }, f)
            print(f"[mdm cache] persisted {len(result_list)} manufacturers to disk")
        except Exception:
            pass

    return result_list


def get_manufacturer_list() -> list[dict]:
    """Return cached manufacturer list, refreshing if stale."""
    return refresh_manufacturer_registry()


# ═══════════════════════════════════════════════════════════════════════
# Manufacturer Search Expansion — Manufacturer + device terms (scoped search)
# ═══════════════════════════════════════════════════════════════════════

# Maps FDA product code → list of device terms to combine WITH manufacturer name
PRODUCT_CODE_TO_DEVICE_TERMS = {
    "FRN": ["infusion pump"],
    "MEB": ["infusion pump"],
    "FPA": ["insulin pump"],
    "BSX": ["enteral pump", "feeding pump"],
    "FLL": ["syringe pump"],
    "DXY": ["pacemaker"],
    "DTB": ["defibrillator", "ICD"],
    "DSQ": ["CRT", "cardiac resynchronization"],
    "DPS": ["cardiac monitor"],
    "LWS": ["patient monitor"],
    "DQA": ["telemetry"],
    "DRE": ["ECG monitor"],
    "MHX": ["ventilator"],
    "BRY": ["CPAP", "ventilator"],
    "QBJ": ["glucose monitor", "CGM"],
    "OYC": ["AED", "defibrillator"],
}


def build_manufacturer_search_queries(manufacturer_name: str) -> list[str]:
    """
    Given a manufacturer name, return list of NVD search queries scoped to
    that manufacturer's registered device categories AND actual product trade names.
    Capped at 5 queries to avoid NVD rate limits.
    """
    # Use cached lookup directly — get_manufacturer_list() reads disk on every call
    # if the in-process cache is empty, so trigger it once here
    if not _manufacturer_cache.get("lookup"):
        get_manufacturer_list()
    lookup = _manufacturer_cache.get("lookup", {})

    entry = lookup.get(manufacturer_name.lower())
    if not entry:
        return [manufacturer_name]

    # Use the NVD-indexed term as the search base — this is what NVD actually
    # has in CVE descriptions (e.g. "Tandem" not "Tandem Diabetes").
    nvd_term = entry.get("nvd_term", manufacturer_name)

    queries = []
    # Baseline: NVD search term alone
    queries.append(nvd_term)

    # Add category-based queries (up to 2)
    added_terms = set()
    for pc in entry.get("product_codes", []):
        for term in PRODUCT_CODE_TO_DEVICE_TERMS.get(pc, []):
            if term not in added_terms and len(queries) < 3:
                queries.append(f"{nvd_term} {term}")
                added_terms.add(term)

    # Add top product trade names (up to 2 more)
    try:
        result = refresh_manufacturer_product_names(manufacturer_name)
        product_names = result.get(manufacturer_name.lower(), [])
        for product in product_names[:2]:
            if len(queries) < 5:
                queries.append(f"{nvd_term} {product}")
    except Exception:
        pass

    return queries


# ═══════════════════════════════════════════════════════════════════════
# 510(k) Product Name Lookup — Real trade names from FDA premarket submissions
# ═══════════════════════════════════════════════════════════════════════

OPENFDA_510K_URL = "https://api.fda.gov/device/510k.json"

_product_name_cache = {"by_manufacturer": {}, "fetched_at": 0}
PRODUCT_NAME_CACHE_TTL = 86400   # 24 hours — checked daily
_PRODUCT_NAME_CACHE_FILE = "/tmp/dtvss_product_names.json"


def _load_product_name_cache() -> dict:
    """Load product name cache from disk. Returns empty dict on error."""
    try:
        with open(_PRODUCT_NAME_CACHE_FILE) as f:
            data = json.load(f)
        # Only use if not stale
        if (time.time() - data.get("fetched_at", 0)) < PRODUCT_NAME_CACHE_TTL:
            return data.get("by_manufacturer", {})
    except Exception:
        pass
    return {}


def _save_product_name_cache() -> None:
    """Persist product name cache to disk."""
    try:
        with open(_PRODUCT_NAME_CACHE_FILE, "w") as f:
            json.dump({
                "by_manufacturer": _product_name_cache["by_manufacturer"],
                "fetched_at": time.time(),
            }, f)
    except Exception:
        pass


def refresh_manufacturer_product_names(manufacturer_name: str = None) -> dict:
    """
    Fetch actual product trade names for a manufacturer from FDA 510(k) API.
    Lazy-cached per manufacturer for 24 hours.
    If manufacturer_name is None, returns full cache dict.
    """
    now = time.time()

    if manufacturer_name is None:
        return _product_name_cache["by_manufacturer"]

    key = manufacturer_name.lower()

    # Load from disk cache if in-process cache is empty (cold start / new worker)
    if not _product_name_cache["by_manufacturer"]:
        disk = _load_product_name_cache()
        if disk:
            _product_name_cache["by_manufacturer"] = disk

    cached = _product_name_cache["by_manufacturer"].get(key)
    cached_at = _product_name_cache.get("per_mdm_fetched", {}).get(key, 0)

    # Return cached if fresh (daily TTL)
    if cached is not None and (now - cached_at) < PRODUCT_NAME_CACHE_TTL:
        return {key: cached}

    # Fetch for this manufacturer only
    mdm_list = get_manufacturer_list()
    lookup = _manufacturer_cache.get("lookup", {})
    entry = lookup.get(key)

    if not entry:
        return {}

    product_names = set()

    for pc in entry.get("product_codes", []):
        if pc not in PRODUCT_CODE_TO_DEVICE_TERMS:
            continue
        try:
            params = urllib.parse.urlencode({
                "search": f'applicant:"{manufacturer_name}" AND product_code:"{pc}"',
                "limit": 15,
            })
            url = f"{OPENFDA_510K_URL}?{params}"
            req = urllib.request.Request(url, headers={
                "Accept": "application/json", "User-Agent": "DTVSS/6.0"
            })
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            for entry_510k in data.get("results", []):
                device_name = entry_510k.get("device_name", "").strip()
                if not device_name or len(device_name) < 4:
                    continue

                # Strip manufacturer prefix if present
                cleaned = device_name
                for prefix in [manufacturer_name, manufacturer_name.upper(), manufacturer_name.lower()]:
                    if cleaned.lower().startswith(prefix.lower()):
                        cleaned = cleaned[len(prefix):].strip(", -:")

                # Strip generic suffixes to leave product line name
                cleaned = re.sub(
                    r'\s*(infusion pump|insulin pump|pacemaker|defibrillator|'
                    r'monitor|ventilator|system|device|pump|implant).*$',
                    '', cleaned, flags=re.IGNORECASE
                ).strip()

                if cleaned and 3 <= len(cleaned) <= 40:
                    product_names.add(cleaned)

        except Exception:
            continue

    final_list = list(product_names)[:10]  # Limit to 10 names per manufacturer

    # Update in-process cache
    _product_name_cache["by_manufacturer"][key] = final_list
    if "per_mdm_fetched" not in _product_name_cache:
        _product_name_cache["per_mdm_fetched"] = {}
    _product_name_cache["per_mdm_fetched"][key] = now

    # Persist to disk so all workers and restarts share the cache
    _save_product_name_cache()

    return {key: final_list}
