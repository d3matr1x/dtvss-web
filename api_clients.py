# DTVSS - API Clients for NVD and EPSS
# Copyright © 2026 Andrew Broglio. All rights reserved.
# Licensed under BSL 1.1

"""
Direct API clients for NVD v2 and EPSS.
No Anthropic API dependency. All public data sources.

FIXED: EPSS batch processing bug - now handles 100+ CVE batches correctly
"""

import json
import logging
import math
import os
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import date
from typing import Optional

from security import safe_fetch_bytes

log = logging.getLogger("dtvss.api_clients")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
MITRE_CVE_URL = "https://cveawg.mitre.org/api/cve"


# ═══════════════════════════════════════════════════════════════════════
# M-3: Centralized safe JSON fetch
# ═══════════════════════════════════════════════════════════════════════

def _fetch_json(url: str, headers: Optional[dict] = None, timeout: int = 15,
                max_bytes: Optional[int] = None) -> dict:
    """
    Fetch JSON from an external API with SSRF protection, host allowlisting,
    response size cap, and timeout. Wraps security.safe_fetch_bytes.

    Replaces direct urllib.request.urlopen calls throughout this module
    so that every external HTTP request goes through the central security
    policy rather than re-implementing it per-callsite.

    Raises ValueError on SSRF policy rejection or oversized response.
    Raises json.JSONDecodeError if the body isn't valid JSON.
    Raises urllib.error.URLError / socket errors on network failure.
    Behaves like the previous urlopen+json.loads chain so existing
    try/except blocks at call sites still catch the same exception types.
    """
    # Lazy import to avoid circulars and to read the latest cap value if
    # security.MAX_RESPONSE_BYTES is changed at runtime.
    from security import MAX_RESPONSE_BYTES
    if max_bytes is None:
        max_bytes = MAX_RESPONSE_BYTES
    raw = safe_fetch_bytes(
        url,
        headers=headers or {},
        timeout=timeout,
        max_bytes=max_bytes,
    )
    return json.loads(raw.decode("utf-8"))

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

    Precision: rounds to 3 decimals to match the FIRST.org CVSS v3.1
    specification examples and the dataset-build path in build_dataset.py.
    Previously rounded to 1 decimal here, which caused the live API path
    and the calibration path to disagree on B for the same CVSS vector
    (and therefore on DTVSS score, sometimes crossing the 8.0 Critical
    threshold).
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

        return round(8.22 * av * ac * pr * ui, 3)
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
        data = _fetch_json(url, headers=headers, timeout=15)
    except Exception:
        # Log server-side for operator diagnosis; return a hardcoded
        # error message so no exception/stack-trace text flows up to
        # callers (and thence to clients via /api/cve).
        log.exception("NVD lookup failed for %s", cve_id)
        # NVD unreachable - try MITRE fallback
        mitre = mitre_lookup_cve(cve_id)
        if mitre and "error" not in mitre:
            return mitre
        return {"error": "NVD API unavailable"}

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


def is_lookup_error(result: Optional[dict]) -> bool:
    """
    Helper: True if a *_lookup_cve result is an error sentinel.

    Both nvd_lookup_cve() and mitre_lookup_cve() use the convention of
    returning either a valid result dict, an error dict {"error": "..."},
    or None. This helper centralises the "is this a real result?" check
    so future callers don't accidentally treat an error dict as success
    by writing `if result:` (which is True for both).

    Usage:
        result = mitre_lookup_cve(cve_id)
        if is_lookup_error(result):
            ...handle error...
        else:
            ...use result...
    """
    return result is None or (isinstance(result, dict) and "error" in result)


def mitre_lookup_cve(cve_id: str) -> Optional[dict]:
    """
    Fallback: look up CVE from MITRE CVE.org API when NVD hasn't enriched it.
    Extracts CVSS vector from CNA-provided metrics and computes exploitability.
    Addresses the NVD backlog where 72%+ of CVEs remain unenriched.

    Returns:
        - A populated dict with CVSS data on success.
        - {"error": "..."} on any failure (network, no CNA data, etc.).
        - Never returns None today, but typed Optional[dict] for forward
          compatibility with future callers that may want to distinguish
          "no result" from "error result".

    Callers should use is_lookup_error() rather than a bare truthiness check.
    """
    url = f"{MITRE_CVE_URL}/{cve_id}"

    try:
        data = _fetch_json(url, headers={
            "Accept": "application/json", "User-Agent": "DTVSS/6.0"
        }, timeout=15)
    except Exception:
        # Log server-side; hardcoded message avoids exception-data flow to clients.
        log.exception("MITRE CVE API lookup failed for %s", cve_id)
        return {"error": "MITRE CVE API unavailable"}

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
    unique_refs = []
    for ref_url in refs:
        if ref_url not in seen:
            seen.add(ref_url)
            unique_refs.append(ref_url)

    ics = any(frag in ref_url for ref_url in unique_refs for frag in ICS_URL_FRAGMENTS)
    ics_urls = [ref_url for ref_url in unique_refs if any(f in ref_url for f in ICS_URL_FRAGMENTS)]

    # M-5: same v4.0 approximation transparency as the NVD path
    result = {
        "cve_id": cve_id,
        "description": desc[:300] + ("..." if len(desc) > 300 else ""),
        "B": round(float(B), 3),
        "cvss_version": cvss_ver,
        "cvss_vector": cvss_vec,
        "severity": sev,
        "published": data.get("cveMetadata", {}).get("datePublished", "")[:10],
        "kev": False,  # KEV must be checked separately
        "kev_added": "",
        "kev_due": "",
        "kev_name": "",
        "ics_advisory": ics,
        "ics_urls": ics_urls,
        "impact_score": 0.0,  # not available from MITRE
        "source": "mitre_cve",  # flag that this came from MITRE fallback
    }
    if cvss_ver == "4.0":
        result["cvss_v4_approximate"] = True
        result["note"] = (
            "B (exploitability sub-score) for CVSS v4.0 is approximated "
            "using the v3.1 formula with AT mapped to AC, because MITRE's "
            "v4.0 metric block does not expose an exploitability sub-score. "
            "The B value is a proxy, not a true v4.0 sub-score."
        )
    return result


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
        # M-3: _fetch_json applies SSRF policy + size cap. We still need
        # the HTML-error-page guard because NVD has historically returned
        # 200 OK with an HTML error body. _fetch_json will raise
        # JSONDecodeError on that case; we catch it below as before.
        data = _fetch_json(url, headers=headers, timeout=30)
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

    # F-02d: Guard against NaN/inf from upstream. Python's float("NaN")
    # succeeds silently, and NaN propagates through max()/min() clamps
    # because NaN comparisons always return False. Without this guard, a
    # poisoned NVD response with exploitabilityScore="NaN" would produce
    # a NaN B that only gets caught at strict compute_dtvss (as a 422).
    # Defence in depth: stop it at the parser.
    def _safe_float(value, default=0.0):
        try:
            v = float(value)
        except (TypeError, ValueError):
            return default
        if math.isnan(v) or math.isinf(v):
            return default
        return v

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
        B = _safe_float(x.get("exploitabilityScore", 0))
        impact = _safe_float(x.get("impactScore", 0))
        cvss_ver = "3.1"
        cvss_vec = x.get("cvssData", {}).get("vectorString", "")
        sev = x.get("cvssData", {}).get("baseSeverity", "")
    elif m.get("cvssMetricV30"):
        x = pick_best(m["cvssMetricV30"])
        B = _safe_float(x.get("exploitabilityScore", 0))
        impact = _safe_float(x.get("impactScore", 0))
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

        impact = _safe_float(x.get("cvssData", {}).get("baseScore", 0)) - B if B else 0.0
    elif m.get("cvssMetricV2"):
        # v2.0 - compute exploitability from vector if available
        x = pick_best(m["cvssMetricV2"])
        cvss_ver = "2.0"
        cvss_vec = x.get("cvssData", {}).get("vectorString", "")
        sev = x.get("cvssData", {}).get("baseSeverity", "")
        B = _safe_float(x.get("exploitabilityScore", 0))
        impact = _safe_float(x.get("impactScore", 0))

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

    # M-5: CVSS v4.0 transparency flag.
    # NVD's v4.0 metric block does not expose an exploitability sub-score
    # the way v3.x does. We approximate it by parsing the v4.0 vector
    # with the v3.1 formula (mapping AT→AC). This is a reasonable proxy
    # but is NOT a true v4.0 sub-score, so we surface the approximation
    # explicitly to API consumers and patent reproducibility checkers.
    result = {
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
    if cvss_ver == "4.0":
        result["cvss_v4_approximate"] = True
        result["note"] = (
            "B (exploitability sub-score) for CVSS v4.0 is approximated "
            "using the v3.1 formula with AT mapped to AC, because NVD's "
            "v4.0 metric block does not expose an exploitability sub-score. "
            "The B value is a proxy, not a true v4.0 sub-score."
        )
    return result


def epss_lookup(cve_ids: list[str]) -> dict:
    """
    Batch lookup EPSS scores. Returns dict of cve_id -> {epss, percentile, date}.

    FIXED: Now handles 100+ CVEs by processing in chunks of 100.
    FIXED: Per-row error isolation — a single malformed row no longer discards
           the rest of the batch (a KeyError used to bubble out of the for loop
           into the outer except: pass).
    FIXED: Logs failures instead of swallowing them silently. EPSS failure is
           non-fatal for scoring (L defaults to 0.0) but operators need visible
           signal when scores are silently degrading to static B*H/10.
    """
    import logging
    _log = logging.getLogger("dtvss.epss")

    if not cve_ids:
        return {}

    results = {}

    # Process in chunks of 100 (EPSS API limit)
    for i in range(0, len(cve_ids), 100):
        chunk = cve_ids[i:i+100]
        batch = ",".join(chunk)
        params = f"?cve={batch}"

        try:
            data = _fetch_json(
                EPSS_URL + params,
                headers={"Accept": "application/json", "User-Agent": "DTVSS/6.0"},
                timeout=10,
            )
        except Exception as e:
            _log.warning(
                "EPSS batch %d/%d failed (%d CVEs): %s — affected scores will "
                "default to L=0.0 (static B*H/10).",
                (i // 100) + 1, (len(cve_ids) + 99) // 100, len(chunk), e,
            )
            data = None

        if data and isinstance(data.get("data"), list):
            for row in data["data"]:
                # Per-row try/except: previously a single malformed row took
                # down the whole batch via the outer except: pass.
                try:
                    cve = row.get("cve")
                    epss_val = row.get("epss")
                    pct_val = row.get("percentile")
                    if not cve or epss_val is None or pct_val is None:
                        continue
                    results[cve] = {
                        "epss": float(epss_val),
                        "percentile": float(pct_val),
                        "date": row.get("date", ""),
                    }
                except (TypeError, ValueError) as row_err:
                    _log.debug("EPSS row skipped (%s): %r", row_err, row)
                    continue

        # Rate limit between batches (be nice to EPSS API)
        if i + 100 < len(cve_ids):
            time.sleep(0.5)

    # Fill missing CVEs with default values
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
        data = _fetch_json(url, headers={
            "Accept": "application/json", "User-Agent": "DTVSS/6.0"
        }, timeout=10)
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

_kev_cache = {"data": None, "fetched_at": 0, "last_failure_at": 0}
KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_TTL = 3600       # refresh hourly on success
KEV_FAILURE_BACKOFF = 300  # after a failure or invalid catalog, wait 5 min
                           # before retrying. Without this, every request after
                           # an upstream outage triggers a fresh fetch attempt
                           # and re-validation of ~1 MB of JSON.


def cisa_kev_check(cve_id: str) -> Optional[dict]:
    """
    Check if a CVE is in the CISA KEV catalog.

    Returns:
        dict with keys {kev, kev_added, kev_due, kev_name, kev_action} when
        the CVE IS in the catalog. The "kev" key is always True when present
        (kept for backward compatibility with callers that may have relied
        on it; truthiness of the dict alone is also a valid presence test).

        None when the CVE is NOT in the catalog, OR when the catalog is
        unavailable (cold start + network failure, structurally invalid
        upstream response, etc.). Callers MUST treat None as "unknown",
        not "definitely not KEV-listed", because a transient outage looks
        identical to a genuine miss from a caller's perspective.

    Caches the full catalog in memory, refreshes hourly, backs off
    KEV_FAILURE_BACKOFF seconds on failure to avoid hammering upstream
    during outages.

    BUG FIX: previously, when validation failed or the fetch raised, the
    function returned None without recording the failure time. Every
    subsequent call within the cache TTL re-fetched and re-validated the
    bad catalog, hammering CISA. Now uses last_failure_at + KEV_FAILURE_BACKOFF.
    """
    import time as _time
    import logging as _logging
    _log = _logging.getLogger("dtvss.kev")
    now = _time.time()

    # Decide whether to attempt a refresh.
    cache_empty = _kev_cache["data"] is None
    cache_stale = (now - _kev_cache["fetched_at"]) > KEV_CACHE_TTL
    in_failure_backoff = (now - _kev_cache["last_failure_at"]) < KEV_FAILURE_BACKOFF

    # Attempt only when (empty OR stale) AND not currently in failure backoff.
    # Earlier draft of this fix bypassed backoff when cache_empty, which meant
    # repeated failures after a cold-start outage still hammered upstream.
    should_refresh = (cache_empty or cache_stale) and not in_failure_backoff

    if should_refresh:
        try:
            catalog = _fetch_json(
                KEV_CATALOG_URL,
                headers={"Accept": "application/json", "User-Agent": "DTVSS/6.0"},
                timeout=15,
            )

            # M-1: Validate the refreshed catalog before trusting it.
            from security import validate_kev_catalog
            indexed = validate_kev_catalog(catalog)
            if indexed is None:
                _log.warning("KEV catalog validation failed; backing off %ds.",
                             KEV_FAILURE_BACKOFF)
                _kev_cache["last_failure_at"] = now
                if _kev_cache["data"] is None:
                    return None
                # Otherwise fall through to use stale-but-good cached data
            else:
                _kev_cache["data"] = indexed
                _kev_cache["fetched_at"] = now
                _kev_cache["last_failure_at"] = 0  # clear failure state
        except Exception as e:
            _log.warning("KEV catalog fetch failed (%s); backing off %ds.",
                         e, KEV_FAILURE_BACKOFF)
            _kev_cache["last_failure_at"] = now
            if _kev_cache["data"] is None:
                return None

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
            data = _fetch_json(url, headers={
                "Accept": "application/json", "User-Agent": "DTVSS/6.0"
            }, timeout=10)

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
