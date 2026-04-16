# DTVSS — API Clients for NVD and EPSS
# Copyright © 2026 Andrew Broglio. All rights reserved.
# Licensed under BSL 1.1

"""
Direct API clients for NVD v2 and EPSS.
No Anthropic API dependency. All public data sources.
"""

import fcntl
import json
import logging
import os
import re
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import date
from typing import Optional

from dtvss_engine import DESCRIPTION_MAX_LEN

log = logging.getLogger(__name__)

NVD_URL        = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL       = "https://api.first.org/data/v1/epss"
MITRE_CVE_URL  = "https://cveawg.mitre.org/api/cve"

# ── Helpers ─────────────────────────────────────────────────────────────

def _truncate_desc(text: str) -> str:
    """Truncate a CVE description to DESCRIPTION_MAX_LEN characters."""
    if len(text) <= DESCRIPTION_MAX_LEN:
        return text
    return text[:DESCRIPTION_MAX_LEN] + "..."


def _atomic_json_write(path: str, data) -> None:
    """
    Write *data* to *path* as JSON atomically (write to temp file, then rename).
    Uses the same directory as *path* so the rename is guaranteed to be on the
    same filesystem.  Acquires an exclusive flock before writing so concurrent
    gunicorn workers don't interleave.
    """
    dir_ = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(dir=dir_, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            json.dump(data, f)
            fcntl.flock(f, fcntl.LOCK_UN)
        os.replace(tmp_path, path)   # atomic on POSIX
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _locked_json_read(path: str):
    """Read JSON from *path* with a shared flock so we don't read a partial write."""
    with open(path) as f:
        fcntl.flock(f, fcntl.LOCK_SH)
        try:
            return json.load(f)
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


# ── NVD rate limiter ─────────────────────────────────────────────────────
# NVD allows 50 req/30 s with API key, 5 req/30 s without.
_nvd_last_call: float = 0.0
_nvd_rate_lock = threading.Lock()

def _nvd_rate_limit(api_key: bool) -> None:
    """Sleep only as long as needed to respect NVD rate limits."""
    global _nvd_last_call
    min_gap = 0.7 if api_key else 6.0
    with _nvd_rate_lock:
        elapsed = time.time() - _nvd_last_call
        if elapsed < min_gap:
            time.sleep(min_gap - elapsed)
        _nvd_last_call = time.time()


# ── CVE response cache ───────────────────────────────────────────────────
# NVD data (B score, KEV flag) changes at most daily.
# Cache assembled lookup results for 1 hour to avoid repeat round-trips.
CVE_CACHE_TTL   = 3600    # 1 hour
MAX_CVE_CACHE   = 2000    # max entries before LRU eviction
_CVE_CACHE_FILE = "/tmp/dtvss_cve_cache.json"

# Per-worker in-process write buffer — avoids disk read on repeat hits
# within the same gunicorn worker.
_cve_write_buffer: dict = {}


def _load_cve_cache() -> dict:
    try:
        return _locked_json_read(_CVE_CACHE_FILE)
    except Exception:
        return {}


def _save_cve_cache(cache: dict) -> None:
    try:
        if len(cache) > MAX_CVE_CACHE:
            sorted_keys = sorted(cache, key=lambda k: cache[k][1])
            for k in sorted_keys[:len(cache) - MAX_CVE_CACHE]:
                del cache[k]
        _atomic_json_write(_CVE_CACHE_FILE, cache)
    except Exception as exc:
        log.debug("CVE cache save failed: %s", exc)


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


# ── EPSS daily cache ──────────────────────────────────────────────────────
# EPSS publishes one update per day.
# Cache key is just today's date — all CVEs looked up on the same day share
# the same EPSS snapshot, so a giant sorted-CVE-list key is unnecessary.
_epss_cache: dict = {}        # {iso_date: {cve_id: {epss, percentile, date}}}
MAX_EPSS_CACHE = 7            # keep at most 7 days of snapshots


# ── Search results cache ─────────────────────────────────────────────────
# Caches /api/search keyword results for 5 minutes.
# Shared across all gunicorn workers via disk; in-process buffer avoids
# re-reading the file on every hit within the same worker.
SEARCH_CACHE_TTL   = 300    # 5 minutes
MAX_SEARCH_CACHE   = 500    # max entries before LRU eviction
_SEARCH_CACHE_FILE = "/tmp/dtvss_search_cache.json"
_search_write_buffer: dict = {}


def _search_cache_key(query: str, tga_class: str = "") -> str:
    """Normalised cache key — lowercase, collapsed whitespace, plus optional class."""
    normalised = " ".join(query.lower().split())
    return f"{normalised}|{tga_class}"


def _load_search_cache() -> dict:
    try:
        return _locked_json_read(_SEARCH_CACHE_FILE)
    except Exception:
        return {}


def _save_search_cache(cache: dict) -> None:
    try:
        if len(cache) > MAX_SEARCH_CACHE:
            sorted_keys = sorted(cache, key=lambda k: cache[k][1])
            for k in sorted_keys[:len(cache) - MAX_SEARCH_CACHE]:
                del cache[k]
        _atomic_json_write(_SEARCH_CACHE_FILE, cache)
    except Exception as exc:
        log.debug("Search cache save failed: %s", exc)


def get_cached_search(query: str, tga_class: str = "") -> list | None:
    """Check cache — shared across all gunicorn workers via disk."""
    key = _search_cache_key(query, tga_class)
    now = time.time()

    entry = _search_write_buffer.get(key)
    if entry and (now - entry[1]) < SEARCH_CACHE_TTL:
        return entry[0]

    cache = _load_search_cache()
    entry = cache.get(key)
    if entry and (now - entry[1]) < SEARCH_CACHE_TTL:
        _search_write_buffer[key] = entry
        return entry[0]

    return None


def set_cached_search(query: str, results: list, tga_class: str = "") -> None:
    """Write to disk cache so all gunicorn workers can read it."""
    key = _search_cache_key(query, tga_class)
    entry = (results, time.time())
    _search_write_buffer[key] = entry
    cache = _load_search_cache()
    cache[key] = entry
    _save_search_cache(cache)


# ── CVSS exploitability parsing ──────────────────────────────────────────
# Used as fallback when NVD hasn't enriched the CVE (backlog).
CVSS31_AV   = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
CVSS31_AC   = {"L": 0.77, "H": 0.44}
CVSS31_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # Scope Unchanged
CVSS31_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}   # Scope Changed
CVSS31_UI   = {"N": 0.85, "R": 0.62}


def parse_cvss31_exploitability(vector: str) -> Optional[float]:
    """
    Parse a CVSS v3.x or v4.0 vector string and compute the exploitability
    sub-score.  v3.x: 8.22 × AV × AC × PR × UI.
    v4.0: same AV/AC/PR/UI components with AT mapped to AC equivalent.
    Returns None if the vector cannot be parsed.
    """
    if not vector:
        return None
    if "CVSS:3" not in vector and "CVSS:4" not in vector:
        return None

    parts: dict[str, str] = {}
    for segment in vector.split("/"):
        if ":" in segment:
            k, v = segment.split(":", 1)
            parts[k] = v

    try:
        av = CVSS31_AV.get(parts.get("AV", ""))
        ui = CVSS31_UI.get(parts.get("UI", ""))

        # CVSS v4.0 uses AT (Attack Requirements) alongside AC.
        # Map AT:N → AC:L equivalent, AT:P → AC:H equivalent.
        ac = CVSS31_AC.get(parts.get("AC", ""))
        if ac is None and "AT" in parts:
            at_map = {"N": "L", "P": "H"}
            ac = CVSS31_AC.get(at_map.get(parts["AT"], ""))

        # CVSS v4.0 has no Scope — default to Unchanged for PR lookup.
        scope    = parts.get("S", "U")
        pr_table = CVSS31_PR_C if scope == "C" else CVSS31_PR_U
        pr       = pr_table.get(parts.get("PR", ""))

        if None in (av, ac, pr, ui):
            return None

        return round(8.22 * av * ac * pr * ui, 1)
    except Exception as exc:
        log.debug("CVSS vector parse failed for %r: %s", vector, exc)
        return None


def _extract_cvss_from_metrics(metrics_list: list) -> tuple[float, str, str, str]:
    """
    Shared helper: iterate a list of metric blocks (CNA or ADP format) and
    return (B, cvss_version, cvss_vector, severity).  Prefers newer CVSS
    versions.  Returns (0.0, "", "", "") if nothing usable is found.

    Previously this logic was duplicated across mitre_lookup_cve (CNA block),
    mitre_lookup_cve (ADP block), and _parse_nvd_cve.
    """
    VERSION_KEYS    = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]
    VERSION_LABELS  = {"cvssV4_0": "4.0", "cvssV3_1": "3.1", "cvssV3_0": "3.0", "cvssV2_0": "2.0"}

    B = 0.0
    cvss_ver = cvss_vec = sev = ""

    for metric_block in metrics_list:
        for ver_key in VERSION_KEYS:
            if ver_key not in metric_block:
                continue
            cvss_data = metric_block[ver_key]
            cvss_vec  = cvss_data.get("vectorString", "")
            sev       = cvss_data.get("baseSeverity", "")
            cvss_ver  = VERSION_LABELS[ver_key]

            if ver_key == "cvssV2_0":
                base = float(cvss_data.get("baseScore", 0) or 0)
                B    = round(min(base * 0.5, 10.0), 1) if base else 0.0
            else:
                B = parse_cvss31_exploitability(cvss_vec) or 0.0
                if not B and ver_key == "cvssV4_0":
                    base = float(cvss_data.get("baseScore", 0) or 0)
                    B    = round(min(base * 0.5, 10.0), 1) if base else 0.0
            break       # found a version in this block

        if B > 0:
            break       # stop at first block that gave us a score

    return B, cvss_ver, cvss_vec, sev


ICS_URL_FRAGMENTS = (
    "ics-cert.us-cert.gov",
    "us-cert.cisa.gov/ics",
    "cisa.gov/news-events/ics-medical-advisories",
    "cisa.gov/news-events/ics-advisories",
    "/icsma-",
    "/icsa-",
)


# ── NVD lookup ───────────────────────────────────────────────────────────

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
    query  = urllib.parse.urlencode(params)
    url    = f"{NVD_URL}?{query}"

    headers = {"Accept": "application/json", "User-Agent": "DTVSS/6.0"}
    if api_key:
        headers["apiKey"] = api_key

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        log.debug("NVD lookup failed for %s: %s — trying MITRE fallback", cve_id, exc)
        mitre = mitre_lookup_cve(cve_id)
        if mitre and "error" not in mitre:
            _set_cached_cve(cve_id, mitre)
            return mitre
        return {"error": f"NVD API error: {exc}"}

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        log.debug("CVE %s not in NVD — trying MITRE fallback", cve_id)
        mitre = mitre_lookup_cve(cve_id)
        if mitre and "error" not in mitre:
            _set_cached_cve(cve_id, mitre)
            return mitre
        return {"error": f"CVE {cve_id} not found in NVD or MITRE"}

    cve    = vulns[0].get("cve", {})
    result = _parse_nvd_cve(cve)

    # If NVD returned the CVE but has no CVSS (unenriched/backlog), try MITRE.
    if result and "error" in result and "No CVSS" in result.get("error", ""):
        log.debug("CVE %s has no CVSS in NVD — trying MITRE fallback", cve_id)
        mitre = mitre_lookup_cve(cve_id)
        if mitre and "error" not in mitre:
            # Preserve KEV data from NVD if available.
            if cve.get("cisaExploitAdd"):
                mitre["kev"]       = True
                mitre["kev_added"] = cve.get("cisaExploitAdd", "")
                mitre["kev_due"]   = cve.get("cisaActionDue", "")
                mitre["kev_name"]  = cve.get("cisaVulnerabilityName", "")
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
    except Exception as exc:
        log.debug("MITRE lookup failed for %s: %s", cve_id, exc)
        return {"error": f"MITRE CVE API error: {exc}"}

    cna = data.get("containers", {}).get("cna", {})
    if not cna:
        return {"error": f"No CNA data for {cve_id}"}

    # Extract English description.
    desc = ""
    for d in cna.get("descriptions", []):
        if d.get("lang", "").startswith("en"):
            desc = d.get("value", "")
            break

    # Extract CVSS from CNA metrics first, then ADP (CISA Vulnrichment) as fallback.
    B, cvss_ver, cvss_vec, sev = _extract_cvss_from_metrics(cna.get("metrics", []))

    if not B:
        for adp in data.get("containers", {}).get("adp", []):
            B, cvss_ver, cvss_vec, sev = _extract_cvss_from_metrics(adp.get("metrics", []))
            if B:
                break

    if not B:
        return {"error": f"No CVSS scoring data published for {cve_id}"}

    # ICS advisory — check CNA references.
    refs     = [r.get("url", "") for r in cna.get("references", [])]
    ics      = any(frag in u for u in refs for frag in ICS_URL_FRAGMENTS)
    ics_urls = [u for u in refs if any(f in u for f in ICS_URL_FRAGMENTS)]

    published = data.get("cveMetadata", {}).get("datePublished", "")

    return {
        "cve_id":       cve_id,
        "description":  _truncate_desc(desc),
        "B":            round(float(B), 3),
        "cvss_version": cvss_ver,
        "cvss_vector":  cvss_vec,
        "severity":     sev,
        "published":    published,
        "kev":          False,   # checked separately via NVD or CISA catalog
        "kev_added":    "",
        "kev_due":      "",
        "kev_name":     "",
        "ics_advisory": ics,
        "ics_urls":     ics_urls,
        "impact_score": 0.0,     # not available from MITRE
        "source":       "mitre_cve",
    }


def nvd_search_keyword(keyword: str, api_key: str = None, max_results: int = 50) -> list[dict]:
    """Search NVD by keyword, return parsed CVE list."""
    params = {
        "keywordSearch":  keyword,
        "resultsPerPage": min(max_results, 100),
        "startIndex":     0,
        "noRejected":     "",
    }
    query   = urllib.parse.urlencode(params)
    url     = f"{NVD_URL}?{query}"
    headers = {"Accept": "application/json", "User-Agent": "DTVSS/6.0"}
    if api_key:
        headers["apiKey"] = api_key

    _nvd_rate_limit(bool(api_key))

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8")
            if raw.strip().startswith("<"):
                log.debug("NVD returned HTML for keyword=%r — skipping", keyword)
                return []
            data = json.loads(raw)
    except json.JSONDecodeError as exc:
        log.debug("NVD JSON decode error for keyword=%r: %s", keyword, exc)
        return []
    except Exception as exc:
        log.debug("NVD search failed for keyword=%r: %s", keyword, exc)
        return []

    results = []
    for vuln in data.get("vulnerabilities", []):
        parsed = _parse_nvd_cve(vuln.get("cve", {}))
        if parsed and "error" not in parsed:
            results.append(parsed)

    return results


def _parse_nvd_cve(cve: dict) -> Optional[dict]:
    """Extract B, KEV, ICS advisory from an NVD CVE object."""
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    desc = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        ""
    )

    B = 0.0
    cvss_ver = cvss_vec = sev = ""
    impact   = 0.0
    m        = cve.get("metrics", {})

    if m.get("cvssMetricV31"):
        x        = m["cvssMetricV31"][0]
        B        = float(x.get("exploitabilityScore", 0) or 0)
        impact   = float(x.get("impactScore", 0) or 0)
        cvss_ver = "3.1"
        cvss_vec = x.get("cvssData", {}).get("vectorString", "")
        sev      = x.get("cvssData", {}).get("baseSeverity", "")
    elif m.get("cvssMetricV30"):
        x        = m["cvssMetricV30"][0]
        B        = float(x.get("exploitabilityScore", 0) or 0)
        impact   = float(x.get("impactScore", 0) or 0)
        cvss_ver = "3.0"
        cvss_vec = x.get("cvssData", {}).get("vectorString", "")
        sev      = x.get("cvssData", {}).get("baseSeverity", "")
    elif m.get("cvssMetricV40"):
        # CVSS v4.0 — no exploitabilityScore sub-score in NVD response.
        # Extract vector and compute exploitability from components.
        x          = m["cvssMetricV40"][0]
        cvss_ver   = "4.0"
        cvss_vec   = x.get("cvssData", {}).get("vectorString", "")
        sev        = x.get("cvssData", {}).get("baseSeverity", "")
        base_score = float(x.get("cvssData", {}).get("baseScore", 0) or 0)
        B          = parse_cvss31_exploitability(cvss_vec) or 0.0
        if not B and base_score > 0:
            B = round(min(base_score * 0.5, 10.0), 1)
        impact = base_score - B if B else 0.0
    elif m.get("cvssMetricV2"):
        x        = m["cvssMetricV2"][0]
        cvss_ver = "2.0"
        cvss_vec = x.get("cvssData", {}).get("vectorString", "")
        sev      = x.get("cvssData", {}).get("baseSeverity", "")
        B        = float(x.get("exploitabilityScore", 0) or 0)
        impact   = float(x.get("impactScore", 0) or 0)
        if not B:
            return {"cve_id": cve_id, "error": "CVSS v2.0 only with no exploitability score",
                    "cvss_version": "2.0"}
    else:
        return {"cve_id": cve_id, "error": "No CVSS score available"}

    if not B:
        return {"cve_id": cve_id, "error": "Exploitability sub-score is 0"}

    kev       = bool(cve.get("cisaExploitAdd"))
    kev_added = cve.get("cisaExploitAdd", "")
    kev_due   = cve.get("cisaActionDue", "")
    kev_name  = cve.get("cisaVulnerabilityName", "")

    refs     = [r.get("url", "") for r in cve.get("references", [])]
    ics      = any(frag in u for u in refs for frag in ICS_URL_FRAGMENTS)
    ics_urls = [u for u in refs if any(f in u for f in ICS_URL_FRAGMENTS)]

    return {
        "cve_id":       cve_id,
        "description":  _truncate_desc(desc),
        "B":            round(float(B), 3),
        "cvss_version": cvss_ver,
        "cvss_vector":  cvss_vec,
        "severity":     sev,
        "published":    cve.get("published", ""),
        "kev":          kev,
        "kev_added":    kev_added,
        "kev_due":      kev_due,
        "kev_name":     kev_name,
        "ics_advisory": ics,
        "ics_urls":     ics_urls,
        "impact_score": round(float(impact), 3),
    }


# ── EPSS lookup ──────────────────────────────────────────────────────────

def epss_lookup(cve_ids: list[str]) -> dict:
    """
    Batch lookup EPSS scores.
    Returns dict of cve_id → {epss, percentile, date}.

    Cache key is today's date — EPSS publishes one update per day, so all
    CVEs seen on the same day share the same snapshot.  The old approach of
    using a sorted CVE list as the key produced unnecessarily large keys and
    prevented cache hits across different search queries.
    """
    if not cve_ids:
        return {}

    today = date.today().isoformat()

    # Check per-date snapshot cache.
    snapshot = _epss_cache.get(today)

    # Find which IDs are missing from today's snapshot.
    missing = [c for c in cve_ids if not snapshot or c not in snapshot]

    if missing:
        fetched: dict = {}
        chunk_size = 100
        for i in range(0, len(missing), chunk_size):
            chunk  = missing[i:i + chunk_size]
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
                        fetched[row["cve"]] = {
                            "epss":       float(row["epss"]),
                            "percentile": float(row["percentile"]),
                            "date":       row.get("date", ""),
                        }
            except Exception as exc:
                # EPSS failure is non-fatal; L(t) defaults to 0.0 for this chunk.
                log.debug("EPSS lookup failed for chunk starting at %d: %s", i, exc)

        # Merge into today's snapshot.
        if today not in _epss_cache:
            _epss_cache[today] = {}
        _epss_cache[today].update(fetched)
        snapshot = _epss_cache[today]

        # Evict snapshots older than MAX_EPSS_CACHE days.
        if len(_epss_cache) > MAX_EPSS_CACHE:
            oldest = min(_epss_cache)
            del _epss_cache[oldest]

    results = {}
    for cve_id in cve_ids:
        results[cve_id] = snapshot.get(
            cve_id, {"epss": 0.0, "percentile": 0.0, "date": today}
        )

    return results


# ── openFDA Device Classification ────────────────────────────────────────
# Server-side only — never exposed to the frontend.

OPENFDA_DEVICE_URL = "https://api.fda.gov/device/classification.json"

FDA_TO_TGA = {
    "1": None,    # Class I — no network-connected devices with CVEs
    "2": "IIb",   # FDA Class II ≈ TGA Class IIb for network-connected therapeutic devices
    "3": "III",   # FDA Class III = TGA Class III
}


def openfda_classify_device(device_name: str) -> Optional[dict]:
    """
    Look up device classification from openFDA.
    Returns TGA-equivalent class and FDA product details, or None.
    """
    params = urllib.parse.urlencode({
        "search": f'device_name:"{device_name}"',
        "limit":  5,
    })
    url = f"{OPENFDA_DEVICE_URL}?{params}"

    try:
        req = urllib.request.Request(url, headers={
            "Accept": "application/json", "User-Agent": "DTVSS/6.0"
        })
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        log.debug("openFDA classify failed for %r: %s", device_name, exc)
        return None

    results = data.get("results", [])
    if not results:
        return None

    best = None
    for r in results:
        fda_class = str(r.get("device_class", ""))
        tga_class = FDA_TO_TGA.get(fda_class)
        if tga_class is None:
            continue
        entry = {
            "fda_class":         fda_class,
            "tga_class":         tga_class,
            "device_name":       r.get("device_name", ""),
            "medical_specialty": r.get("medical_specialty_description", ""),
            "product_code":      r.get("product_code", ""),
            "definition":        r.get("definition", "")[:200],
        }
        if best is None or fda_class > best["fda_class"]:
            best = entry

    return best


# ── CISA KEV Catalog ─────────────────────────────────────────────────────

_kev_cache       = {"data": None, "fetched_at": 0}
_kev_fetch_lock  = threading.Lock()   # prevents thundering herd on cold start
KEV_CATALOG_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_TTL    = 3600               # refresh hourly
KEV_DISK_CACHE   = "/tmp/dtvss_kev_cache.json"


def cisa_kev_check(cve_id: str) -> Optional[dict]:
    """
    Check if a CVE is in the CISA KEV catalog.
    Full catalog is cached in memory (refreshed hourly) and on disk (survives
    restarts).  A threading lock prevents multiple workers/threads from
    simultaneously fetching the ~2 MB catalog on cold start.
    Returns KEV details dict or None.
    """
    global _kev_cache
    now = time.time()

    # Fast path — in-memory cache is fresh.
    if _kev_cache["data"] is not None and (now - _kev_cache["fetched_at"]) <= KEV_CACHE_TTL:
        entry = _kev_cache["data"].get(cve_id)
        if not entry:
            return None
        return _kev_entry_to_dict(entry)

    # Slow path — acquire lock so only one thread fetches at a time.
    with _kev_fetch_lock:
        # Re-check after acquiring the lock (another thread may have populated it).
        now = time.time()
        if _kev_cache["data"] is not None and (now - _kev_cache["fetched_at"]) <= KEV_CACHE_TTL:
            entry = _kev_cache["data"].get(cve_id)
            return _kev_entry_to_dict(entry) if entry else None

        # Try disk cache first (survives restarts, not deploys).
        if _kev_cache["data"] is None:
            try:
                disk = _locked_json_read(KEV_DISK_CACHE)
                if now - disk.get("fetched_at", 0) < KEV_CACHE_TTL:
                    _kev_cache["data"]       = disk["data"]
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

                indexed = {
                    vuln.get("cveID", ""): vuln
                    for vuln in catalog.get("vulnerabilities", [])
                }
                _kev_cache["data"]       = indexed
                _kev_cache["fetched_at"] = now

                try:
                    _atomic_json_write(KEV_DISK_CACHE, {"data": indexed, "fetched_at": now})
                except Exception as exc:
                    log.debug("KEV disk write failed: %s", exc)

            except Exception as exc:
                log.warning("KEV catalog fetch failed: %s", exc)
                if _kev_cache["data"] is None:
                    return None

    entry = _kev_cache["data"].get(cve_id)
    return _kev_entry_to_dict(entry) if entry else None


def _kev_entry_to_dict(entry: dict) -> dict:
    return {
        "kev":        True,
        "kev_added":  entry.get("dateAdded", ""),
        "kev_due":    entry.get("dueDate", ""),
        "kev_name":   entry.get("vulnerabilityName", ""),
        "kev_action": entry.get("requiredAction", ""),
    }


# ── Dynamic Device Keyword Refresh from openFDA ──────────────────────────

_device_cache      = {"keywords": {}, "fetched_at": 0}
_device_fetch_lock = threading.Lock()
DEVICE_CACHE_TTL   = 86400   # refresh daily (24 hours)

FDA_SPECIALTIES = ["AN", "CV", "SU"]

FDA_PRODUCT_CODES = [
    "FRN", "MEB", "FPA", "DXY", "DTB",
    "LWS", "MHX", "QBJ", "OYC", "DSQ", "DQA",
]


def refresh_device_keywords() -> dict:
    """
    Fetch device names from openFDA classification API for known
    network-connected medical device product codes.
    Returns dict of {lowercase_device_name: tga_class}.
    Cached daily.  Thread-safe.
    """
    now = time.time()
    if _device_cache["keywords"] and (now - _device_cache["fetched_at"]) < DEVICE_CACHE_TTL:
        return _device_cache["keywords"]

    with _device_fetch_lock:
        # Re-check under lock.
        now = time.time()
        if _device_cache["keywords"] and (now - _device_cache["fetched_at"]) < DEVICE_CACHE_TTL:
            return _device_cache["keywords"]

        keywords: dict = {}

        for product_code in FDA_PRODUCT_CODES:
            try:
                params = urllib.parse.urlencode({
                    "search": f'product_code:"{product_code}"',
                    "limit":  10,
                })
                url = f"{OPENFDA_DEVICE_URL}?{params}"
                req = urllib.request.Request(url, headers={
                    "Accept": "application/json", "User-Agent": "DTVSS/6.0"
                })
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read().decode("utf-8"))

                for result in data.get("results", []):
                    device_name = result.get("device_name", "").strip().lower()
                    fda_class   = str(result.get("device_class", ""))
                    if not device_name or fda_class not in ("2", "3"):
                        continue
                    tga_class = "III" if fda_class == "3" else "IIb"
                    keywords[device_name] = tga_class
                    words = device_name.split()
                    if len(words) >= 2:
                        short = " ".join(words[:2])
                        if len(short) > 4:
                            keywords[short] = tga_class

            except Exception as exc:
                log.debug("openFDA device keyword fetch failed for %s: %s", product_code, exc)
                continue

            time.sleep(0.3)

        if keywords:
            _device_cache["keywords"]   = keywords
            _device_cache["fetched_at"] = now

        return keywords


# ── FDA Manufacturer Registry ────────────────────────────────────────────

OPENFDA_REG_URL = "https://api.fda.gov/device/registrationlisting.json"

_TARGET_MARKETS = {
    "US", "AU", "NZ", "GB",
    "AT","BE","BG","CY","CZ","DE","DK","EE","ES","FI",
    "FR","GR","HR","HU","IE","IT","LT","LU","LV","MT",
    "NL","PL","PT","RO","SE","SI","SK",
}

CONNECTED_PRODUCT_CODES = [
    "FRN","MEB","FPA","BSX","FLL","JAK","MYN","OZO",
    "DXY","DTB","DSQ","DXX","OYC",
    "LWS","DQA","DPS","DRE","PIB","PIE","NBW","PEI","QIH",
    "QBJ","KZH","NBE",
    "MHX","BRY","MHY",
]

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
    "cardiac science":   ("Cardiac Science",       "Cardiac Science"),
    "physio-control":    ("Physio-Control",        "Physio-Control"),
    "lifepoint":         ("LifePoint",             "LifePoint"),
    "natus":             ("Natus Medical",         "Natus"),
    "criticare":         ("Criticare",             "Criticare"),
    "datascope":         ("Datascope",             "Datascope"),
    "datex":             ("Datex-Ohmeda",          "Datex"),
    "ohmeda":            ("Datex-Ohmeda",          "Datex"),
    "nonin":             ("Nonin Medical",         "Nonin"),
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
    "st. jude medical":  ("St. Jude Medical",      "St. Jude"),
    "abbott diabetes":   ("Abbott",                "Abbott"),
    "abbott vascular":   ("Abbott",                "Abbott"),
}

_manufacturer_cache      = {"manufacturers": [], "lookup": {}, "fetched_at": 0}
_manufacturer_fetch_lock = threading.Lock()
MANUFACTURER_CACHE_TTL   = 86400   # 24 hours
MDM_DISK_CACHE           = "/tmp/dtvss_mdm_cache.json"

_SUFFIX_RE = re.compile(
    r',?\s*(inc\.?|llc|ltd\.?|gmbh|ag|corp\.?|corporation|co\.?|'
    r'limited|healthcare|medical|diabetes\s*care|usa|technology|'
    r'systems|cardiovascular|diagnostics|services|international|'
    r'americas|europe|global|north\s*america|holdings?).*$',
    re.IGNORECASE,
)


def _normalise_firm_name(firm_name: str) -> tuple[str, str]:
    """
    Normalise a raw FDA firm name to (display_name, nvd_term).
    Applies canonical name map first; falls through to title-casing.
    """
    firm_lower  = firm_name.lower().strip()
    clean_match = _SUFFIX_RE.sub("", firm_lower).strip(", ")

    if len(clean_match) < 2:
        return "", ""

    matched = _CANONICAL_NAMES.get(clean_match)
    if not matched:
        for key in sorted(_CANONICAL_NAMES, key=len, reverse=True):
            if clean_match.startswith(key) or key in clean_match.split():
                matched = _CANONICAL_NAMES[key]
                break

    if matched:
        return matched

    # Unknown firm — title-case, preserve known acronyms.
    _ACRONYMS = {"bd", "ge", "icu", "ecg", "cgm", "aed", "mri", "ct"}
    display = " ".join(
        w.upper() if w in _ACRONYMS else w.capitalize()
        for w in clean_match.split()
    )
    return display, display


def refresh_manufacturer_registry() -> list[dict]:
    """
    Fetch manufacturers of network-connected Class II/III medical devices
    from openFDA Registration & Listing API. Cached daily. Thread-safe.
    """
    now = time.time()

    if _manufacturer_cache["manufacturers"] and \
       (now - _manufacturer_cache["fetched_at"]) < MANUFACTURER_CACHE_TTL and \
       all("nvd_term" in m for m in _manufacturer_cache["manufacturers"]):
        return _manufacturer_cache["manufacturers"]

    with _manufacturer_fetch_lock:
        # Re-check under lock.
        now = time.time()
        if _manufacturer_cache["manufacturers"] and \
           (now - _manufacturer_cache["fetched_at"]) < MANUFACTURER_CACHE_TTL and \
           all("nvd_term" in m for m in _manufacturer_cache["manufacturers"]):
            return _manufacturer_cache["manufacturers"]

        # Try disk cache first.
        if not _manufacturer_cache["manufacturers"]:
            try:
                disk = _locked_json_read(MDM_DISK_CACHE)
                if (now - disk.get("fetched_at", 0)) < MANUFACTURER_CACHE_TTL and \
                   all("nvd_term" in m for m in disk.get("manufacturers", [])):
                    _manufacturer_cache["manufacturers"] = disk["manufacturers"]
                    _manufacturer_cache["fetched_at"]    = disk["fetched_at"]
                    _manufacturer_cache["lookup"]        = {
                        m["name"].lower(): m for m in disk["manufacturers"]
                    }
                    log.info("[mdm cache] loaded %d manufacturers from disk", len(disk["manufacturers"]))
                    return _manufacturer_cache["manufacturers"]
            except Exception:
                pass

        manufacturers: dict = {}
        _skip_keywords = [
            "distribution", "logistics", "supply chain", "sterilization",
            "sterilisation", "sterigenics", "isomedix", "synergy health",
            "dhl", "ups ", "ceva ", "flash global", "repair", "services",
            "warehouse", "operations center", "distripark", "donnelley",
            "sterile", "sterilis",
        ]
        _reg_deadline = time.time() + 120

        for pc in CONNECTED_PRODUCT_CODES:
            if time.time() > _reg_deadline:
                log.info("[manufacturer registry] deadline reached — returning partial result")
                break
            try:
                all_results = []
                for page_skip in range(0, 300, 100):
                    if time.time() > _reg_deadline:
                        break
                    params = urllib.parse.urlencode({
                        "search": f'products.product_code:"{pc}" AND establishment_type:"Manufacture Medical Device"',
                        "limit":  100,
                        "skip":   page_skip,
                    })
                    url = f"{OPENFDA_REG_URL}?{params}"
                    req = urllib.request.Request(url, headers={
                        "Accept": "application/json", "User-Agent": "DTVSS/6.0"
                    })
                    with urllib.request.urlopen(req, timeout=15) as resp:
                        page_data    = json.loads(resp.read().decode("utf-8"))
                    page_results     = page_data.get("results", [])
                    all_results.extend(page_results)
                    total_available  = page_data.get("meta", {}).get("results", {}).get("total", 0)
                    if len(all_results) >= total_available or len(page_results) < 100:
                        break
                    time.sleep(0.15)

                for result in all_results:
                    estab_types = result.get("establishment_type", [])
                    if not any(e == "Manufacture Medical Device" for e in estab_types):
                        continue

                    reg     = result.get("registration", {})
                    country = reg.get("iso_country_code", "").upper().strip()
                    if country and country not in _TARGET_MARKETS:
                        continue

                    prop      = result.get("proprietor", {})
                    firm_name = prop.get("firm_name", "").strip()
                    if not firm_name:
                        firm_name = reg.get("name", "").strip()
                    if not firm_name or len(firm_name) < 3:
                        continue

                    if any(kw in firm_name.lower() for kw in _skip_keywords):
                        continue

                    display_name, nvd_term = _normalise_firm_name(firm_name)
                    if not display_name:
                        continue

                    clean = display_name.upper()
                    if clean not in manufacturers:
                        manufacturers[clean] = {
                            "name":          display_name,
                            "nvd_term":      nvd_term,
                            "product_codes": set(),
                        }
                    manufacturers[clean]["product_codes"].add(pc)

            except Exception as exc:
                log.debug("Manufacturer registry fetch failed for %s: %s", pc, exc)
                continue

            time.sleep(0.3)

        canonical_display = {v[0].lower() for v in _CANONICAL_NAMES.values()}
        is_canonical      = lambda e: e["name"].lower() in canonical_display

        all_entries = [
            {"name": v["name"], "nvd_term": v.get("nvd_term", v["name"]),
             "product_codes": list(v["product_codes"]), "count": len(v["product_codes"])}
            for v in manufacturers.values()
        ]
        result_list = sorted(
            [e for e in all_entries if is_canonical(e) or e["count"] >= 2],
            key=lambda x: (0 if is_canonical(x) else 1, x["name"].lower()),
        )

        log.info("[mdm registry] %d total → %d after filtering", len(all_entries), len(result_list))

        lookup = {e["name"].lower(): e for e in result_list}

        if result_list:
            _manufacturer_cache["manufacturers"] = result_list
            _manufacturer_cache["lookup"]        = lookup
            _manufacturer_cache["fetched_at"]    = now
            try:
                _atomic_json_write(MDM_DISK_CACHE, {
                    "manufacturers": result_list,
                    "fetched_at":    now,
                })
                log.info("[mdm cache] persisted %d manufacturers to disk", len(result_list))
            except Exception as exc:
                log.debug("MDM disk write failed: %s", exc)

        return result_list


def get_manufacturer_list() -> list[dict]:
    """Return cached manufacturer list, refreshing if stale."""
    return refresh_manufacturer_registry()


# ── Manufacturer Search Expansion ────────────────────────────────────────

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
    that manufacturer's registered device categories AND actual product trade
    names.  Capped at 5 queries to avoid NVD rate limits.
    """
    if not _manufacturer_cache.get("lookup"):
        get_manufacturer_list()
    lookup = _manufacturer_cache.get("lookup", {})

    entry = lookup.get(manufacturer_name.lower())
    if not entry:
        return [manufacturer_name]

    nvd_term = entry.get("nvd_term", manufacturer_name)
    queries: list[str] = [nvd_term]

    added_terms: set[str] = set()
    for pc in entry.get("product_codes", []):
        for term in PRODUCT_CODE_TO_DEVICE_TERMS.get(pc, []):
            if term not in added_terms and len(queries) < 3:
                queries.append(f"{nvd_term} {term}")
                added_terms.add(term)

    try:
        result       = refresh_manufacturer_product_names(manufacturer_name)
        product_names = result.get(manufacturer_name.lower(), [])
        for product in product_names[:2]:
            if len(queries) < 5:
                queries.append(f"{nvd_term} {product}")
    except Exception as exc:
        log.debug("Product name expansion failed for %r: %s", manufacturer_name, exc)

    return queries


# ── 510(k) Product Name Lookup ───────────────────────────────────────────

OPENFDA_510K_URL       = "https://api.fda.gov/device/510k.json"
_product_name_cache    = {"by_manufacturer": {}, "per_mdm_fetched": {}}
PRODUCT_NAME_CACHE_TTL = 86400
_PRODUCT_NAME_CACHE_FILE = "/tmp/dtvss_product_names.json"

_GENERIC_SUFFIX_RE = re.compile(
    r'\s*(infusion pump|insulin pump|pacemaker|defibrillator|'
    r'monitor|ventilator|system|device|pump|implant).*$',
    re.IGNORECASE,
)


def _load_product_name_cache() -> dict:
    try:
        data = _locked_json_read(_PRODUCT_NAME_CACHE_FILE)
        if (time.time() - data.get("fetched_at", 0)) < PRODUCT_NAME_CACHE_TTL:
            return data.get("by_manufacturer", {})
    except Exception:
        pass
    return {}


def _save_product_name_cache() -> None:
    try:
        _atomic_json_write(_PRODUCT_NAME_CACHE_FILE, {
            "by_manufacturer": _product_name_cache["by_manufacturer"],
            "fetched_at":      time.time(),
        })
    except Exception as exc:
        log.debug("Product name cache write failed: %s", exc)


def refresh_manufacturer_product_names(manufacturer_name: str = None) -> dict:
    """
    Fetch actual product trade names for a manufacturer from FDA 510(k) API.
    Lazy-cached per manufacturer for 24 hours.
    """
    now = time.time()

    if manufacturer_name is None:
        return _product_name_cache["by_manufacturer"]

    key = manufacturer_name.lower()

    if not _product_name_cache["by_manufacturer"]:
        disk = _load_product_name_cache()
        if disk:
            _product_name_cache["by_manufacturer"] = disk

    cached    = _product_name_cache["by_manufacturer"].get(key)
    cached_at = _product_name_cache["per_mdm_fetched"].get(key, 0)

    if cached is not None and (now - cached_at) < PRODUCT_NAME_CACHE_TTL:
        return {key: cached}

    if not _manufacturer_cache.get("lookup"):
        get_manufacturer_list()
    entry = _manufacturer_cache.get("lookup", {}).get(key)
    if not entry:
        return {}

    product_names: set[str] = set()

    for pc in entry.get("product_codes", []):
        if pc not in PRODUCT_CODE_TO_DEVICE_TERMS:
            continue
        try:
            params = urllib.parse.urlencode({
                "search": f'applicant:"{manufacturer_name}" AND product_code:"{pc}"',
                "limit":  15,
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

                cleaned = device_name
                for prefix in [manufacturer_name, manufacturer_name.upper(), manufacturer_name.lower()]:
                    if cleaned.lower().startswith(prefix.lower()):
                        cleaned = cleaned[len(prefix):].strip(", -:")

                cleaned = _GENERIC_SUFFIX_RE.sub("", cleaned).strip()
                if cleaned and 3 <= len(cleaned) <= 40:
                    product_names.add(cleaned)

        except Exception as exc:
            log.debug("510(k) lookup failed for %r / %s: %s", manufacturer_name, pc, exc)
            continue

    final_list = list(product_names)[:10]

    _product_name_cache["by_manufacturer"][key]  = final_list
    _product_name_cache["per_mdm_fetched"][key]  = now
    _save_product_name_cache()

    return {key: final_list}
