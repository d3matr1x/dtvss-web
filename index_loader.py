"""
DTVSS Index Loader — Serves pre-built CPE-based manufacturer/CVE data.
Loads from static/data/mdm_index.json (built by build_index.py).
Hourly background thread checks NVD for new CVEs per existing CPE entries.

Copyright © 2026 Andrew Broglio. All rights reserved.
Patent Pending — IP Australia | Licensed under BSL 1.1
"""

import json
import os
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime

INDEX_FILE = os.path.join(os.path.dirname(__file__), "static", "data", "mdm_index.json")
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
NVD_DELAY = 0.7 if NVD_API_KEY else 6.0

_index = {"manufacturers": {}}
_lock = threading.Lock()


def _nvd_headers():
    h = {"Accept": "application/json", "User-Agent": "DTVSS/6.0"}
    if NVD_API_KEY:
        h["apiKey"] = NVD_API_KEY
    return h


def _save():
    try:
        os.makedirs(os.path.dirname(INDEX_FILE), exist_ok=True)
        with _lock:
            snap = json.loads(json.dumps(_index, default=str))
        with open(INDEX_FILE, "w") as f:
            json.dump(snap, f, indent=2)
    except Exception as e:
        print(f"  Index save failed: {e}")


# ─── Public API ──────────────────────────────────────────────────────

def get_manufacturer_dropdown():
    """Return manufacturers with CVEs for the dropdown, sorted by CVE count."""
    with _lock:
        mdms = _index.get("manufacturers", {})

    result = []
    for key, mdm in mdms.items():
        if mdm.get("status") != "has_cves":
            continue
        cve_count = len(mdm.get("cves", []))
        if cve_count == 0:
            continue
        result.append({
            "name": mdm["display_name"],
            "nvd": mdm["display_name"],
            "cve_count": cve_count,
            "status": "ready",
        })

    result.sort(key=lambda x: (-x["cve_count"], x["name"]))
    return result


def search_manufacturer_cves(manufacturer_name):
    """Return pre-indexed CVEs for a manufacturer."""
    with _lock:
        mdms = _index.get("manufacturers", {})
    key = manufacturer_name.lower().replace(" ", "_").strip()

    # Direct match on CPE vendor key
    if key in mdms:
        return mdms[key].get("cves", [])

    # Try matching on display name
    name_lower = manufacturer_name.lower().strip()
    for mkey, mdm in mdms.items():
        if name_lower in mdm.get("display_name", "").lower():
            return mdm.get("cves", [])

    return []


def get_cpe_search_terms(manufacturer_name):
    """Return CPE-derived NVD search terms for a manufacturer."""
    with _lock:
        mdms = _index.get("manufacturers", {})

    # Try CPE vendor key
    key = manufacturer_name.lower().replace(" ", "_").strip()
    mdm = mdms.get(key)

    # Try display name match
    if not mdm:
        name_lower = manufacturer_name.lower().strip()
        for mkey, m in mdms.items():
            if name_lower in m.get("display_name", "").lower():
                mdm = m
                break

    if not mdm:
        return [manufacturer_name]

    terms = [mdm["display_name"]]

    # Add vendor+product combos from CPE entries
    vendor = mdm.get("cpe_vendor", "").replace("_", " ")
    for cpe in mdm.get("cpe_entries", []):
        product = cpe.get("product", "").replace("_", " ")
        if product and len(product) >= 3:
            combined = f"{vendor} {product}"
            if combined not in terms:
                terms.append(combined)

    return terms[:10]


# ─── Hourly CVE refresh ─────────────────────────────────────────────

def _hourly_refresh():
    while True:
        time.sleep(3600)
        print(f"  [CVE Refresh] {datetime.utcnow().isoformat()}Z")

        with _lock:
            mdms = _index.get("manufacturers", {})

        new_total = 0
        for key, mdm in mdms.items():
            if mdm.get("status") != "has_cves":
                continue
            existing_ids = {c["cve_id"] for c in mdm.get("cves", [])}

            for cpe in mdm.get("cpe_entries", [])[:3]:
                time.sleep(NVD_DELAY)
                try:
                    params = urllib.parse.urlencode({
                        "cpeName": cpe["cpe_name"],
                        "resultsPerPage": 20,
                    })
                    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{params}"
                    req = urllib.request.Request(url, headers=_nvd_headers())
                    with urllib.request.urlopen(req, timeout=15) as resp:
                        data = json.loads(resp.read().decode("utf-8"))

                    for vuln in data.get("vulnerabilities", []):
                        cve = vuln.get("cve", {})
                        cid = cve.get("id", "")
                        if cid and cid not in existing_ids:
                            desc = next((d["value"] for d in cve.get("descriptions", [])
                                        if d.get("lang") == "en"), "")
                            m = cve.get("metrics", {})
                            bs = sev = cv = ""
                            for vk, vl in [("cvssMetricV31","3.1"),("cvssMetricV30","3.0"),
                                           ("cvssMetricV40","4.0"),("cvssMetricV2","2.0")]:
                                if m.get(vk):
                                    bs = m[vk][0].get("cvssData",{}).get("baseScore",0)
                                    sev = m[vk][0].get("cvssData",{}).get("baseSeverity","")
                                    cv = vl
                                    break
                            with _lock:
                                mdm["cves"].append({
                                    "cve_id": cid, "description": desc[:300],
                                    "cvss_version": cv, "base_score": bs,
                                    "severity": sev, "published": cve.get("published","")[:10],
                                })
                            existing_ids.add(cid)
                            new_total += 1
                except Exception:
                    pass

        if new_total:
            _save()
            print(f"  [CVE Refresh] {new_total} new CVEs")
        else:
            print(f"  [CVE Refresh] No new CVEs")


# ─── Init ────────────────────────────────────────────────────────────

def _load():
    global _index
    if os.path.exists(INDEX_FILE):
        try:
            with open(INDEX_FILE, "r") as f:
                _index = json.load(f)
            total = len(_index.get("manufacturers", {}))
            with_cves = sum(1 for m in _index.get("manufacturers", {}).values()
                          if m.get("status") == "has_cves")
            total_cves = sum(len(m.get("cves", [])) for m in _index.get("manufacturers", {}).values())
            print(f"  MDM index: {total} vendors, {with_cves} with CVEs, {total_cves} total CVEs")
        except Exception as e:
            print(f"  MDM index load failed: {e}")
    else:
        print(f"  MDM index not found — run build_index.py")


_load()
threading.Thread(target=_hourly_refresh, daemon=True).start()
print("  Hourly CVE refresh thread started")
