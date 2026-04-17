"""
DTVSS Index Loader
==================
Loads pre-built manufacturer/CVE index from static/data/mdm_index.json.
On startup, processes unchecked manufacturers one at a time.
Dropdown shows "Updating..." next to each name as it runs.

Background threads:
  - Startup: process unchecked manufacturers sequentially
  - Hourly: check NVD for new CVEs per existing CPE entries

Copyright © 2026 Andrew Broglio. All rights reserved.
Patent Pending — IP Australia | Licensed under BSL 1.1
"""

import json
import os
import re
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
_updating = {}  # key -> True while being refreshed


def _nvd_headers():
    h = {"Accept": "application/json", "User-Agent": "DTVSS/6.0"}
    if NVD_API_KEY:
        h["apiKey"] = NVD_API_KEY
    return h


def _api_get(url, timeout=15):
    try:
        req = urllib.request.Request(url, headers=_nvd_headers())
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            if raw.strip().startswith("<"):
                return None
            return json.loads(raw)
    except Exception:
        return None


def _save_index():
    try:
        os.makedirs(os.path.dirname(INDEX_FILE), exist_ok=True)
        with _lock:
            snapshot = json.loads(json.dumps(_index, default=str))
        with open(INDEX_FILE, "w") as f:
            json.dump(snapshot, f, indent=2)
    except Exception as e:
        print(f"  Index save failed: {e}")


# ─── Public API ──────────────────────────────────────────────────────

def get_manufacturer_dropdown():
    with _lock:
        mdms = _index.get("manufacturers", {})

    result = []
    for key in sorted(mdms.keys()):
        mdm = mdms[key]
        status = mdm.get("status", "unknown")
        is_updating = key in _updating

        if status == "has_cves" or is_updating:
            result.append({
                "name": mdm["display_name"],
                "nvd": mdm["display_name"],
                "cve_count": len(mdm.get("cves", [])),
                "status": "updating" if is_updating else "ready",
            })

    result.sort(key=lambda x: (0 if x["status"] == "ready" else 1, -x["cve_count"], x["name"]))
    return result


def search_manufacturer_cves(manufacturer_name):
    with _lock:
        mdms = _index.get("manufacturers", {})
    key = manufacturer_name.lower().strip()
    if key in mdms:
        return mdms[key].get("cves", [])
    for mkey, mdm in mdms.items():
        if key in mdm.get("display_name", "").lower():
            return mdm.get("cves", [])
    return []


def get_cpe_search_terms(manufacturer_name):
    with _lock:
        mdms = _index.get("manufacturers", {})
    key = manufacturer_name.lower().strip()
    mdm = mdms.get(key)
    if not mdm:
        for mkey, m in mdms.items():
            if key in m.get("display_name", "").lower():
                mdm = m
                break
    if not mdm:
        return [manufacturer_name]

    terms = [mdm["display_name"]]
    for cpe in mdm.get("cpe_entries", []):
        product = cpe.get("product", "")
        vendor = cpe.get("vendor", "")
        if product and len(product) >= 3:
            combined = f"{vendor} {product}"
            if combined not in terms:
                terms.append(combined)
    return terms[:10]


# ─── NVD CPE/CVE lookup ─────────────────────────────────────────────

def _clean_firm(name):
    return re.sub(
        r',?\s*(Inc\.?|LLC|Ltd\.?|GmbH|AG|Corp\.?|Corporation|Co\.?|Limited).*$',
        '', name, flags=re.IGNORECASE
    ).strip(",. ")


def _fetch_cpe(term):
    params = urllib.parse.urlencode({"keywordSearch": term, "resultsPerPage": 50})
    data = _api_get(f"https://services.nvd.nist.gov/rest/json/cpes/2.0?{params}")
    if not data:
        return []
    cpes = []
    tl = term.lower()
    for entry in data.get("products", []):
        cn = entry.get("cpe", {}).get("cpeName", "")
        parts = cn.split(":")
        if len(parts) < 5:
            continue
        vendor = parts[3].replace("_", " ").strip()
        product = parts[4].replace("_", " ").strip()
        if not product or len(product) < 3 or product == "*":
            continue
        if tl not in vendor.lower() and vendor.lower() not in tl:
            continue
        cpes.append({"vendor": vendor, "product": product, "cpe_name": cn})
    return cpes


def _fetch_cves(cpe_name):
    params = urllib.parse.urlencode({"cpeName": cpe_name, "resultsPerPage": 50})
    data = _api_get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?{params}", timeout=20)
    if not data:
        return []
    cves = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cid = cve.get("id", "")
        if not cid:
            continue
        desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        m = cve.get("metrics", {})
        bs = sev = cv = ""
        for vk, vl in [("cvssMetricV31","3.1"),("cvssMetricV30","3.0"),("cvssMetricV40","4.0"),("cvssMetricV2","2.0")]:
            if m.get(vk):
                bs = m[vk][0].get("cvssData", {}).get("baseScore", 0)
                sev = m[vk][0].get("cvssData", {}).get("baseSeverity", "")
                cv = vl
                break
        cves.append({"cve_id": cid, "description": desc[:300], "cvss_version": cv,
                     "base_score": bs, "severity": sev, "published": cve.get("published", "")[:10]})
    return cves


def _process_manufacturer(key, mdm):
    """Process one manufacturer: CPE lookup then CVE lookup. Shows updating status."""
    _updating[key] = True
    display = mdm["display_name"]
    clean = _clean_firm(mdm.get("fda_firm_name", display))

    print(f"  [Index] {display} — CPE...", end=" ", flush=True)
    time.sleep(NVD_DELAY)
    cpes = _fetch_cpe(clean)

    if not cpes:
        print("no CPE")
        with _lock:
            mdm["cpe_entries"] = []
            mdm["cves"] = []
            mdm["cpe_checked"] = True
            mdm["status"] = "no_cpe"
        _updating.pop(key, None)
        return

    print(f"{len(cpes)} CPEs — CVEs...", end=" ", flush=True)
    all_cves = {}
    for cpe in cpes[:5]:
        time.sleep(NVD_DELAY)
        for cve in _fetch_cves(cpe["cpe_name"]):
            if cve["cve_id"] not in all_cves:
                all_cves[cve["cve_id"]] = cve

    n = len(all_cves)
    print(f"{n} CVEs")

    with _lock:
        mdm["cpe_entries"] = cpes
        mdm["cves"] = list(all_cves.values())
        mdm["cpe_checked"] = True
        mdm["status"] = "has_cves" if n > 0 else "no_cves"
        mdm["last_checked"] = datetime.utcnow().isoformat() + "Z"

    _updating.pop(key, None)


# ─── Background threads ─────────────────────────────────────────────

def _startup_refresh():
    time.sleep(2)
    with _lock:
        mdms = _index.get("manufacturers", {})
    unchecked = [(k, m) for k, m in mdms.items() if not m.get("cpe_checked")]
    if not unchecked:
        print(f"  [Index] All {len(mdms)} manufacturers already checked")
        return
    print(f"  [Index] {len(unchecked)} manufacturers need CPE/CVE check")
    for key, mdm in unchecked:
        _process_manufacturer(key, mdm)
    _save_index()
    print(f"  [Index] Startup refresh complete")


def _hourly_cve_refresh():
    while True:
        time.sleep(3600)
        print(f"  [CVE Refresh] {datetime.utcnow().isoformat()}Z")
        with _lock:
            mdms = _index.get("manufacturers", {})
        new_total = 0
        for key, mdm in mdms.items():
            if mdm.get("status") != "has_cves":
                continue
            existing = {c["cve_id"] for c in mdm.get("cves", [])}
            for cpe in mdm.get("cpe_entries", [])[:3]:
                time.sleep(NVD_DELAY)
                for cve in _fetch_cves(cpe["cpe_name"]):
                    if cve["cve_id"] not in existing:
                        with _lock:
                            mdm["cves"].append(cve)
                        existing.add(cve["cve_id"])
                        new_total += 1
        if new_total:
            _save_index()
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
            with_cves = sum(1 for m in _index.get("manufacturers", {}).values() if m.get("status") == "has_cves")
            print(f"  MDM index loaded: {total} manufacturers, {with_cves} with CVEs")
        except Exception as e:
            print(f"  MDM index load failed: {e}")
    else:
        print(f"  MDM index not found — run build_index.py")

_load()
threading.Thread(target=_startup_refresh, daemon=True).start()
threading.Thread(target=_hourly_cve_refresh, daemon=True).start()
print("  Background threads started (startup + hourly CVE refresh)")
