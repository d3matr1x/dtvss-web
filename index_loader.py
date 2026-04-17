"""
DTVSS Index Loader - CISA ICSMA Runtime
========================================
Loads pre-built index from static/data/mdm_index.json.
Hourly background thread checks ICSMA RSS for new advisories
and enriches new CVEs with CVSS data from NVD.

NVD is used for scoring enrichment only, not CVE discovery.
All CVE discovery comes from CISA ICSMA advisories.

Copyright 2026 Andrew Broglio. All rights reserved.
Patent Pending - IP Australia | Licensed under BSL 1.1
"""

import json
import os
import re
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

INDEX_FILE = os.path.join(os.path.dirname(__file__), "static", "data", "mdm_index.json")
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
NVD_DELAY = 0.7 if NVD_API_KEY else 6.0
ICSMA_RSS_URL = "https://www.cisa.gov/cybersecurity-advisories/ics-medical-advisories.xml"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

EXCLUDED_DEVICES = ["wheelchair", "power chair", "electric chair", "fitness", "wearable", "smart watch"]

VENDOR_ALIASES = {
    "phillips": "Philips", "philips": "Philips",
    "b. braun": "B. Braun", "b. braun medical": "B. Braun", "b. braun melsungen ag": "B. Braun",
    "ge healthcare": "GE Healthcare", "general electric (ge)": "GE Healthcare",
    "fujifilm": "FUJIFILM", "fujifilm healthcare americas corporation": "FUJIFILM",
    "hillrom": "Hillrom", "hillrom and eli, baxter international inc.": "Hillrom",
    "silex technology and ge healthcare": "GE Healthcare",
    "natus medical, inc. (natus)": "Natus Medical",
    "becton, dickinson and company (bd)": "BD (Becton Dickinson)",
    "abbott laboratories": "Abbott", "roche diagnostics": "Roche",
    "hamilton medical ag": "Hamilton Medical",
    "sooil developments co, ltd.": "SOOIL",
    "bmc medical, 3b medical": "BMC Medical",
}

KNOWN_VENDORS = [
    "B. Braun", "Boston Scientific", "GE Healthcare", "GE HealthCare",
    "Becton, Dickinson", "Becton Dickinson", "BD ",
    "St. Jude Medical", "ICU Medical", "Smiths Medical",
    "Hamilton Medical", "Cook Medical", "Cardinal Health",
    "Nihon Kohden", "Karl Storz", "Welch Allyn",
    "Fresenius Kabi", "Tandem Diabetes", "Siemens Healthineers",
    "Contec Health", "Hillrom", "Spacelabs", "Oxford Nanopore",
    "FUJIFILM Healthcare",
]

_index = {"manufacturers": {}}
_lock = threading.Lock()


# --- Public API ---

def get_manufacturer_dropdown():
    """Return manufacturers for the dropdown, sorted by CVE count."""
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

    key = manufacturer_name.lower().strip()
    if key in mdms:
        return mdms[key].get("cves", [])

    for mkey, mdm in mdms.items():
        if key in mdm.get("display_name", "").lower():
            return mdm.get("cves", [])

    return []


def get_cpe_search_terms(manufacturer_name):
    """Return search terms for live NVD queries."""
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

    return [mdm["display_name"]]


def get_advisory_urls(manufacturer_name):
    """Return ICSMA advisory URLs for a manufacturer."""
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
        return []

    return mdm.get("advisory_urls", [])


# --- Helpers ---

def _extract_vendor(title):
    clean = re.sub(r'\s*\(Update [A-Z]\)', '', title).strip()
    for vendor in KNOWN_VENDORS:
        if clean.lower().startswith(vendor.lower()):
            return vendor
    words = clean.split()
    if len(words) >= 2 and words[1].lower() in ("healthcare", "medical", "diabetes", "scientific"):
        return f"{words[0]} {words[1]}"
    return words[0] if words else ""


def _normalise_vendor(raw_name):
    key = raw_name.lower().strip()
    return VENDOR_ALIASES.get(key, raw_name)


def _nvd_enrich_cve(cve_id):
    """Query NVD for CVSS data for a single CVE."""
    hdrs = {"Accept": "application/json", "User-Agent": "DTVSS/3.0"}
    if NVD_API_KEY:
        hdrs["apiKey"] = NVD_API_KEY
    try:
        params = urllib.parse.urlencode({"cveId": cve_id})
        req = urllib.request.Request(f"{NVD_CVE_URL}?{params}", headers=hdrs)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None

        cve_obj = vulns[0].get("cve", {})
        desc = next((d["value"] for d in cve_obj.get("descriptions", []) if d.get("lang") == "en"), "")

        m = cve_obj.get("metrics", {})
        bs = sev = cv = ""
        for vk, vl in [("cvssMetricV31","3.1"),("cvssMetricV30","3.0"),
                        ("cvssMetricV40","4.0"),("cvssMetricV2","2.0")]:
            if m.get(vk):
                entry = next((e for e in m[vk] if e.get("type") == "Primary"), m[vk][0])
                bs = entry.get("cvssData",{}).get("baseScore",0)
                sev = entry.get("cvssData",{}).get("baseSeverity","")
                cv = vl
                break

        return {
            "description": desc[:300],
            "cvss_version": cv,
            "base_score": bs,
            "severity": sev,
            "published": cve_obj.get("published","")[:10],
        }
    except Exception:
        return None


def _save_index():
    try:
        os.makedirs(os.path.dirname(INDEX_FILE), exist_ok=True)
        with _lock:
            snap = json.loads(json.dumps(_index, default=str))
        with open(INDEX_FILE, "w") as f:
            json.dump(snap, f, indent=2)
    except Exception as e:
        print(f"  [Hourly] Index save failed: {e}")


# --- Hourly: ICSMA RSS ingestion + NVD CVSS enrichment ---

def _hourly_pipeline():
    """Check ICSMA RSS for new advisories, enrich with NVD CVSS."""
    while True:
        time.sleep(3600)
        try:
            ts = datetime.now(timezone.utc).isoformat()
            print(f"  [Hourly] {ts}")

            changes = False

            req = urllib.request.Request(ICSMA_RSS_URL, headers={"User-Agent": "DTVSS/3.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode("utf-8")

            root = ET.fromstring(raw)

            with _lock:
                mdms = _index.get("manufacturers", {})
                known_urls = set()
                for m in mdms.values():
                    for a in m.get("advisory_urls", []):
                        known_urls.add(a.get("url", ""))

            for item in root.findall(".//item"):
                title = (item.findtext("title") or "").strip()
                link = (item.findtext("link") or "").strip()

                if not title or not link or "/icsma-" not in link.lower():
                    continue
                if link in known_urls:
                    continue
                if any(term in title.lower() for term in EXCLUDED_DEVICES):
                    continue

                vendor = _normalise_vendor(_extract_vendor(title))
                if not vendor:
                    continue

                icsma_id = ""
                match = re.search(r'(icsma-[\d-]+)', link.lower())
                if match:
                    icsma_id = match.group(1).upper()

                # Fetch CVEs from advisory page
                time.sleep(0.3)
                try:
                    req2 = urllib.request.Request(link, headers={"User-Agent": "DTVSS/3.0"})
                    with urllib.request.urlopen(req2, timeout=15) as resp2:
                        page = resp2.read().decode("utf-8")
                    cve_ids = list(set(re.findall(r'CVE-\d{4}-\d+', page)))
                except Exception:
                    cve_ids = []

                key = vendor.lower().strip()
                with _lock:
                    if key not in mdms:
                        mdms[key] = {
                            "display_name": vendor,
                            "advisory_urls": [],
                            "cves": [],
                            "cve_count": 0,
                            "status": "no_cves",
                            "source": "cisa_icsma",
                        }

                    mdms[key]["advisory_urls"].append({
                        "url": link, "title": title, "icsma_id": icsma_id,
                    })

                    existing_ids = {c["cve_id"] for c in mdms[key]["cves"]}
                    new_cves = []
                    for cve_id in cve_ids:
                        if cve_id in existing_ids:
                            continue

                        # Enrich with NVD CVSS
                        time.sleep(NVD_DELAY)
                        nvd = _nvd_enrich_cve(cve_id)
                        new_cves.append({
                            "cve_id": cve_id,
                            "description": nvd["description"] if nvd else "",
                            "cvss_version": nvd["cvss_version"] if nvd else "",
                            "base_score": nvd["base_score"] if nvd else 0,
                            "severity": nvd["severity"] if nvd else "",
                            "published": nvd["published"] if nvd else "",
                            "source": "rss",
                        })

                    mdms[key]["cves"].extend(new_cves)
                    mdms[key]["cve_count"] = len(mdms[key]["cves"])
                    if mdms[key]["cves"]:
                        mdms[key]["status"] = "has_cves"
                    mdms[key]["last_checked"] = datetime.now(timezone.utc).isoformat()

                if new_cves:
                    changes = True
                    print(f"    RSS: {vendor} +{len(new_cves)} CVEs ({icsma_id})")

            if changes:
                _save_index()
                print(f"  [Hourly] Index updated and saved")
            else:
                print(f"  [Hourly] No new advisories")

        except Exception as e:
            print(f"  [Hourly] Error: {e}")


# --- Init ---

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
            source = _index.get("source", "unknown")
            print(f"  MDM index: {total} vendors, {with_cves} with CVEs, {total_cves} total CVEs")
            print(f"  Source: {source}")
        except Exception as e:
            print(f"  MDM index load failed: {e}")
    else:
        print(f"  MDM index not found - run build_index.py")


_load()
threading.Thread(target=_hourly_pipeline, daemon=True).start()
print("  Hourly ICSMA pipeline started")
