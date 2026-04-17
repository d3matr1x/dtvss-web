#!/usr/bin/env python3
"""
DTVSS Build Script — Manufacturer & Vulnerability Index Builder
================================================================
Runs before deployment (Railway build step) to create a pre-computed
index of manufacturers, their products (from NVD CPE), and associated
CVEs. This file is then loaded at runtime for instant search results.

Data sources:
  1. openFDA Registration & Listing API → manufacturer list
  2. NVD CPE Dictionary API → vendor:product entries per manufacturer
  3. NVD CVE API v2 → vulnerabilities per CPE

Output: static/data/mdm_index.json

Weekly: re-run to pick up new manufacturers and products (append only)
Hourly: runtime refresh checks for new CVEs per existing CPE entries

Copyright © 2026 Andrew Broglio. All rights reserved.
Patent Pending — IP Australia | Licensed under BSL 1.1
"""

import json
import os
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime

# ─── Configuration ───────────────────────────────────────────────────

NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "static", "data", "mdm_index.json")

OPENFDA_REG_URL = "https://api.fda.gov/device/registrationlisting.json"
NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# FDA product codes for network-connected Class II/III medical devices
CONNECTED_PRODUCT_CODES = [
    "FRN", "MEB", "FPA", "DXY", "DTB", "DSQ", "LWS", "DQA",
    "MHX", "QBJ", "OYC", "BSX", "DPS", "DRE", "FLL", "BRY",
]

# Rate limits
NVD_DELAY = 0.7 if NVD_API_KEY else 6.0
FDA_DELAY = 0.3

# ─── Helpers ─────────────────────────────────────────────────────────

def api_get(url, headers=None, timeout=15):
    """Make a GET request, return parsed JSON or None."""
    hdrs = {"Accept": "application/json", "User-Agent": "DTVSS-Build/1.0"}
    if headers:
        hdrs.update(headers)
    try:
        req = urllib.request.Request(url, headers=hdrs)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            if raw.strip().startswith("<"):
                return None
            return json.loads(raw)
    except Exception as e:
        print(f"    API error: {e}")
        return None


def nvd_headers():
    h = {}
    if NVD_API_KEY:
        h["apiKey"] = NVD_API_KEY
    return h


def load_existing_index():
    """Load existing index file if present (for append-only updates)."""
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"manufacturers": {}, "built_at": None, "last_cve_check": None}


def save_index(index):
    """Save index to JSON file."""
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(index, f, indent=2, default=str)
    size_kb = os.path.getsize(OUTPUT_FILE) / 1024
    print(f"\n  Index saved: {OUTPUT_FILE} ({size_kb:.1f} KB)")


# ─── Step 1: Query openFDA for manufacturers ────────────────────────

def fetch_fda_manufacturers():
    """
    Query openFDA Registration & Listing API for all manufacturers
    of network-connected Class II/III medical devices.
    Returns dict of {firm_name: set(product_codes)}.
    """
    print("\n  Step 1: Querying openFDA for manufacturers...")
    manufacturers = {}

    for pc in CONNECTED_PRODUCT_CODES:
        print(f"    Product code {pc}...", end=" ", flush=True)
        params = urllib.parse.urlencode({
            "search": f'products.product_code:"{pc}" AND establishment_type:"Manufacture Medical Device"',
            "limit": 100,
        })
        url = f"{OPENFDA_REG_URL}?{params}"
        data = api_get(url)

        if not data:
            print("no data")
            time.sleep(FDA_DELAY)
            continue

        count = 0
        for result in data.get("results", []):
            estab_types = result.get("establishment_type", [])
            if not any("Manufacture" in e for e in estab_types):
                continue

            prop = result.get("proprietor", {})
            firm_name = prop.get("firm_name", "").strip()
            if not firm_name:
                firm_name = result.get("registration", {}).get("name", "").strip()
            if not firm_name or len(firm_name) < 3:
                continue

            # Skip non-manufacturers
            skip = ["distribution", "logistics", "sterilization", "sterilisation",
                    "warehouse", "repair", "services", "dhl", "ups "]
            if any(kw in firm_name.lower() for kw in skip):
                continue

            if firm_name not in manufacturers:
                manufacturers[firm_name] = set()
            manufacturers[firm_name].add(pc)
            count += 1

        print(f"{count} firms")
        time.sleep(FDA_DELAY)

    print(f"  Total unique manufacturers from FDA: {len(manufacturers)}")
    return manufacturers


# ─── Step 2: Query NVD CPE for each manufacturer ────────────────────

def fetch_cpe_for_manufacturer(firm_name):
    """
    Query NVD CPE API with keyword search for a manufacturer name.
    Returns list of {vendor, product, cpe_name} dicts.
    """
    # Clean firm name for search
    import re
    clean = re.sub(
        r',?\s*(Inc\.?|LLC|Ltd\.?|GmbH|AG|Corp\.?|Corporation|Co\.?|Limited).*$',
        '', firm_name, flags=re.IGNORECASE
    ).strip(",. ")

    if len(clean) < 3:
        return []

    params = urllib.parse.urlencode({
        "keywordSearch": clean,
        "resultsPerPage": 50,
    })
    url = f"{NVD_CPE_URL}?{params}"
    data = api_get(url, headers=nvd_headers())

    if not data:
        return []

    cpes = []
    clean_lower = clean.lower()

    for entry in data.get("products", []):
        cpe_name = entry.get("cpe", {}).get("cpeName", "")
        parts = cpe_name.split(":")
        if len(parts) < 5:
            continue

        vendor = parts[3].replace("_", " ").strip()
        product = parts[4].replace("_", " ").strip()

        if not product or len(product) < 3 or product == "*":
            continue

        # Only include if vendor matches the manufacturer
        if clean_lower not in vendor.lower() and vendor.lower() not in clean_lower:
            continue

        cpes.append({
            "vendor": vendor,
            "product": product,
            "cpe_name": cpe_name,
        })

    return cpes


# ─── Step 3: Query NVD CVE for each CPE ─────────────────────────────

def fetch_cves_for_cpe(cpe_name):
    """
    Query NVD CVE API for vulnerabilities matching a CPE name.
    Returns list of {cve_id, description, cvss_version, base_score, severity, published}.
    """
    # Use virtualMatchString for broad matching
    params = urllib.parse.urlencode({
        "cpeName": cpe_name,
        "resultsPerPage": 50,
    })
    url = f"{NVD_CVE_URL}?{params}"
    data = api_get(url, headers=nvd_headers(), timeout=20)

    if not data:
        return []

    cves = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue

        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            ""
        )

        # Get CVSS info
        m = cve.get("metrics", {})
        base_score = 0
        severity = ""
        cvss_ver = ""

        for ver_key, ver_label in [("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"),
                                     ("cvssMetricV40", "4.0"), ("cvssMetricV2", "2.0")]:
            if m.get(ver_key):
                entry = m[ver_key][0]
                base_score = entry.get("cvssData", {}).get("baseScore", 0)
                severity = entry.get("cvssData", {}).get("baseSeverity", "")
                cvss_ver = ver_label
                break

        cves.append({
            "cve_id": cve_id,
            "description": desc[:300],
            "cvss_version": cvss_ver,
            "base_score": base_score,
            "severity": severity,
            "published": cve.get("published", "")[:10],
        })

    return cves


# ─── Main Build Process ─────────────────────────────────────────────

def build_index():
    """
    Full build: FDA manufacturers → NVD CPE → NVD CVE.
    Processes one manufacturer at a time, updating the dropdown status.
    Append-only: never removes existing entries.
    """
    print("=" * 60)
    print("  DTVSS Manufacturer & Vulnerability Index Builder")
    print("  Patent Pending — © 2026 Andrew Broglio")
    print("=" * 60)

    # Load existing index (append-only)
    index = load_existing_index()
    existing_mdms = index.get("manufacturers", {})

    # Step 1: Get FDA manufacturers
    fda_manufacturers = fetch_fda_manufacturers()

    # Step 2 & 3: For each manufacturer, get CPE and CVE data
    print(f"\n  Step 2-3: Processing {len(fda_manufacturers)} manufacturers...")
    print(f"  (Existing index has {len(existing_mdms)} manufacturers)")

    processed = 0
    new_mdms = 0
    new_cves = 0

    for firm_name, product_codes in sorted(fda_manufacturers.items()):
        processed += 1

        # Clean display name
        import re
        display = re.sub(
            r',?\s*(Inc\.?|LLC|Ltd\.?|GmbH|AG|Corp\.?|Corporation|Co\.?|Limited|'
            r'Healthcare|USA|Technology|Systems).*$',
            '', firm_name, flags=re.IGNORECASE
        ).strip(",. ").title()

        if len(display) < 3:
            continue

        # Check if already in index
        key = display.lower()
        if key in existing_mdms and existing_mdms[key].get("cpe_checked"):
            # Already processed — skip CPE/CVE lookup but keep entry
            print(f"  [{processed}/{len(fda_manufacturers)}] {display} — cached")
            continue

        print(f"  [{processed}/{len(fda_manufacturers)}] {display} — querying NVD CPE...", end=" ", flush=True)

        # Query NVD CPE
        time.sleep(NVD_DELAY)
        cpes = fetch_cpe_for_manufacturer(firm_name)

        if not cpes:
            print("no CPE entries")
            # Still record manufacturer but flag as no CPE
            if key not in existing_mdms:
                existing_mdms[key] = {
                    "display_name": display,
                    "fda_firm_name": firm_name,
                    "product_codes": list(product_codes),
                    "cpe_entries": [],
                    "cves": [],
                    "cpe_checked": True,
                    "status": "no_cpe",
                }
            continue

        print(f"{len(cpes)} CPE entries — querying CVEs...", end=" ", flush=True)

        # Query NVD CVE for each unique CPE
        all_cves = {}
        for cpe in cpes[:5]:  # Limit to 5 CPE entries per manufacturer
            time.sleep(NVD_DELAY)
            cve_list = fetch_cves_for_cpe(cpe["cpe_name"])
            for cve in cve_list:
                if cve["cve_id"] not in all_cves:
                    all_cves[cve["cve_id"]] = cve

        cve_count = len(all_cves)
        print(f"{cve_count} CVEs")

        status = "has_cves" if cve_count > 0 else "no_cves"

        if key not in existing_mdms:
            new_mdms += 1

        new_cves += cve_count

        existing_mdms[key] = {
            "display_name": display,
            "fda_firm_name": firm_name,
            "product_codes": list(product_codes),
            "cpe_entries": [{"vendor": c["vendor"], "product": c["product"], "cpe_name": c["cpe_name"]} for c in cpes],
            "cves": list(all_cves.values()),
            "cpe_checked": True,
            "status": status,
        }

    # Save
    index["manufacturers"] = existing_mdms
    index["built_at"] = datetime.utcnow().isoformat() + "Z"
    index["last_cve_check"] = datetime.utcnow().isoformat() + "Z"
    index["total_manufacturers"] = len(existing_mdms)
    index["manufacturers_with_cves"] = sum(1 for m in existing_mdms.values() if m.get("status") == "has_cves")
    index["total_cves"] = sum(len(m.get("cves", [])) for m in existing_mdms.values())

    save_index(index)

    print(f"\n  Summary:")
    print(f"    Total manufacturers: {len(existing_mdms)}")
    print(f"    New manufacturers:   {new_mdms}")
    print(f"    With CVEs:           {index['manufacturers_with_cves']}")
    print(f"    Total CVEs indexed:  {index['total_cves']}")
    print(f"    New CVEs this run:   {new_cves}")
    print("=" * 60)


if __name__ == "__main__":
    try:
        build_index()
    except Exception as e:
        print(f"\n  Build index failed: {e}")
        # Don't fail the deployment — runtime will use whatever index exists
        if os.path.exists(OUTPUT_FILE):
            print(f"  Existing index preserved at {OUTPUT_FILE}")
        else:
            # Write empty index so the app can start
            os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
            with open(OUTPUT_FILE, "w") as f:
                json.dump({"manufacturers": {}, "built_at": None}, f)
            print(f"  Empty index created — runtime startup refresh will populate it")
        sys.exit(0)  # Exit 0 so Railway doesn't fail the build
