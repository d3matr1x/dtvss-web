#!/usr/bin/env python3
"""
DTVSS Build Script — CPE-First Manufacturer & Vulnerability Index
==================================================================
Builds the manufacturer dropdown and CVE index directly from NVD's CPE
dictionary. No name guessing, no openFDA name cleaning.

Approach:
  1. Search NVD CPE dictionary for known medical device manufacturer keywords
  2. Extract the exact CPE vendor strings (these ARE the canonical names)
  3. For each vendor, query NVD CVE API using cpeName to get tagged CVEs
  4. Write mdm_index.json — ships with deployment

The CPE vendor field is NVD's own identifier for a manufacturer.
No name cleaning needed — the vendor string is authoritative.

Append-only: never removes manufacturers or CVEs from existing index.

Copyright © 2026 Andrew Broglio. All rights reserved.
Patent Pending — IP Australia | Licensed under BSL 1.1
"""

import json
import os
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime

NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "static", "data", "mdm_index.json")

NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

NVD_DELAY = 0.7 if NVD_API_KEY else 6.0

# Medical device manufacturers to search in CPE dictionary.
# These are keyword searches — NVD returns all matching CPE entries.
# The exact CPE vendor string is extracted from results (no guessing).
# Source: CISA ICS-CERT medical advisory history + FDA registered manufacturers
MDM_SEARCH_TERMS = [
    "medtronic",
    "abbott",
    "st. jude medical",
    "philips",
    "baxter",
    "becton dickinson",
    "bd alaris",
    "smiths medical",
    "hospira",
    "b. braun",
    "fresenius",
    "boston scientific",
    "biotronik",
    "dexcom",
    "insulet",
    "tandem diabetes",
    "nihon kohden",
    "mindray",
    "ge healthcare",
    "draeger",
    "hamilton medical",
    "zoll",
    "resmed",
    "getinge",
    "carestream",
    "roche",
    "siemens healthineers",
    "stryker",
    "icu medical",
    "gambro",
    "natus",
    "spacelabs",
    "welch allyn",
    "hillrom",
    "karl storz",
    "olympus medical",
    "bd pyxis",
    "covidien",
    "cardinal health",
    "cook medical",
]


def nvd_headers():
    h = {"Accept": "application/json", "User-Agent": "DTVSS-Build/1.0"}
    if NVD_API_KEY:
        h["apiKey"] = NVD_API_KEY
    return h


def api_get(url, timeout=15):
    try:
        req = urllib.request.Request(url, headers=nvd_headers())
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            if raw.strip().startswith("<"):
                return None
            return json.loads(raw)
    except Exception as e:
        print(f"    API error: {e}")
        return None


def load_existing():
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"manufacturers": {}}


def save_index(index):
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(index, f, indent=2, default=str)
    kb = os.path.getsize(OUTPUT_FILE) / 1024
    print(f"\n  Index saved: {OUTPUT_FILE} ({kb:.1f} KB)")


def vendor_display_name(cpe_vendor):
    """Convert CPE vendor string to display name.
    e.g. 'smiths_medical' → 'Smiths Medical'
         'becton_dickinson' → 'Becton Dickinson'
    """
    name = cpe_vendor.replace("_", " ").strip().title()
    # Preserve known acronyms
    for acr in ["BD", "GE", "ICU", "IV", "B."]:
        name = name.replace(acr.title(), acr)
    return name


# ─── Step 1: Search CPE dictionary for medical device vendors ────────

def find_cpe_vendors(search_term):
    """
    Search NVD CPE dictionary for a keyword.
    Returns dict of {cpe_vendor: [list of {product, cpe_name}]}
    """
    params = urllib.parse.urlencode({
        "keywordSearch": search_term,
        "resultsPerPage": 100,
    })
    url = f"{NVD_CPE_URL}?{params}"
    data = api_get(url)

    if not data:
        return {}

    vendors = {}
    for entry in data.get("products", []):
        cpe_name = entry.get("cpe", {}).get("cpeName", "")
        parts = cpe_name.split(":")
        if len(parts) < 5:
            continue

        part_type = parts[2]   # a=application, h=hardware, o=os/firmware
        vendor = parts[3]
        product = parts[4]

        if not product or product == "*" or len(product) < 2:
            continue

        # Only include hardware (h) and firmware (o) — skip generic applications (a)
        # unless the vendor name strongly matches the search term
        search_lower = search_term.lower().replace(" ", "_").replace(".", "")
        vendor_lower = vendor.lower().replace(".", "")
        if part_type == "a" and search_lower not in vendor_lower:
            continue

        if vendor not in vendors:
            vendors[vendor] = []

        # Deduplicate by product name (ignore version differences)
        existing_products = {p["product"] for p in vendors[vendor]}
        if product not in existing_products:
            vendors[vendor].append({
                "product": product,
                "cpe_name": cpe_name,
                "part_type": part_type,
            })

    return vendors


# ─── Step 2: Query CVEs for each CPE vendor:product ─────────────────

def fetch_cves_for_cpe(cpe_name):
    """Query NVD CVE API for vulnerabilities tagged to a CPE name."""
    params = urllib.parse.urlencode({
        "cpeName": cpe_name,
        "resultsPerPage": 50,
    })
    url = f"{NVD_CVE_URL}?{params}"
    data = api_get(url, timeout=20)

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

        m = cve.get("metrics", {})
        base_score = 0
        severity = ""
        cvss_ver = ""
        for vk, vl in [("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"),
                        ("cvssMetricV40", "4.0"), ("cvssMetricV2", "2.0")]:
            if m.get(vk):
                entry = m[vk][0]
                base_score = entry.get("cvssData", {}).get("baseScore", 0)
                severity = entry.get("cvssData", {}).get("baseSeverity", "")
                cvss_ver = vl
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


# ─── Main Build ──────────────────────────────────────────────────────

def build_index():
    print("=" * 60)
    print("  DTVSS Index Builder — CPE-First Approach")
    print("  Patent Pending — © 2026 Andrew Broglio")
    print("=" * 60)

    index = load_existing()
    existing = index.get("manufacturers", {})

    print(f"\n  Existing index: {len(existing)} manufacturers")
    print(f"  Searching NVD CPE for {len(MDM_SEARCH_TERMS)} medical device terms...\n")

    total_new_vendors = 0
    total_new_cves = 0

    for i, term in enumerate(MDM_SEARCH_TERMS):
        print(f"  [{i+1}/{len(MDM_SEARCH_TERMS)}] Searching CPE: \"{term}\"...", end=" ", flush=True)

        time.sleep(NVD_DELAY)
        vendors = find_cpe_vendors(term)

        if not vendors:
            print("no CPE vendors found")
            continue

        print(f"{len(vendors)} vendor(s)")

        for vendor, products in vendors.items():
            key = vendor.lower()
            display = vendor_display_name(vendor)

            # Skip if already fully processed
            if key in existing and existing[key].get("cve_checked"):
                continue

            print(f"    → {display} ({len(products)} products) — CVEs...", end=" ", flush=True)

            # Query CVEs for up to 5 products
            all_cves = {}
            for prod in products[:5]:
                time.sleep(NVD_DELAY)
                for cve in fetch_cves_for_cpe(prod["cpe_name"]):
                    if cve["cve_id"] not in all_cves:
                        all_cves[cve["cve_id"]] = cve

            n = len(all_cves)
            print(f"{n} CVEs")

            if key not in existing:
                total_new_vendors += 1

            total_new_cves += n

            existing[key] = {
                "display_name": display,
                "cpe_vendor": vendor,
                "cpe_entries": [{"product": p["product"], "cpe_name": p["cpe_name"],
                                 "part_type": p["part_type"]} for p in products],
                "cves": list(all_cves.values()),
                "cve_checked": True,
                "status": "has_cves" if n > 0 else "no_cves",
                "last_checked": datetime.utcnow().isoformat() + "Z",
                "search_term": term,
            }

    # Summary stats
    index["manufacturers"] = existing
    index["built_at"] = datetime.utcnow().isoformat() + "Z"
    index["total_manufacturers"] = len(existing)
    index["manufacturers_with_cves"] = sum(
        1 for m in existing.values() if m.get("status") == "has_cves"
    )
    index["total_cves"] = sum(len(m.get("cves", [])) for m in existing.values())

    save_index(index)

    print(f"\n  Summary:")
    print(f"    Total vendors:       {len(existing)}")
    print(f"    New this run:        {total_new_vendors}")
    print(f"    With CVEs:           {index['manufacturers_with_cves']}")
    print(f"    Total CVEs indexed:  {index['total_cves']}")
    print(f"    New CVEs this run:   {total_new_cves}")
    print("=" * 60)


if __name__ == "__main__":
    try:
        build_index()
    except Exception as e:
        print(f"\n  Build failed: {e}")
        if os.path.exists(OUTPUT_FILE):
            print(f"  Existing index preserved")
        else:
            os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
            with open(OUTPUT_FILE, "w") as f:
                json.dump({"manufacturers": {}}, f)
            print(f"  Empty index created — runtime will populate")
        sys.exit(0)
