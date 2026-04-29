#!/usr/bin/env python3
"""
DTVSS Build Script - CISA ICSMA Pipeline
==========================================
Builds the manufacturer/CVE index from two authoritative sources:

  Source 1: CISA CSAF JSON (cisagov/CSAF on GitHub)
    - Full historical archive of every ICSMA advisory ever published
    - Structured JSON with vendor, product, CVE IDs, CVSS vectors

  Source 2: CISA ICSMA RSS feed
    - Catches advisories not yet committed to the CSAF repo
    - Lightweight, fast

NVD is used only for CVSS enrichment (scoring CVEs that lack CVSS
data in CSAF), not for CVE discovery. This prevents false positives
from NVD keyword search matching non-medical products.

Copyright 2026 Andrew Broglio. All rights reserved.
Patent Pending - IP Australia | Licensed under BSL 1.1
"""

import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
# XXE-safe XML parsing for the ICSMA RSS feed. The runtime path in
# index_loader.py was hardened to use defusedxml in an earlier patch, but
# this build script kept the stdlib ElementTree, which still resolves
# external entities on older Python and is vulnerable to billion-laughs
# entity expansion on every Python version. defusedxml exposes a drop-in
# ElementTree shim so the rest of the file doesn't need to change.
# Hard-required: a build run that silently falls back to the stdlib parser
# would re-introduce the vulnerability without warning.
try:
    from defusedxml import ElementTree as ET
except ImportError as _e:
    raise ImportError(
        "defusedxml is required for build_index.py. "
        "Install with: pip install defusedxml"
    ) from _e
from datetime import datetime, timezone

NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
# Output path: prefer the legacy static/data/ layout if that directory
# already exists (production deploys with a real /static dir), otherwise
# write to the repo root alongside the seed copy that ships with the repo.
# This mirrors index_loader.py so the writer and reader always agree on
# where the index lives. Override with DTVSS_INDEX_PATH for custom layouts.
_BUILD_HERE = os.path.dirname(os.path.abspath(__file__))
_LEGACY_OUTPUT = os.path.join(_BUILD_HERE, "static", "data", "mdm_index.json")
_ROOT_OUTPUT = os.path.join(_BUILD_HERE, "mdm_index.json")
OUTPUT_FILE = os.environ.get("DTVSS_INDEX_PATH") or (
    _LEGACY_OUTPUT if os.path.isdir(os.path.dirname(_LEGACY_OUTPUT))
    else _ROOT_OUTPUT
)

CSAF_API_URL = "https://api.github.com/repos/cisagov/CSAF/git/trees/develop?recursive=1"
CSAF_RAW_URL = "https://raw.githubusercontent.com/cisagov/CSAF/develop/"
ICSMA_RSS_URL = "https://www.cisa.gov/cybersecurity-advisories/ics-medical-advisories.xml"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

NVD_DELAY = 0.7 if NVD_API_KEY else 6.0

EXCLUDED_DEVICES = [
    "wheelchair", "power chair", "electric chair",
    "fitness", "wearable", "smart watch",
]

# Vendors to exclude - software libraries and platforms, not medical devices.
# These have ICSMA advisories because their code runs in healthcare settings,
# but they are not medical device manufacturers.
EXCLUDED_VENDORS = {
    "enea (rtos)",
    "enea, green hills software, itron, ip infusion, and wind river",
    "openclinic ga",
    "grassroots",
    "offis",
    "orthanc",
}

# Vendor name normalisation - map CSAF variants to canonical names.
VENDOR_ALIASES = {
    "phillips": "Philips",
    "philips": "Philips",
    "b. braun": "B. Braun",
    "b. braun medical": "B. Braun",
    "b. braun melsungen ag": "B. Braun",
    "ge healthcare": "GE Healthcare",
    "general electric (ge)": "GE Healthcare",
    "fujifilm": "FUJIFILM",
    "fujifilm healthcare americas corporation": "FUJIFILM",
    "fujifilm healthcare americas": "FUJIFILM",
    "hillrom": "Hillrom",
    "hillrom and eli, baxter international inc.": "Hillrom",
    "silex technology and ge healthcare": "GE Healthcare",
    "natus medical, inc. (natus)": "Natus Medical",
    "natus medical, inc.": "Natus Medical",
    "becton, dickinson and company (bd)": "BD (Becton Dickinson)",
    "becton dickinson": "BD (Becton Dickinson)",
    "sooil developments co, ltd.": "SOOIL",
    "abbott laboratories": "Abbott",
    "roche diagnostics": "Roche",
    "hamilton medical ag": "Hamilton Medical",
    "bmc medical, 3b medical": "BMC Medical",
    "enea, green hills software, itron, ip infusion, and wind river": "ENEA (RTOS)",
    "innokas yhtym\u00e4 oy": "Innokas",
    "innokas yhtymã¤ oy": "Innokas",
    "siemens": "Siemens Healthineers",
    "johnson & johnson": "Johnson & Johnson",
    "ossur": "Ossur",
}


def normalise_vendor(raw_name):
    """Map vendor name variants to canonical display name."""
    key = raw_name.lower().strip()
    if key in VENDOR_ALIASES:
        return VENDOR_ALIASES[key]
    return raw_name


def api_get(url, headers=None, timeout=20):
    hdrs = {"User-Agent": "DTVSS-Build/3.0"}
    if headers:
        hdrs.update(headers)
    try:
        req = urllib.request.Request(url, headers=hdrs)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8")
    except Exception as e:
        print(f"    API error: {e}")
        return None


def nvd_get(url, timeout=15):
    hdrs = {"Accept": "application/json", "User-Agent": "DTVSS-Build/3.0"}
    if NVD_API_KEY:
        hdrs["apiKey"] = NVD_API_KEY
    raw = api_get(url, headers=hdrs, timeout=timeout)
    if not raw or raw.strip().startswith("<"):
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def save_index(index):
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(index, f, indent=2, default=str)
    kb = os.path.getsize(OUTPUT_FILE) / 1024
    print(f"\n  Index saved: {OUTPUT_FILE} ({kb:.1f} KB)")


def is_excluded(title):
    t = title.lower()
    return any(term in t for term in EXCLUDED_DEVICES)


# ================================================================
# Source 1: CISA CSAF JSON from GitHub
# ================================================================

def source1_csaf():
    """
    Fetch ICSMA advisory JSON files from cisagov/CSAF GitHub repo.
    Returns dict of {vendor_key: {display_name, advisories, cves}}.
    """
    print("\n  Source 1: CISA CSAF JSON (GitHub)")
    print("  Fetching repo file tree...")

    raw = api_get(CSAF_API_URL, timeout=30)
    if not raw:
        print("    Failed to fetch GitHub tree")
        return {}

    try:
        tree = json.loads(raw)
    except json.JSONDecodeError:
        print("    Invalid JSON from GitHub")
        return {}

    icsma_files = []
    for item in tree.get("tree", []):
        path = item.get("path", "")
        if "/icsma-" in path and path.endswith(".json"):
            icsma_files.append(path)

    print(f"    Found {len(icsma_files)} ICSMA JSON files")

    vendors = {}
    for i, path in enumerate(icsma_files):
        url = CSAF_RAW_URL + path
        icsma_id = path.split("/")[-1].replace(".json", "").upper()

        if (i + 1) % 20 == 0:
            print(f"    Processing {i+1}/{len(icsma_files)}...", flush=True)

        time.sleep(0.1)
        raw = api_get(url, timeout=10)
        if not raw:
            continue

        try:
            csaf = json.loads(raw)
        except json.JSONDecodeError:
            continue

        title = csaf.get("document", {}).get("title", "")
        if is_excluded(title):
            continue

        # Extract vendor from product_tree
        vendor_name = ""
        product_tree = csaf.get("product_tree", {})
        for branch in product_tree.get("branches", []):
            if branch.get("category") == "vendor":
                vendor_name = branch.get("name", "")
                break

        if not vendor_name:
            continue

        vendor_name = normalise_vendor(vendor_name)

        if vendor_name.lower().strip() in EXCLUDED_VENDORS:
            continue

        # Extract CVEs and CVSS from vulnerabilities
        cves = []
        for vuln in csaf.get("vulnerabilities", []):
            cve_id = vuln.get("cve", "")
            if not cve_id:
                continue

            base_score = 0
            severity = ""
            cvss_ver = ""
            cvss_vector = ""
            for score in vuln.get("scores", []):
                if score.get("cvss_v3"):
                    base_score = score["cvss_v3"].get("baseScore", 0)
                    severity = score["cvss_v3"].get("baseSeverity", "")
                    cvss_ver = score["cvss_v3"].get("version", "3.1")
                    cvss_vector = score["cvss_v3"].get("vectorString", "")
                    break

            desc = ""
            # Try per-vulnerability notes first
            for note in vuln.get("notes", []):
                if note.get("category") == "description":
                    desc = note.get("text", "")[:300]
                    break
            # Try vulnerability title
            if not desc:
                desc = vuln.get("title", "")[:300]
            # Fall back to advisory title as context
            if not desc and title:
                desc = title[:300]

            cves.append({
                "cve_id": cve_id,
                "description": desc,
                "cvss_version": cvss_ver,
                "cvss_vector": cvss_vector,
                "base_score": base_score,
                "severity": severity,
                "published": csaf.get("document", {}).get("tracking", {}).get("initial_release_date", "")[:10],
                "source": "csaf",
            })

        # Get advisory web URL
        advisory_url = ""
        for ref in csaf.get("document", {}).get("references", []):
            if "Web Version" in ref.get("summary", ""):
                advisory_url = ref.get("url", "")
                break

        if not advisory_url:
            advisory_url = f"https://www.cisa.gov/news-events/ics-medical-advisories/{icsma_id.lower()}"

        key = vendor_name.lower().strip()
        if key not in vendors:
            vendors[key] = {
                "display_name": vendor_name,
                "advisories": [],
                "cves": {},
            }

        vendors[key]["advisories"].append({
            "url": advisory_url,
            "title": title,
            "icsma_id": icsma_id,
        })

        for cve in cves:
            vendors[key]["cves"][cve["cve_id"]] = cve

    print(f"    Parsed: {len(vendors)} vendors, {sum(len(v['cves']) for v in vendors.values())} CVEs")
    return vendors


# ================================================================
# Source 2: CISA ICSMA RSS feed
# ================================================================

def source2_rss(existing_vendors):
    """
    Fetch ICSMA RSS feed for advisories not yet in CSAF repo.
    Adds new advisories/CVEs to existing_vendors dict.
    """
    print("\n  Source 2: CISA ICSMA RSS feed")

    raw = api_get(ICSMA_RSS_URL, timeout=30)
    if not raw:
        print("    Failed to fetch RSS feed")
        return 0

    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        print("    XML parse error")
        return 0

    known_urls = set()
    for v in existing_vendors.values():
        for a in v.get("advisories", []):
            known_urls.add(a.get("url", ""))

    new_count = 0

    for item in root.findall(".//item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()

        if not title or not link:
            continue
        if "/icsma-" not in link.lower():
            continue
        if link in known_urls:
            continue
        if is_excluded(title):
            continue

        icsma_id = ""
        match = re.search(r'(icsma-[\d-]+)', link.lower())
        if match:
            icsma_id = match.group(1).upper()

        vendor_name = _extract_vendor_from_title(title)
        if not vendor_name:
            continue

        vendor_name = normalise_vendor(vendor_name)

        if vendor_name.lower().strip() in EXCLUDED_VENDORS:
            continue

        time.sleep(0.3)
        page = api_get(link, timeout=15)
        cve_ids = list(set(re.findall(r'CVE-\d{4}-\d+', page))) if page else []

        key = vendor_name.lower().strip()
        if key not in existing_vendors:
            existing_vendors[key] = {
                "display_name": vendor_name,
                "advisories": [],
                "cves": {},
            }

        existing_vendors[key]["advisories"].append({
            "url": link,
            "title": title,
            "icsma_id": icsma_id,
        })

        for cve_id in cve_ids:
            if cve_id not in existing_vendors[key]["cves"]:
                existing_vendors[key]["cves"][cve_id] = {
                    "cve_id": cve_id,
                    "description": "",
                    "cvss_version": "",
                    "cvss_vector": "",
                    "base_score": 0,
                    "severity": "",
                    "published": "",
                    "source": "rss",
                }

        new_count += 1
        print(f"    NEW: {vendor_name} - {icsma_id} ({len(cve_ids)} CVEs)")

    print(f"    {new_count} new advisories from RSS")
    return new_count


def _extract_vendor_from_title(title):
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
    clean = re.sub(r'\s*\(Update [A-Z]\)', '', title).strip()
    for vendor in KNOWN_VENDORS:
        if clean.lower().startswith(vendor.lower()):
            return vendor
    words = clean.split()
    if len(words) >= 2 and words[1].lower() in ("healthcare", "medical", "diabetes", "scientific"):
        return f"{words[0]} {words[1]}"
    return words[0] if words else ""


# ================================================================
# Enrich: Fetch NVD CVSS data for CVEs missing scores
# ================================================================

def enrich_missing_cvss(existing_vendors):
    """For CVEs without descriptions or CVSS scores, query NVD."""
    # Count how many need enrichment
    total_missing = 0
    for key, vdata in existing_vendors.items():
        for cve_id, cve in vdata.get("cves", {}).items():
            needs_desc = not cve.get("description", "").strip()
            needs_score = cve.get("base_score", 0) == 0
            if needs_desc or needs_score:
                total_missing += 1

    if total_missing == 0:
        print("\n  Enrichment: All CVEs have descriptions and scores")
        return

    print(f"\n  Enrichment: {total_missing} CVEs need NVD data (descriptions or scores)...")

    enriched = 0
    processed = 0

    for key, vdata in existing_vendors.items():
        for cve_id, cve in vdata.get("cves", {}).items():
            needs_desc = not cve.get("description", "").strip()
            needs_score = cve.get("base_score", 0) == 0
            if not needs_desc and not needs_score:
                continue

            processed += 1
            time.sleep(NVD_DELAY)
            params = urllib.parse.urlencode({"cveId": cve_id})
            data = nvd_get(f"{NVD_CVE_URL}?{params}")

            if data and data.get("vulnerabilities"):
                cve_obj = data["vulnerabilities"][0].get("cve", {})
                desc = next(
                    (d["value"] for d in cve_obj.get("descriptions", []) if d.get("lang") == "en"),
                    ""
                )
                m = cve_obj.get("metrics", {})
                for vk, vl in [("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"),
                                ("cvssMetricV40", "4.0"), ("cvssMetricV2", "2.0")]:
                    if m.get(vk):
                        entry = next((e for e in m[vk] if e.get("type") == "Primary"), m[vk][0])
                        cve["base_score"] = entry.get("cvssData", {}).get("baseScore", 0)
                        cve["severity"] = entry.get("cvssData", {}).get("baseSeverity", "")
                        cve["cvss_version"] = vl
                        cve["cvss_vector"] = entry.get("cvssData", {}).get("vectorString", "")
                        cve["exploitability"] = entry.get("exploitabilityScore", 0)
                        break
                cve["description"] = desc[:300] if desc else cve.get("description", "")
                cve["published"] = cve_obj.get("published", "")[:10] or cve.get("published", "")

                if cve.get("base_score", 0) > 0:
                    enriched += 1

            if processed > 0 and processed % 20 == 0:
                print(f"    Enriched {enriched}/{processed} of {total_missing}...", flush=True)

    print(f"    Enriched {enriched} of {total_missing} CVEs needing NVD data")


# ================================================================
# Main Build
# ================================================================

def build_index():
    print("=" * 60)
    print("  DTVSS Index Builder - CISA ICSMA Pipeline")
    print("  Patent Pending - (c) 2026 Andrew Broglio")
    print("=" * 60)

    # Source 1: CSAF JSON (full historical)
    vendors = source1_csaf()

    # Source 2: ICSMA RSS (catch recent not yet in CSAF)
    source2_rss(vendors)

    # Enrich CVEs missing CVSS scores via NVD
    enrich_missing_cvss(vendors)

    # Convert to output format
    manufacturers = {}
    for key, vdata in vendors.items():
        cves_list = sorted(vdata["cves"].values(), key=lambda c: c.get("base_score", 0), reverse=True)
        manufacturers[key] = {
            "display_name": vdata["display_name"],
            "advisory_urls": vdata.get("advisories", []),
            "cves": cves_list,
            "cve_count": len(cves_list),
            "icsma_checked": True,
            "status": "has_cves" if cves_list else "no_cves",
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "source": "cisa_icsma",
        }

    index = {
        "manufacturers": manufacturers,
        "built_at": datetime.now(timezone.utc).isoformat(),
        "source": "CISA CSAF JSON + ICSMA RSS (NVD for CVSS enrichment only)",
        "total_manufacturers": len(manufacturers),
        "manufacturers_with_cves": sum(1 for m in manufacturers.values() if m["status"] == "has_cves"),
        "total_cves": sum(len(m["cves"]) for m in manufacturers.values()),
    }

    save_index(index)

    print(f"\n  Summary:")
    print(f"    Sources:             CSAF JSON + ICSMA RSS")
    print(f"    Enrichment:          NVD (CVSS scores only)")
    print(f"    Total vendors:       {index['total_manufacturers']}")
    print(f"    With CVEs:           {index['manufacturers_with_cves']}")
    print(f"    Total CVEs indexed:  {index['total_cves']}")
    print("=" * 60)


if __name__ == "__main__":
    try:
        build_index()
    except Exception as e:
        print(f"\n  Build failed: {e}")
        import traceback
        traceback.print_exc()
        if os.path.exists(OUTPUT_FILE):
            print(f"  Existing index preserved")
        else:
            os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
            with open(OUTPUT_FILE, "w") as f:
                json.dump({"manufacturers": {}}, f)
            print(f"  Empty index created")
        sys.exit(0)
