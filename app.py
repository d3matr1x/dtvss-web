# DTVSS — Web Application
# Copyright © 2026 Andrew Broglio. All rights reserved.
# Patent Pending — IP Australia
# Licensed under BSL 1.1 — Commercial licence required for production use.

"""
DTVSS Tier 1 Web Application
=============================
Flask backend with:
  - /api/lookup?cve=CVE-2017-12725    → single CVE lookup, auto-scored
  - /api/search?q=Medfusion           → device name search, all results scored
  - /api/score                         → manual scoring (POST with B, L, H, kev)
  - /                                  → serves the frontend

All data from NVD API v2 + EPSS API + CISA KEV + openFDA. No proprietary data.
"""

import os
import json
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

from dtvss_engine import compute_dtvss, classify_device, TGA_CLASSES
from api_clients import nvd_lookup_cve, nvd_search_keyword, epss_lookup, cisa_kev_check
from index_loader import get_manufacturer_dropdown, search_manufacturer_cves, get_cpe_search_terms

app = Flask(__name__, static_folder="static", static_url_path="")
CORS(app)

NVD_API_KEY = os.environ.get("NVD_API_KEY", "")


@app.errorhandler(Exception)
def handle_exception(e):
    """Return JSON instead of HTML for all errors so the frontend can parse them."""
    import traceback
    tb = traceback.format_exc()
    print(f"ERROR: {e}\n{tb}")
    code = getattr(e, 'code', 500)
    return jsonify({"error": f"Server error: {str(e)}", "type": e.__class__.__name__}), code


@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/calculator")
def calculator():
    return send_from_directory("static", "calculator.html")


@app.route("/about")
def about():
    return send_from_directory("static", "about.html")


@app.route("/robots.txt")
def robots():
    return send_from_directory("static", "robots.txt", mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap():
    return send_from_directory("static", "sitemap.xml", mimetype="application/xml")


@app.route("/api/lookup")
def lookup():
    """
    Look up a single CVE by ID.
    Auto-fetches B from NVD, L(t) from EPSS, detects KEV, classifies device, scores.

    GET /api/lookup?cve=CVE-2017-12725&tga_class=IIb
    tga_class is optional — auto-detected from CVE description if omitted.
    """
    cve_id = request.args.get("cve", "").strip().upper()
    tga_override = request.args.get("tga_class", "").strip()

    if not cve_id:
        return jsonify({"error": "Missing 'cve' parameter"}), 400

    if not cve_id.startswith("CVE-"):
        cve_id = "CVE-" + cve_id

    # Fetch from NVD
    nvd = nvd_lookup_cve(cve_id, api_key=NVD_API_KEY)
    if not nvd or "error" in nvd:
        return jsonify(nvd or {"error": "NVD lookup failed"}), 404

    # Fetch EPSS
    epss = epss_lookup([cve_id])
    epss_data = epss.get(cve_id, {"epss": 0.0, "percentile": 0.0, "date": ""})

    # Determine TGA class
    if tga_override and tga_override in TGA_CLASSES:
        tga_class = tga_override
        classify_source = "user"
    else:
        tga_class, classify_source = classify_device(nvd.get("description", ""))
        if not tga_class:
            tga_class = "IIb"  # default to IIb if unclassifiable
            classify_source = "default"

    H = TGA_CLASSES[tga_class]["H"]

    # KEV: check NVD first, then CISA catalog directly if NVD didn't have it
    kev_status = nvd.get("kev", False)
    kev_added = nvd.get("kev_added", "")
    kev_due = nvd.get("kev_due", "")
    kev_name = nvd.get("kev_name", "")

    if not kev_status:
        cisa_kev = cisa_kev_check(cve_id)
        if cisa_kev:
            kev_status = True
            kev_added = cisa_kev.get("kev_added", "")
            kev_due = cisa_kev.get("kev_due", "")
            kev_name = cisa_kev.get("kev_name", "")

    # Score
    result = compute_dtvss(
        B=nvd.get("B", 0),
        L=epss_data["epss"],
        H=H,
        kev=kev_status,
    )

    # Merge all data
    result.update({
        "cve_id": cve_id,
        "description": nvd.get("description", ""),
        "tga_class": tga_class,
        "tga_label": TGA_CLASSES[tga_class]["label"],
        "jurisdictions": TGA_CLASSES[tga_class]["jurisdictions"],
        "cvss_version": nvd.get("cvss_version", ""),
        "cvss_vector": nvd.get("cvss_vector", ""),
        "severity": nvd.get("severity", ""),
        "published": nvd.get("published", ""),
        "epss_percentile": epss_data["percentile"],
        "epss_date": epss_data["date"],
        "kev_added": kev_added,
        "kev_due": kev_due,
        "kev_name": kev_name,
        "ics_advisory": nvd.get("ics_advisory", False),
        "ics_urls": nvd.get("ics_urls", []),
        "impact_score": nvd.get("impact_score", 0.0),
    })

    return jsonify(result)


@app.route("/api/search")
def search():
    """
    Search by device name or keyword.
    Auto-fetches all matching CVEs, scores each, returns ranked list.

    GET /api/search?q=Medfusion+4000&tga_class=IIb
    tga_class is optional — auto-detected per CVE if omitted.
    """
    query = request.args.get("q", "").strip()
    tga_override = request.args.get("tga_class", "").strip()
    try:
        max_results = min(int(request.args.get("max", 50)), 100)
    except (ValueError, TypeError):
        max_results = 50

    if not query:
        return jsonify({"error": "Missing 'q' parameter"}), 400

    # Always run the baseline query first (most reliable)
    nvd_results_map = {}
    baseline = nvd_search_keyword(query, api_key=NVD_API_KEY, max_results=max_results)
    for r in baseline:
        if "error" in r:
            continue
        cve_id = r.get("cve_id", "")
        if cve_id:
            nvd_results_map[cve_id] = r

    # Then try CPE-based search terms from pre-built index
    import time as _search_time
    expanded_queries = []
    expansion_start = _search_time.time()
    EXPANSION_BUDGET = 15.0

    try:
        expanded_queries = get_cpe_search_terms(query)
        for q in expanded_queries:
            if q == query:
                continue
            if (_search_time.time() - expansion_start) > EXPANSION_BUDGET:
                print(f"Expansion time budget exceeded for '{query}' after {len(nvd_results_map)} results")
                break
            batch = nvd_search_keyword(q, api_key=NVD_API_KEY, max_results=max_results)
            for r in batch:
                if "error" in r:
                    continue
                cve_id = r.get("cve_id", "")
                if cve_id and cve_id not in nvd_results_map:
                    nvd_results_map[cve_id] = r
    except Exception as e:
        print(f"CPE expansion failed for '{query}': {e}")

    # Post-filter: if this was a manufacturer search, only keep CVEs whose
    # description mentions at least one of the complete search terms.
    # Uses full terms only (no word splitting) to avoid false exclusions.
    if len(expanded_queries) > 1:
        valid_terms = [q.lower().strip() for q in expanded_queries if len(q.strip()) >= 3]
        filtered_map = {}
        for cve_id, r in nvd_results_map.items():
            desc = r.get("description", "").lower()
            if any(term in desc for term in valid_terms):
                filtered_map[cve_id] = r
        nvd_results_map = filtered_map

    nvd_results = list(nvd_results_map.values())

    if not nvd_results:
        return jsonify({"results": [], "count": 0, "query": query,
                        "note": f"No CVEs found in NVD for \"{query}\". This manufacturer may not have any disclosed vulnerabilities."})

    # Filter out errors and v2.0-only
    valid = [r for r in nvd_results if "error" not in r]

    if not valid:
        # All results had errors (mostly v2-only or no CVSS)
        total = len(nvd_results)
        return jsonify({"results": [], "count": 0, "query": query,
                        "note": f"Found {total} CVE(s) for \"{query}\" but none have CVSS scores available for DTVSS scoring."})

    # Batch EPSS lookup
    cve_ids = [r["cve_id"] for r in valid]
    epss_map = epss_lookup(cve_ids)

    # Score each
    scored = []
    for nvd in valid:
        epss_data = epss_map.get(nvd["cve_id"], {"epss": 0.0, "percentile": 0.0, "date": ""})

        if tga_override and tga_override in TGA_CLASSES:
            tga_class = tga_override
        else:
            tga_class, _ = classify_device(nvd.get("description", ""))
            if not tga_class:
                tga_class = "IIb"

        H = TGA_CLASSES[tga_class]["H"]

        # KEV: NVD first, CISA catalog fallback
        kev_status = nvd.get("kev", False)
        if not kev_status:
            cisa_kev = cisa_kev_check(nvd["cve_id"])
            if cisa_kev:
                kev_status = True

        result = compute_dtvss(nvd["B"], epss_data["epss"], H, kev=kev_status)

        result.update({
            "cve_id": nvd["cve_id"],
            "description": nvd.get("description", ""),
            "tga_class": tga_class,
            "cvss_version": nvd.get("cvss_version", ""),
            "severity": nvd.get("severity", ""),
            "published": nvd.get("published", ""),
            "epss_percentile": epss_data["percentile"],
            "epss_date": epss_data["date"],
            "kev_added": nvd.get("kev_added", ""),
            "ics_advisory": nvd.get("ics_advisory", False),
            "impact_score": nvd.get("impact_score", 0.0),
        })
        scored.append(result)

    # Sort: KEV first, then score descending
    scored.sort(key=lambda x: (0 if x.get("kev_override") else 1, -x["score"], x["cve_id"]))

    return jsonify({
        "results": scored,
        "count": len(scored),
        "query": query,
    })


@app.route("/api/score", methods=["POST"])
def score():
    """
    Manual scoring endpoint.
    POST {"B": 3.9, "L": 0.0089, "H": 7.5, "kev": false}
    """
    data = request.json or {}
    B = float(data.get("B", 0))
    L = float(data.get("L", 0))
    H = float(data.get("H", 7.5))
    kev = bool(data.get("kev", False))

    result = compute_dtvss(B, L, H, kev)
    return jsonify(result)


@app.route("/api/device-classes")
def device_classes():
    """Return available device classes with H values and jurisdiction mappings."""
    return jsonify(TGA_CLASSES)


@app.route("/api/manufacturers")
def manufacturers():
    """Return list of medical device manufacturers with per-entry status."""
    mdm_list = get_manufacturer_dropdown()
    return jsonify({
        "manufacturers": mdm_list,
        "count": len(mdm_list),
        "source": "openFDA Registration API + NVD CPE/CVE",
    })


# Pre-load at import time (runs under both gunicorn and __main__)
# index_loader.py loads the pre-built index and starts background refresh on import
try:
    from api_clients import refresh_device_keywords
    _keywords = refresh_device_keywords()
    print(f"  Device keywords loaded: {len(_keywords)} from openFDA")
except Exception as _e:
    print(f"  Device keyword refresh skipped: {_e}")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))

    print(f"\n{'=' * 60}")
    print(f"  DTVSS Web v1.0.0")
    print(f"  Formula: (B/10 × H/10 × (1 + 15 × L(t))) × 10")
    print(f"  Patent Pending — © 2026 Andrew Broglio")
    print(f"{'=' * 60}")
    print(f"  http://localhost:{port}")
    print(f"  NVD API key: {'loaded' if NVD_API_KEY else 'not set (rate limited)'}")
    print(f"{'=' * 60}\n")
    app.run(host="0.0.0.0", port=port, debug=False)
