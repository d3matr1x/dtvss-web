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
  - /                                  → serves the React frontend

All data from NVD API v2 + EPSS API. No Anthropic API. No operator config required.
"""

import os
import json
import re as _re
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    _limiter_available = True
except ImportError:
    _limiter_available = False

from dtvss_engine import compute_dtvss, classify_device, TGA_CLASSES
from api_clients import nvd_lookup_cve, nvd_search_keyword, epss_lookup, cisa_kev_check, get_manufacturer_list, build_manufacturer_search_queries, get_cached_search, set_cached_search

app = Flask(__name__, static_folder="static", static_url_path="")
CORS(app, origins=["https://dtvss.io", "http://localhost:5000", "http://127.0.0.1:5000"])

# Rate limiting — 60 searches or lookups per minute per IP
if _limiter_available:
    limiter = Limiter(get_remote_address, app=app, default_limits=[], storage_uri="memory://")
else:
    limiter = None

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

    # Validate CVE ID format before hitting NVD
    if not _re.match(r"^CVE-\d{4}-\d{1,7}$", cve_id):
        return jsonify({"error": f"Invalid CVE ID format: {cve_id}"}), 400

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
        B=nvd["B"],
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
        "classify_source": classify_source,
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
    max_results = min(int(request.args.get("max", 20)), 50)

    if not query:
        return jsonify({"error": "Missing 'q' parameter"}), 400

    # Check search cache first (5-minute TTL, shared across all users)
    cached = get_cached_search(query, tga_override)
    if cached is not None:
        return jsonify({
            "results": cached,
            "count": len(cached),
            "query": query,
            "cached": True,
        })

    # Always run the baseline query first (most reliable)
    nvd_results_map = {}
    baseline = nvd_search_keyword(query, api_key=NVD_API_KEY, max_results=max_results)
    for r in baseline:
        if "error" in r:
            continue
        cve_id = r.get("cve_id", "")
        if cve_id:
            nvd_results_map[cve_id] = r

    # Then try manufacturer expansion (additive — adds more results, can't reduce)
    try:
        expanded_queries = build_manufacturer_search_queries(query)
        # Skip the baseline query (already done) to avoid duplicate API calls
        for q in expanded_queries:
            if q == query:
                continue
            batch = nvd_search_keyword(q, api_key=NVD_API_KEY, max_results=max_results)
            for r in batch:
                if "error" in r:
                    continue
                cve_id = r.get("cve_id", "")
                if cve_id and cve_id not in nvd_results_map:
                    nvd_results_map[cve_id] = r
    except Exception as e:
        print(f"Manufacturer expansion failed for '{query}': {e}")

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

    # Cache for 5 minutes — shared across all users
    set_cached_search(query, scored, tga_override)

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
    try:
        B = float(data.get("B", 0))
        L = float(data.get("L", 0))
        H = float(data.get("H", 7.5))
        kev = bool(data.get("kev", False))
    except (TypeError, ValueError) as exc:
        return jsonify({"error": f"Invalid input: {exc}"}), 400

    if not (0.0 <= B <= 10.0):
        return jsonify({"error": f"B must be between 0.0 and 10.0, got {B}"}), 400
    if not (0.0 <= L <= 1.0):
        return jsonify({"error": f"L must be between 0.0 and 1.0, got {L}"}), 400
    if H not in (2.0, 5.0, 7.5, 10.0):
        return jsonify({"error": f"H must be a valid TGA class value (2.0, 5.0, 7.5, or 10.0), got {H}"}), 400

    result = compute_dtvss(B, L, H, kev)
    return jsonify(result)


@app.route("/api/device-classes")
def device_classes():
    """Return available device classes with H values and jurisdiction mappings."""
    return jsonify(TGA_CLASSES)


@app.route("/api/manufacturers")
def manufacturers():
    """Return list of medical device manufacturers from FDA registry. Cached daily."""
    mdm_list = get_manufacturer_list()
    return jsonify({"manufacturers": mdm_list, "count": len(mdm_list), "source": "openFDA Registration & Listing API"})


# ── Startup pre-warming — runs under gunicorn AND python app.py ─────────
# Uses before_request so it fires on the very first real request to the worker,
# which works correctly under gunicorn (unlike __main__).
_startup_done = False

@app.before_request
def _startup_prewarm():
    global _startup_done
    if _startup_done:
        return
    _startup_done = True
    import threading
    def _warm():
        try:
            from api_clients import refresh_device_keywords
            kw = refresh_device_keywords()
            print(f"[prewarm] Device keywords: {len(kw)} from openFDA")
        except Exception as e:
            print(f"[prewarm] Device keywords skipped: {e}")
        try:
            mdm = get_manufacturer_list()
            print(f"[prewarm] Manufacturers: {len(mdm)} from FDA registry")
        except Exception as e:
            print(f"[prewarm] Manufacturers skipped: {e}")
        try:
            cisa_kev_check("CVE-0000-0000")
            print("[prewarm] CISA KEV catalog loaded")
        except Exception as e:
            print(f"[prewarm] CISA KEV skipped: {e}")
    threading.Thread(target=_warm, daemon=True).start()


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
