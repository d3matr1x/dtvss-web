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
import re as _re
import threading
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    _limiter_available = True
except ImportError:
    _limiter_available = False

from dtvss_engine import compute_dtvss, resolve_tga_class, TGA_CLASSES
from api_clients import (
    nvd_lookup_cve, nvd_search_keyword, epss_lookup, cisa_kev_check,
    get_manufacturer_list, build_manufacturer_search_queries,
    get_cached_search, set_cached_search,
)

# ── App setup ────────────────────────────────────────────────────────────

app = Flask(__name__, static_folder="static", static_url_path="")

DEBUG = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes")

# Allow localhost origins only when running in debug/dev mode.
_allowed_origins = ["https://dtvss.io"]
if DEBUG:
    _allowed_origins += ["http://localhost:5000", "http://127.0.0.1:5000"]

CORS(app, origins=_allowed_origins)

# ── Rate limiting ────────────────────────────────────────────────────────
# 60 requests/minute per IP applied to all routes that hit external APIs.
if _limiter_available:
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=[],      # no blanket default — applied per-route below
        storage_uri="memory://",
    )
else:
    limiter = None

_API_RATE = "60 per minute"

NVD_API_KEY = os.environ.get("NVD_API_KEY", "")

# ── Input constraints ────────────────────────────────────────────────────
_SEARCH_MAX_LEN    = 200
_SEARCH_ALLOWED_RE = _re.compile(r"^[\w\s.\-+/()\[\]]+$")


def _validate_search_query(q: str):
    """
    Validate and sanitise the search query string.
    Returns (cleaned_query, None) on success or (None, error_message) on failure.
    """
    q = q.strip()
    if not q:
        return None, "Missing or empty 'q' parameter"
    if len(q) > _SEARCH_MAX_LEN:
        return None, f"Query too long (max {_SEARCH_MAX_LEN} characters)"
    if not _SEARCH_ALLOWED_RE.match(q):
        return None, "Query contains invalid characters"
    return q, None


# ── Error handler ────────────────────────────────────────────────────────

@app.errorhandler(Exception)
def handle_exception(e):
    """Return JSON instead of HTML for all errors so the frontend can parse them."""
    import traceback
    app.logger.error("Unhandled exception: %s\n%s", e, traceback.format_exc())
    code = getattr(e, "code", 500)
    return jsonify({"error": f"Server error: {e}", "type": e.__class__.__name__}), code


# ── Static routes ────────────────────────────────────────────────────────

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


# ── API routes ───────────────────────────────────────────────────────────
# Rate-limit decorator is a no-op when flask-limiter is not installed, so the
# same decorator expression works in both cases.

def _limit(f):
    """Apply _API_RATE limit if limiter is available, otherwise pass through."""
    return limiter.limit(_API_RATE)(f) if limiter else f


@app.route("/api/lookup")
@_limit
def lookup():
    """
    Look up a single CVE by ID.
    Auto-fetches B from NVD, L(t) from EPSS, detects KEV, classifies device, scores.

    GET /api/lookup?cve=CVE-2017-12725&tga_class=IIb
    tga_class is optional — auto-detected from CVE description if omitted.
    """
    cve_id       = request.args.get("cve", "").strip().upper()
    tga_override = request.args.get("tga_class", "").strip()

    if not cve_id:
        return jsonify({"error": "Missing 'cve' parameter"}), 400
    if not cve_id.startswith("CVE-"):
        cve_id = "CVE-" + cve_id
    if not _re.match(r"^CVE-\d{4}-\d{1,7}$", cve_id):
        return jsonify({"error": f"Invalid CVE ID format: {cve_id}"}), 400

    nvd = nvd_lookup_cve(cve_id, api_key=NVD_API_KEY)
    if not nvd or "error" in nvd:
        return jsonify(nvd or {"error": "NVD lookup failed"}), 404

    epss_data = epss_lookup([cve_id]).get(cve_id, {"epss": 0.0, "percentile": 0.0, "date": ""})
    tga_class, classify_source = resolve_tga_class(nvd.get("description", ""), tga_override)
    H = TGA_CLASSES[tga_class]["H"]

    kev_status = nvd.get("kev", False)
    kev_added  = nvd.get("kev_added", "")
    kev_due    = nvd.get("kev_due", "")
    kev_name   = nvd.get("kev_name", "")

    if not kev_status:
        cisa_kev = cisa_kev_check(cve_id)
        if cisa_kev:
            kev_status = True
            kev_added  = cisa_kev.get("kev_added", "")
            kev_due    = cisa_kev.get("kev_due", "")
            kev_name   = cisa_kev.get("kev_name", "")

    result = compute_dtvss(B=nvd["B"], L=epss_data["epss"], H=H, kev=kev_status)
    result.update({
        "cve_id":          cve_id,
        "description":     nvd.get("description", ""),
        "tga_class":       tga_class,
        "tga_label":       TGA_CLASSES[tga_class]["label"],
        "jurisdictions":   TGA_CLASSES[tga_class]["jurisdictions"],
        "cvss_version":    nvd.get("cvss_version", ""),
        "cvss_vector":     nvd.get("cvss_vector", ""),
        "severity":        nvd.get("severity", ""),
        "published":       nvd.get("published", ""),
        "epss_percentile": epss_data["percentile"],
        "epss_date":       epss_data["date"],
        "kev_added":       kev_added,
        "kev_due":         kev_due,
        "kev_name":        kev_name,
        "ics_advisory":    nvd.get("ics_advisory", False),
        "ics_urls":        nvd.get("ics_urls", []),
        "impact_score":    nvd.get("impact_score", 0.0),
        "classify_source": classify_source,
    })
    return jsonify(result)


@app.route("/api/search")
@_limit
def search():
    """
    Search by device name or keyword.
    Auto-fetches all matching CVEs, scores each, returns ranked list.

    GET /api/search?q=Medfusion+4000&tga_class=IIb
    tga_class is optional — auto-detected per CVE if omitted.
    """
    raw_query    = request.args.get("q", "")
    tga_override = request.args.get("tga_class", "").strip()
    max_results  = min(int(request.args.get("max", 20)), 50)

    query, err = _validate_search_query(raw_query)
    if err:
        return jsonify({"error": err}), 400

    cached = get_cached_search(query, tga_override)
    if cached is not None:
        return jsonify({"results": cached, "count": len(cached), "query": query, "cached": True})

    nvd_results_map: dict = {}
    for r in nvd_search_keyword(query, api_key=NVD_API_KEY, max_results=max_results):
        if "error" not in r and r.get("cve_id"):
            nvd_results_map[r["cve_id"]] = r

    try:
        for q in build_manufacturer_search_queries(query):
            if q == query:
                continue
            for r in nvd_search_keyword(q, api_key=NVD_API_KEY, max_results=max_results):
                if "error" not in r and r.get("cve_id") and r["cve_id"] not in nvd_results_map:
                    nvd_results_map[r["cve_id"]] = r
    except Exception as exc:
        app.logger.debug("Manufacturer expansion failed for %r: %s", query, exc)

    nvd_results = list(nvd_results_map.values())
    if not nvd_results:
        return jsonify({
            "results": [], "count": 0, "query": query,
            "note": f'No CVEs found in NVD for "{query}". '
                    f'This manufacturer may not have any disclosed vulnerabilities.',
        })

    valid = [r for r in nvd_results if "error" not in r]
    if not valid:
        return jsonify({
            "results": [], "count": 0, "query": query,
            "note": f'Found {len(nvd_results)} CVE(s) for "{query}" '
                    f'but none have CVSS scores available for DTVSS scoring.',
        })

    cve_ids  = [r["cve_id"] for r in valid]
    epss_map = epss_lookup(cve_ids)

    scored = []
    for nvd in valid:
        epss_data = epss_map.get(nvd["cve_id"], {"epss": 0.0, "percentile": 0.0, "date": ""})
        tga_class, _ = resolve_tga_class(nvd.get("description", ""), tga_override)
        H = TGA_CLASSES[tga_class]["H"]

        kev_status = nvd.get("kev", False)
        if not kev_status:
            cisa_kev = cisa_kev_check(nvd["cve_id"])
            if cisa_kev:
                kev_status = True

        result = compute_dtvss(nvd["B"], epss_data["epss"], H, kev=kev_status)
        result.update({
            "cve_id":          nvd["cve_id"],
            "description":     nvd.get("description", ""),
            "tga_class":       tga_class,
            "cvss_version":    nvd.get("cvss_version", ""),
            "severity":        nvd.get("severity", ""),
            "published":       nvd.get("published", ""),
            "epss_percentile": epss_data["percentile"],
            "epss_date":       epss_data["date"],
            "kev_added":       nvd.get("kev_added", ""),
            "ics_advisory":    nvd.get("ics_advisory", False),
            "impact_score":    nvd.get("impact_score", 0.0),
        })
        scored.append(result)

    scored.sort(key=lambda x: (0 if x.get("kev_override") else 1, -x["score"], x["cve_id"]))
    set_cached_search(query, scored, tga_override)

    return jsonify({"results": scored, "count": len(scored), "query": query})


@app.route("/api/score", methods=["POST"])
@_limit
def score():
    """
    Manual scoring endpoint.
    POST {"B": 3.9, "L": 0.0089, "H": 7.5, "kev": false}
    """
    data = request.json or {}
    try:
        B   = float(data.get("B", 0))
        L   = float(data.get("L", 0))
        H   = float(data.get("H", 7.5))
        kev = bool(data.get("kev", False))
    except (TypeError, ValueError) as exc:
        return jsonify({"error": f"Invalid input: {exc}"}), 400

    if not (0.0 <= B <= 10.0):
        return jsonify({"error": f"B must be between 0.0 and 10.0, got {B}"}), 400
    if not (0.0 <= L <= 1.0):
        return jsonify({"error": f"L must be between 0.0 and 1.0, got {L}"}), 400
    if H not in (2.0, 5.0, 7.5, 10.0):
        return jsonify({"error": f"H must be a valid TGA class value (2.0, 5.0, 7.5, or 10.0), got {H}"}), 400

    return jsonify(compute_dtvss(B, L, H, kev))


@app.route("/api/device-classes")
def device_classes():
    """Return available device classes with H values and jurisdiction mappings."""
    return jsonify(TGA_CLASSES)


@app.route("/api/manufacturers")
def manufacturers():
    """Return list of medical device manufacturers from FDA registry. Cached daily."""
    mdm_list = get_manufacturer_list()
    return jsonify({"manufacturers": mdm_list, "count": len(mdm_list),
                    "source": "openFDA Registration & Listing API"})


# ── Startup pre-warming ──────────────────────────────────────────────────

_startup_done = False


@app.before_request
def _startup_prewarm():
    global _startup_done
    if _startup_done:
        return
    _startup_done = True

    def _warm():
        try:
            from api_clients import refresh_device_keywords
            kw = refresh_device_keywords()
            app.logger.info("[prewarm] Device keywords: %d from openFDA", len(kw))
        except Exception as exc:
            app.logger.warning("[prewarm] Device keywords skipped: %s", exc)
        try:
            mdm = get_manufacturer_list()
            app.logger.info("[prewarm] Manufacturers: %d from FDA registry", len(mdm))
        except Exception as exc:
            app.logger.warning("[prewarm] Manufacturers skipped: %s", exc)
        try:
            cisa_kev_check("CVE-0000-0000")
            app.logger.info("[prewarm] CISA KEV catalog loaded")
        except Exception as exc:
            app.logger.warning("[prewarm] CISA KEV skipped: %s", exc)

    threading.Thread(target=_warm, daemon=True).start()


# ── Dev server entry-point ───────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))

    print(f"\n{'=' * 60}")
    print(f"  DTVSS Web v1.0.0")
    print(f"  Formula: (B/10 × H/10 × (1 + 15 × L(t))) × 10")
    print(f"  Patent Pending — © 2026 Andrew Broglio")
    print(f"{'=' * 60}")
    print(f"  http://localhost:{port}")
    print(f"  NVD API key: {'loaded' if NVD_API_KEY else 'not set (rate limited)'}")
    print(f"  Rate limiting: {'enabled' if limiter else 'flask-limiter not installed'}")
    print(f"  CORS: {'dev (localhost allowed)' if DEBUG else 'production only'}")
    print(f"{'=' * 60}\n")

    app.run(host="0.0.0.0", port=port, debug=DEBUG)
