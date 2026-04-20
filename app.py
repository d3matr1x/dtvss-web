# DTVSS - Web Application (SECURITY HARDENED)
# Copyright © 2026 Andrew Broglio. All rights reserved.
# Patent Pending - IP Australia
# Licensed under BSL 1.1 - Commercial licence required for production use.

"""
DTVSS Tier 1 Web Application — Security Hardened
==================================================
This version applies all findings from PENTEST_REPORT.md via security.py.

Changes from original:
  - CORS allowlist (HIGH-01)
  - ProxyFix for accurate client IPs (HIGH-02)
  - Redis-backed rate limiting with X-Forwarded-For awareness (HIGH-02)
  - Input validation on all parameters (HIGH-03, HIGH-04, MED-02)
  - Response size caps on outbound fetches (HIGH-03)
  - Error message sanitization (HIGH-05)
  - Security headers on all responses (MED-01)
  - Payload size guards on POST (MED-02)
  - Explicit static file allowlist (MED-04)
  - Atomic index writes via security.atomic_write_json (MED-05)
  - Structured logging with query hashing (MED-06)
  - Modern request.get_json() (MED-07)
  - Dedicated /health endpoint (INFO-03)
"""

import hashlib
import logging
import os
import uuid

from flask import Flask, abort, g, jsonify, redirect, request, send_from_directory
from werkzeug.exceptions import HTTPException

from dtvss_engine import compute_dtvss, classify_device, TGA_CLASSES
from api_clients import nvd_lookup_cve, nvd_search_keyword, epss_lookup, cisa_kev_check
from index_loader import (
    get_manufacturer_dropdown,
    search_manufacturer_cves,
    get_cpe_search_terms,
    get_advisory_urls,
)

# Security module — centralized hardening
from security import (
    apply_hardening,
    get_real_client_ip,
    validate_cve_id,
    validate_query,
    validate_float_param,
    validate_int_param,
    sanitize_error,
    require_max_body_size,
    MAX_JSON_BODY_BYTES,
)

# Medical-device scope filter — rejects non-medical CVEs (PHP-Fusion,
# Wonderware, WordPress, ZPanel, etc.) that were leaking through the old
# substring-based filter.
from medical_scope import is_in_scope, filter_scored_results

app = Flask(__name__, static_folder=None)  # MED-04: no wildcard static serving
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16 KB global cap on request bodies

# Fail loud if running in Railway production without persistent storage
# (RAIL-01 in PENTEST_RAILWAY_ADDENDUM.md). A "works, silently loses data"
# configuration is worse than a startup crash.
if os.environ.get("RAILWAY_ENVIRONMENT") == "production":
    if not os.environ.get("DTVSS_DATA_DIR"):
        raise RuntimeError(
            "DTVSS_DATA_DIR must be set in Railway production. "
            "Attach a Railway Volume and set DTVSS_DATA_DIR=/data. "
            "Without this, hourly ICSMA index updates are lost on every restart."
        )
    if not os.environ.get("DTVSS_CORS_ORIGINS"):
        logging.warning(
            "DTVSS_CORS_ORIGINS is not set — CORS will use default allowlist "
            "which probably doesn't match your production domain."
        )

# Apply all Flask-level security hardening at once
apply_hardening(app)

NVD_API_KEY = os.environ.get("NVD_API_KEY", "")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(request_id)s] %(name)s: %(message)s",
)
log = logging.getLogger("dtvss")


# Add request_id to every log record
class RequestIdFilter(logging.Filter):
    def filter(self, record):
        try:
            record.request_id = getattr(g, "request_id", "-")
        except RuntimeError:
            record.request_id = "-"
        return True


for handler in logging.getLogger().handlers:
    handler.addFilter(RequestIdFilter())


# -----------------------------------------------------------------------------
# Rate limiting (HIGH-02 hardened)
# -----------------------------------------------------------------------------
try:
    from flask_limiter import Limiter

    limiter = Limiter(
        get_real_client_ip,  # Uses ProxyFix-corrected IP
        app=app,
        default_limits=["200 per hour", "30 per minute"],
        storage_uri=os.environ.get("REDIS_URL", "memory://"),
        strategy="fixed-window",
        headers_enabled=True,  # Adds X-RateLimit-* headers
    )
    RATE_LIMIT_EXPENSIVE = "20 per hour;5 per minute"
    RATE_LIMIT_CHEAP = "300 per hour;60 per minute"

    def _expensive(fn):
        return limiter.limit(RATE_LIMIT_EXPENSIVE)(fn)

    def _cheap(fn):
        return limiter.limit(RATE_LIMIT_CHEAP)(fn)

except ImportError:
    log.warning("Flask-Limiter not installed; running without rate limiting")

    def _expensive(fn):
        return fn

    def _cheap(fn):
        return fn


# Helper for query logging — hash the query to avoid logging PII
def _query_hash(q: str) -> str:
    return hashlib.sha256(q.encode("utf-8")).hexdigest()[:8]


# -----------------------------------------------------------------------------
# Routes: HTML pages (MED-04: explicit allowlist only)
# -----------------------------------------------------------------------------
STATIC_PAGES = {
    "": "index.html",
    "calculator": "calculator.html",
    "calibration": "calibration.html",
    "about": "about.html",
}


@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/calculator")
def calculator():
    return send_from_directory("static", "calculator.html")


@app.route("/calibration")
def calibration():
    return send_from_directory("static", "calibration.html")


@app.route("/about")
def about():
    return send_from_directory("static", "about.html")


@app.route("/robots.txt")
def robots():
    return send_from_directory("static", "robots.txt", mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap():
    return send_from_directory("static", "sitemap.xml", mimetype="application/xml")


# -----------------------------------------------------------------------------
# Security disclosure (RFC 9116)
# -----------------------------------------------------------------------------
# Researchers and scanners look here first. The well-known path is the
# canonical location; /security.txt is kept as a 301 for legacy clients.
# These routes MUST come before the catch-all /<path:filename> route below
# or that route will swallow them and 404 based on STATIC_ASSET_PREFIXES.

@app.route("/.well-known/security.txt")
def security_txt():
    return send_from_directory(
        "static/.well-known",
        "security.txt",
        mimetype="text/plain; charset=utf-8",
    )


@app.route("/security.txt")
def security_txt_legacy():
    return redirect("/.well-known/security.txt", code=301)


@app.route("/security-policy")
def security_policy():
    return send_from_directory("static", "security-policy.html")


# Serve only whitelisted static assets (CSS, JS, images)
STATIC_ASSET_PREFIXES = ("assets/", "css/", "js/", "img/", "fonts/")


@app.route("/<path:filename>")
def static_asset(filename):
    """Serve static assets from /static, but only from known subfolders."""
    if not filename.startswith(STATIC_ASSET_PREFIXES):
        abort(404)
    # send_from_directory protects against ../ traversal
    return send_from_directory("static", filename)


# -----------------------------------------------------------------------------
# Health check (INFO-03: decoupled from business logic)
# -----------------------------------------------------------------------------
@app.route("/health")
@_cheap
def health():
    return jsonify({
        "status": "ok",
        "service": "dtvss",
        "version": "1.1.0",
    })


# -----------------------------------------------------------------------------
# API: /api/lookup (HIGH-04, MED-02 validation)
# -----------------------------------------------------------------------------
@app.route("/api/lookup")
@_expensive
def lookup():
    """Look up a single CVE by ID. Auto-scores."""
    raw_cve = request.args.get("cve", "")
    cve_id = validate_cve_id(raw_cve)
    if not cve_id:
        return jsonify({
            "error": "Invalid or missing 'cve' parameter",
            "hint": "Expected format: CVE-YYYY-NNNNN",
        }), 400

    tga_override = request.args.get("tga_class", "").strip()
    if tga_override and tga_override not in TGA_CLASSES:
        return jsonify({
            "error": f"Invalid tga_class '{tga_override}'",
            "valid": list(TGA_CLASSES.keys()),
        }), 400

    try:
        nvd = nvd_lookup_cve(cve_id, api_key=NVD_API_KEY)
    except Exception as e:
        log.exception("NVD lookup failed for %s", cve_id)
        return jsonify({"error": "Upstream lookup failed", "detail": sanitize_error(e)}), 502

    if not nvd or "error" in nvd:
        return jsonify(nvd or {"error": "NVD lookup failed"}), 404

    # Scope gate: DTVSS is for medical devices only. Reject non-medical
    # CVEs (CMS, SCADA, SaaS) before any scoring. Without this, a user
    # looking up e.g. CVE-2006-2331 (PHP-Fusion) would get a fake DTVSS
    # Critical score for a 20-year-old website bug.
    #
    # User TGA override bypasses this gate — if someone explicitly sets
    # tga_class, they're asserting this is a medical device, so we trust
    # them. Useful for new devices not yet in our terminology list.
    if not tga_override:
        in_scope, reason = is_in_scope(
            nvd.get("description", ""),
            ics_advisory=nvd.get("ics_advisory", False),
            ics_urls=nvd.get("ics_urls", []),
        )
        if not in_scope:
            return jsonify({
                "error": "CVE is outside DTVSS scope",
                "cve_id": cve_id,
                "scope_reason": reason,
                "hint": "DTVSS scores medical-device vulnerabilities only. "
                        "This CVE does not reference an ICSMA advisory or "
                        "contain medical-device terminology. If this is a "
                        "medical device we failed to recognise, retry with "
                        "&tga_class=IIb or &tga_class=III.",
            }), 400

    try:
        epss = epss_lookup([cve_id])
    except Exception as e:
        log.exception("EPSS lookup failed for %s", cve_id)
        epss = {}
    epss_data = epss.get(cve_id, {"epss": 0.0, "percentile": 0.0, "date": ""})

    # TGA classification
    if tga_override:
        tga_class = tga_override
        classify_source = "user"
    else:
        tga_class, classify_source = classify_device(nvd.get("description", ""))
        if not tga_class:
            tga_class = "IIb"
            classify_source = "default"

    H = TGA_CLASSES[tga_class]["H"]

    # KEV check
    kev_status = nvd.get("kev", False)
    kev_added = nvd.get("kev_added", "")
    kev_due = nvd.get("kev_due", "")
    kev_name = nvd.get("kev_name", "")
    if not kev_status:
        try:
            cisa_kev = cisa_kev_check(cve_id)
            if cisa_kev:
                kev_status = True
                kev_added = cisa_kev.get("kev_added", "")
                kev_due = cisa_kev.get("kev_due", "")
                kev_name = cisa_kev.get("kev_name", "")
        except Exception:
            pass  # KEV check failure is non-fatal

    result = compute_dtvss(
        B=nvd.get("B", 0),
        L=epss_data["epss"],
        H=H,
        kev=kev_status,
    )

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


# -----------------------------------------------------------------------------
# API: /api/search (HIGH-04 input validation, response caps)
# -----------------------------------------------------------------------------
@app.route("/api/search")
@_expensive
def search():
    """Search by device name or keyword."""
    raw_query = request.args.get("q", "")
    query = validate_query(raw_query)
    if not query:
        return jsonify({
            "error": "Invalid or missing 'q' parameter",
            "hint": f"Query must be 1-100 printable chars, no control chars",
        }), 400

    tga_override = request.args.get("tga_class", "").strip()
    if tga_override and tga_override not in TGA_CLASSES:
        return jsonify({
            "error": f"Invalid tga_class '{tga_override}'",
            "valid": list(TGA_CLASSES.keys()),
        }), 400

    try:
        max_results = validate_int_param(
            request.args.get("max", 50), "max", 1, 100,
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    log.info("search q_hash=%s max=%d", _query_hash(query), max_results)

    # === Try pre-built ICSMA index first ===
    indexed_cves = search_manufacturer_cves(query)
    if indexed_cves:
        return _search_indexed(query, tga_override, max_results, indexed_cves)

    # === Fall back to live NVD ===
    return _search_live_nvd(query, tga_override, max_results)


def _search_indexed(query: str, tga_override: str, max_results: int, indexed_cves: list):
    """Score CVEs from the pre-built index."""
    from api_clients import parse_cvss31_exploitability

    adv_urls = get_advisory_urls(query)
    ics_urls = [a["url"] for a in adv_urls if a.get("url")]

    # Batch EPSS for all CVEs (epss_lookup handles chunking internally post-fix)
    all_cve_ids = [ic.get("cve_id", "") for ic in indexed_cves if ic.get("cve_id")]
    try:
        epss_map = epss_lookup(all_cve_ids)
    except Exception:
        log.exception("EPSS batch lookup failed")
        epss_map = {}

    scored = []
    for ic in indexed_cves:
        cve_id = ic.get("cve_id", "")
        if not cve_id:
            continue

        # Proper B extraction with validated fallback chain
        B = 0.0
        vec = ic.get("cvss_vector", "")
        if vec:
            B = parse_cvss31_exploitability(vec) or 0.0
        if not B and ic.get("exploitability"):
            try:
                B = float(ic["exploitability"])
            except (TypeError, ValueError):
                pass
        if not B:
            continue  # Skip unscorable CVEs rather than guess

        L = float(epss_map.get(cve_id, {}).get("epss", 0))

        try:
            kev = bool(cisa_kev_check(cve_id))
        except Exception:
            kev = False

        # TGA class
        if tga_override in TGA_CLASSES:
            tga_class = tga_override
        else:
            tga_class, _ = classify_device((ic.get("description", "") + " " + query))
            if not tga_class:
                tga_class = "IIb"

        H = TGA_CLASSES[tga_class]["H"]
        result = compute_dtvss(B, L, H, kev)

        scored.append({
            "cve_id": cve_id,
            "description": ic.get("description", ""),
            "score": result["score"],
            "risk_level": result["risk_level"],
            "guidance": result["guidance"],
            "B": result["B"], "H": result["H"], "L": result["L"],
            "static_baseline": result["static_baseline"],
            "tga_class": tga_class,
            "tga_label": TGA_CLASSES[tga_class]["label"],
            "jurisdictions": TGA_CLASSES[tga_class]["jurisdictions"],
            "kev_override": result["kev_override"],
            "cvss_version": ic.get("cvss_version", ""),
            "cvss_vector": vec,
            "base_score": ic.get("base_score", 0),
            "severity": ic.get("severity", ""),
            "published": ic.get("published", ""),
            "epss_percentile": epss_map.get(cve_id, {}).get("percentile", 0),
            "ics_advisory": bool(ics_urls),
            "ics_urls": ics_urls[:3],
            "source": ic.get("source", "icsma"),
        })

    # Scope filter: the ICSMA index SHOULD already be medical-only, but
    # apply the filter as defense-in-depth. Also ensures consistency with
    # the live-NVD path so the two sources never disagree on what counts
    # as a medical-device CVE.
    scored, scope_stats = filter_scored_results(scored)

    scored.sort(key=lambda x: (0 if x.get("kev_override") else 1, -x["score"]))
    return jsonify({
        "results": scored[:max_results],
        "count": len(scored),
        "query": query,
        "source": "CISA ICSMA index",
        "scope_filter": scope_stats,
    })


def _search_live_nvd(query: str, tga_override: str, max_results: int):
    """Fallback to live NVD keyword search."""
    import time as _search_time

    nvd_results_map = {}
    try:
        baseline = nvd_search_keyword(query, api_key=NVD_API_KEY, max_results=max_results) or []
    except Exception as e:
        log.exception("NVD search failed for q_hash=%s", _query_hash(query))
        return jsonify({
            "results": [], "count": 0, "query": query,
            "note": "Upstream search temporarily unavailable. Try again later.",
        }), 503

    for r in baseline:
        if "error" in r:
            continue
        cve_id = r.get("cve_id", "")
        if cve_id:
            nvd_results_map[cve_id] = r

    # CPE expansion with time + count budgets (HIGH-04)
    EXPANSION_TIME_BUDGET = 15.0
    EXPANSION_QUERY_LIMIT = 10
    expansion_start = _search_time.time()
    expansion_count = 0

    try:
        expanded_queries = get_cpe_search_terms(query) or [query]
    except Exception:
        expanded_queries = [query]

    for q in expanded_queries:
        if q == query:
            continue
        if expansion_count >= EXPANSION_QUERY_LIMIT:
            break
        if (_search_time.time() - expansion_start) > EXPANSION_TIME_BUDGET:
            break

        expansion_count += 1
        try:
            batch = nvd_search_keyword(q, api_key=NVD_API_KEY, max_results=max_results) or []
        except Exception:
            continue
        for r in batch:
            if "error" in r:
                continue
            cve_id = r.get("cve_id", "")
            if cve_id and cve_id not in nvd_results_map:
                nvd_results_map[cve_id] = r

    nvd_results = list(nvd_results_map.values())
    if not nvd_results:
        return jsonify({
            "results": [], "count": 0, "query": query,
            "note": "No CVEs found.",
        })

    valid = [r for r in nvd_results if "error" not in r]
    if not valid:
        return jsonify({
            "results": [], "count": 0, "query": query,
            "note": "Found CVEs but none have CVSS scores available for DTVSS scoring.",
        })

    cve_ids = [r["cve_id"] for r in valid]
    try:
        epss_map = epss_lookup(cve_ids)
    except Exception:
        epss_map = {}

    scored = []
    for nvd in valid:
        epss_data = epss_map.get(nvd["cve_id"], {"epss": 0.0, "percentile": 0.0, "date": ""})

        if tga_override in TGA_CLASSES:
            tga_class = tga_override
        else:
            tga_class, _ = classify_device(nvd.get("description", ""))
            if not tga_class:
                tga_class = "IIb"

        H = TGA_CLASSES[tga_class]["H"]

        kev_status = nvd.get("kev", False)
        if not kev_status:
            try:
                if cisa_kev_check(nvd["cve_id"]):
                    kev_status = True
            except Exception:
                pass

        result = compute_dtvss(nvd["B"], epss_data["epss"], H, kev=kev_status)
        result.update({
            "cve_id": nvd["cve_id"],
            "description": nvd.get("description", ""),
            "tga_class": tga_class,
            "tga_label": TGA_CLASSES[tga_class]["label"],
            "jurisdictions": TGA_CLASSES[tga_class]["jurisdictions"],
            "cvss_version": nvd.get("cvss_version", ""),
            "cvss_vector": nvd.get("cvss_vector", ""),
            "base_score": nvd.get("B", 0),
            "severity": nvd.get("severity", ""),
            "published": nvd.get("published", ""),
            "epss_percentile": epss_data["percentile"],
            "epss_date": epss_data["date"],
            "kev_added": nvd.get("kev_added", ""),
            "ics_advisory": nvd.get("ics_advisory", False),
            "ics_urls": nvd.get("ics_urls", []),
            "impact_score": nvd.get("impact_score", 0.0),
        })
        scored.append(result)

    # Scope filter — THIS IS THE CRITICAL FIX.
    # Before this filter, searches for terms like "infusion" would return
    # PHP-Fusion CMS, Wonderware InFusion SCADA, WordPress Infusionsoft,
    # ZPanel, etc. — all scored as Critical Class IIb medical devices.
    # filter_scored_results rejects them using word-boundary regex and an
    # explicit non-medical blocklist.
    scored, scope_stats = filter_scored_results(scored)

    # If filtering removed everything, return an informative empty result
    # rather than silently returning []. Users can see what happened.
    if not scored:
        return jsonify({
            "results": [],
            "count": 0,
            "query": query,
            "source": "NVD live search",
            "scope_filter": scope_stats,
            "note": (
                f"No medical-device CVEs found for this query. "
                f"{scope_stats['rejected_blocklist']} result(s) rejected as "
                f"non-medical (CMS, SCADA, or other); "
                f"{scope_stats['rejected_no_signal']} result(s) had no "
                f"medical-device indicators. Try a more specific medical "
                f"device name (e.g. 'Hospira LifeCare', 'Medfusion 4000')."
            ),
        })

    scored.sort(key=lambda x: (0 if x.get("kev_override") else 1, -x["score"], x["cve_id"]))
    return jsonify({
        "results": scored[:max_results],
        "count": len(scored),
        "query": query,
        "source": "NVD live search",
        "scope_filter": scope_stats,
    })


# -----------------------------------------------------------------------------
# API: /api/score (MED-02 — full input validation)
# -----------------------------------------------------------------------------
@app.route("/api/score", methods=["POST"])
@_cheap
@require_max_body_size(MAX_JSON_BODY_BYTES)
def score():
    """Manual scoring. POST {B, L, H, kev}."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Expected JSON object body"}), 400

    try:
        B = validate_float_param(data.get("B", 0), "B", 0.0, 10.0)
        L = validate_float_param(data.get("L", 0), "L", 0.0, 1.0)
        H = validate_float_param(data.get("H", 7.5), "H", 0.0, 10.0)
        kev = bool(data.get("kev", False))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    return jsonify(compute_dtvss(B, L, H, kev))


# -----------------------------------------------------------------------------
# API: /api/device-classes, /api/manufacturers (cheap, rate-limited)
# -----------------------------------------------------------------------------
@app.route("/api/device-classes")
@_cheap
def device_classes():
    return jsonify(TGA_CLASSES)


@app.route("/api/manufacturers")
@_cheap
def manufacturers():
    mdm_list = get_manufacturer_dropdown()
    return jsonify({
        "manufacturers": mdm_list,
        "count": len(mdm_list),
        "source": "CISA ICSMA (CSAF JSON + RSS)",
    })


# -----------------------------------------------------------------------------
# Startup
# -----------------------------------------------------------------------------
try:
    from api_clients import refresh_device_keywords
    _keywords = refresh_device_keywords()
    log.info("Device keywords loaded: %d", len(_keywords))
except Exception as _e:
    log.warning("Device keyword refresh skipped: %s", sanitize_error(_e))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n{'=' * 60}")
    print(f"  DTVSS Web v1.1.0 (Security Hardened)")
    print(f"  Formula: (B/10 × H/10 × (1 + 15 × L(t))) × 10")
    print(f"{'=' * 60}")
    print(f"  http://localhost:{port}")
    print(f"  NVD API key: {'loaded' if NVD_API_KEY else 'not set'}")
    print(f"  CORS origins: {os.environ.get('DTVSS_CORS_ORIGINS', 'defaults')}")
    print(f"  Rate limit storage: {os.environ.get('REDIS_URL', 'memory (single-worker)')}")
    print(f"{'=' * 60}\n")
    app.run(host="0.0.0.0", port=port, debug=False)
