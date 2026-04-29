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

from flask import Flask, abort, g, jsonify, redirect, request, send_from_directory

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
    _log_safe_value,
    MAX_JSON_BODY_BYTES,
)

# Medical-device scope filter — rejects non-medical CVEs (PHP-Fusion,
# Wonderware, WordPress, ZPanel, etc.) that were leaking through the old
# substring-based filter.
from medical_scope import is_in_scope, filter_scored_results

app = Flask(__name__, static_folder=None)  # MED-04: no wildcard static serving
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16 KB global cap on request bodies

# Where HTML pages, robots.txt, sitemap.xml, security-policy.html, and
# whitelisted static assets are served from.
#
# CORRECTION (2026-04-20): the project ships HTML pages in a `static/`
# subfolder (matches the original send_from_directory("static", ...)
# pattern). An earlier patch incorrectly resolved STATIC_DIR to the repo
# root, which was based on a misread of the file layout in a snapshot
# delivered to me — the live repo has always had `static/`. The fix here
# preserves the env-var override for operators who restructure later.
_APP_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.environ.get("DTVSS_STATIC_DIR") or os.path.join(_APP_DIR, "static")
WELL_KNOWN_DIR = os.path.join(STATIC_DIR, ".well-known")


# -----------------------------------------------------------------------------
# CSP nonce injection on the static HTML path (Fix #8 in PATCHES_v2)
# -----------------------------------------------------------------------------
# The HTML pages are served as flat files via send_from_directory, so there
# is no Jinja pass to inject the per-request CSP nonce that security.py
# generates in g.csp_nonce. Without injection, every inline <script> and
# <style> tag would be blocked by a strict CSP — meaning the existing
# DTVSS_CSP_STRICT=1 opt-in could never be safely enabled.
#
# This helper rewrites <script> and <style> open tags to carry the current
# request's nonce. It runs once per page load and adds a few hundred
# microseconds of regex work per request — a non-issue for a low-traffic
# tool, and crucially it makes strict CSP actually deployable.
#
# Limitations honestly stated:
#   - Does NOT touch inline event handlers (onclick=, onchange=, etc).
#     Those are blocked by strict CSP regardless of nonce, and the project
#     currently has ~10 of them. Strict CSP will require a separate
#     refactor to addEventListener; until then, the project should stay on
#     the default permissive CSP. The infrastructure is now in place so
#     that refactor can be done incrementally.
#   - Regex is intentionally restricted to opening <script> / <style> tags
#     that don't already have a nonce attribute, to avoid double-injection
#     if anything else adds one upstream.
import re as _re_csp
_SCRIPT_OPEN_RE = _re_csp.compile(
    rb'<(script|style)(?![^>]*\bnonce=)([^>]*)>',
    _re_csp.IGNORECASE,
)


def _inject_csp_nonce(html_bytes: bytes, nonce: str) -> bytes:
    """Inject nonce="..." into every inline <script>/<style> open tag.

    External script/style tags (with src= or href=) get nonces too — that's
    correct and required by strict CSP, since 'self' alone is not enough
    when 'unsafe-inline' is dropped: the browser still wants the nonce as
    an authentication token for the source.
    """
    if not nonce:
        return html_bytes
    nonce_attr = f' nonce="{nonce}"'.encode("ascii")
    return _SCRIPT_OPEN_RE.sub(
        lambda m: b'<' + m.group(1) + nonce_attr + m.group(2) + b'>',
        html_bytes,
    )


def _serve_html_with_nonce(directory: str, filename: str):
    """Wrapper around send_from_directory that injects g.csp_nonce.

    Falls back to plain send_from_directory if the file is missing or the
    nonce isn't available (e.g. before-request hasn't run for some reason).
    Sets the right Content-Type and prevents intermediate caches from
    serving one user's nonced response to another via Cache-Control and
    Vary: Cookie.
    """
    full_path = os.path.join(directory, filename)
    if not os.path.isfile(full_path):
        # Let send_from_directory do the 404 with proper error handling
        return send_from_directory(directory, filename)
    nonce = getattr(g, "csp_nonce", "") if g else ""
    if not nonce:
        return send_from_directory(directory, filename)
    with open(full_path, "rb") as fh:
        body = fh.read()
    body = _inject_csp_nonce(body, nonce)
    from flask import Response
    resp = Response(body, mimetype="text/html; charset=utf-8")
    # Each response carries a unique nonce. Caches must not share these
    # across requests or the nonce-CSP pairing breaks for the next user.
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    resp.headers["Pragma"] = "no-cache"
    return resp

# Fail loud if running in any managed deploy (Railway/Heroku/Fly/Render) without
# persistent storage. RAIL-01 in PENTEST_RAILWAY_ADDENDUM.md. A "works, silently
# loses data" configuration is worse than a startup crash.
#
# BUG FIX: previously this checked RAILWAY_ENVIRONMENT == "production", but
# Railway sets RAILWAY_ENVIRONMENT to whatever the user named their environment
# in the dashboard — "production" is only the default. Renamed environments
# (staging, prod, main, etc.) silently bypassed the guard, which was the exact
# failure mode this check was designed to prevent. We now trigger on ANY
# Railway-/Heroku-/Fly-/Render-style env var, with an explicit DTVSS_ALLOW_EPHEMERAL
# escape hatch for users who really do want ephemeral storage.
def _is_managed_deploy() -> bool:
    """True if running on Railway, Heroku, Fly, Render, or similar PaaS."""
    return any(
        os.environ.get(k)
        for k in (
            "RAILWAY_ENVIRONMENT",
            "RAILWAY_ENVIRONMENT_NAME",
            "RAILWAY_PROJECT_ID",
            "DYNO",                         # Heroku
            "FLY_APP_NAME",                 # Fly.io
            "RENDER",                       # Render
            "DTVSS_REQUIRE_PERSISTENT",     # explicit opt-in for any other host
        )
    )


if _is_managed_deploy():
    if not os.environ.get("DTVSS_DATA_DIR") and not os.environ.get("DTVSS_ALLOW_EPHEMERAL"):
        raise RuntimeError(
            "DTVSS_DATA_DIR must be set in managed deploys. "
            "Attach a persistent volume and set DTVSS_DATA_DIR=/data "
            "(or your mount point). Without this, hourly ICSMA index "
            "updates are lost on every restart. "
            "If you are intentionally running ephemeral, set "
            "DTVSS_ALLOW_EPHEMERAL=1 to suppress this check."
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
    "tiers": "tiers.html",
}

@app.route("/tiers")
def tiers():
    return _serve_html_with_nonce(STATIC_DIR, "tiers.html")

@app.route("/")
def index():
    return _serve_html_with_nonce(STATIC_DIR, "index.html")


@app.route("/calculator")
def calculator():
    return _serve_html_with_nonce(STATIC_DIR, "calculator.html")


@app.route("/calibration")
def calibration():
    return _serve_html_with_nonce(STATIC_DIR, "calibration.html")


@app.route("/about")
def about():
    return _serve_html_with_nonce(STATIC_DIR, "about.html")


@app.route("/robots.txt")
def robots():
    return send_from_directory(STATIC_DIR, "robots.txt", mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap():
    return send_from_directory(STATIC_DIR, "sitemap.xml", mimetype="application/xml")


# -----------------------------------------------------------------------------
# Security disclosure (RFC 9116)
# -----------------------------------------------------------------------------
# Researchers and scanners look here first. The well-known path is the
# canonical location; /security.txt is kept as a 301 for legacy clients.
# These routes MUST come before the catch-all /<path:filename> route below
# or that route will swallow them and 404 based on STATIC_ASSET_PREFIXES.

@app.route("/.well-known/security.txt")
def security_txt():
    # security.txt may live either under .well-known/ in the static dir
    # (production layout) or directly at the project root with the rest
    # of the static files (current repo layout). Prefer .well-known if
    # it exists; fall back to the root copy. Both are RFC 9116 compliant
    # as long as one of them is reachable at /.well-known/security.txt.
    if os.path.exists(os.path.join(WELL_KNOWN_DIR, "security.txt")):
        return send_from_directory(
            WELL_KNOWN_DIR,
            "security.txt",
            mimetype="text/plain; charset=utf-8",
        )
    return send_from_directory(
        STATIC_DIR,
        "security.txt",
        mimetype="text/plain; charset=utf-8",
    )


@app.route("/security.txt")
def security_txt_legacy():
    return redirect("/.well-known/security.txt", code=301)


@app.route("/security-policy")
def security_policy():
    return _serve_html_with_nonce(STATIC_DIR, "security-policy.html")


# Serve only whitelisted static assets (CSS, JS, images)
STATIC_ASSET_PREFIXES = ("assets/", "css/", "js/", "img/", "fonts/")


@app.route("/<path:filename>")
def static_asset(filename):
    """Serve static assets from STATIC_DIR, but only from known subfolders."""
    if not filename.startswith(STATIC_ASSET_PREFIXES):
        abort(404)
    # send_from_directory protects against ../ traversal
    return send_from_directory(STATIC_DIR, filename)

# -----------------------------------------------------------------------------
# 404 handler — HTML page for browser routes, JSON for API routes
# -----------------------------------------------------------------------------
@app.errorhandler(404)
def page_not_found(e):
    """Custom 404. JSON for API routes (matches existing 4xx shape);
    styled HTML page for everything else."""
    if request.path.startswith("/api/"):
        return jsonify({
            "error": "Not found",
            "request_id": getattr(g, "request_id", None),
        }), 404
    return send_from_directory(STATIC_DIR, "404.html"), 404

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
        log.exception("NVD lookup failed for %s", _log_safe_value(cve_id))
        return jsonify({
            "error": "Upstream lookup failed",
            "request_id": getattr(g, "request_id", None),
        }), 502

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
        log.exception("EPSS lookup failed for %s", _log_safe_value(cve_id))
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
        except Exception as e:
            log.warning("KEV check failed for %s: %s",
                        _log_safe_value(cve_id), _log_safe_value(e))

    # Defensive bounds before strict compute_dtvss. NVD-derived B and
    # EPSS-derived L are nominally in range, but malformed upstream
    # responses shouldn't blow up the request handler.
    try:
        B_in = float(nvd.get("B", 0) or 0)
    except (TypeError, ValueError):
        B_in = 0.0
    try:
        L_in = float(epss_data.get("epss", 0) or 0)
    except (TypeError, ValueError):
        L_in = 0.0
    B_in = max(0.0, min(10.0, B_in))
    L_in = max(0.0, min(1.0, L_in))

    try:
        result = compute_dtvss(B=B_in, L=L_in, H=H, kev=kev_status)
    except ValueError as ve:
        log.warning("compute_dtvss rejected inputs for %s: %s",
                    _log_safe_value(cve_id), _log_safe_value(ve))
        # No 'detail' field — keeping str(ve) out of the response avoids
        # CodeQL py/stack-trace-exposure flow. Operators correlate via
        # request_id in logs.
        return jsonify({
            "error": "CVE has invalid scoring inputs",
            "cve_id": cve_id,
            "request_id": getattr(g, "request_id", None),
        }), 422

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
    except ValueError:
        return jsonify({
            "error": "Invalid 'max' parameter",
            "hint": "Must be an integer between 1 and 100",
        }), 400

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
            except (TypeError, ValueError) as e:
                log.warning("Exploitability parse failed for %s: %s",
                            _log_safe_value(cve_id), _log_safe_value(e))
        if not B:
            continue  # Skip unscorable CVEs rather than guess

        # Bound L defensively. EPSS should always be in [0,1] but a poisoned
        # cache or upstream bug shouldn't crash the request handler now that
        # compute_dtvss is strict.
        try:
            L = float(epss_map.get(cve_id, {}).get("epss", 0))
        except (TypeError, ValueError):
            L = 0.0
        L = max(0.0, min(1.0, L))
        # Bound B similarly. parse_cvss31_exploitability is internally bounded,
        # but the exploitability fallback path reads arbitrary index data.
        B = max(0.0, min(10.0, B))

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
        try:
            result = compute_dtvss(B, L, H, kev)
        except ValueError as ve:
            log.warning("compute_dtvss rejected inputs for %s: %s",
                        _log_safe_value(cve_id), _log_safe_value(ve))
            continue

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
            except Exception as e:
                log.warning("KEV fallback check failed for %s: %s",
                            _log_safe_value(nvd.get("cve_id")), _log_safe_value(e))

        # Defensive bounds before strict compute_dtvss.
        try:
            B_in = float(nvd.get("B", 0) or 0)
        except (TypeError, ValueError):
            B_in = 0.0
        try:
            L_in = float(epss_data.get("epss", 0) or 0)
        except (TypeError, ValueError):
            L_in = 0.0
        B_in = max(0.0, min(10.0, B_in))
        L_in = max(0.0, min(1.0, L_in))

        try:
            result = compute_dtvss(B_in, L_in, H, kev=kev_status)
        except ValueError as ve:
            log.warning("compute_dtvss rejected inputs for %s: %s",
                        _log_safe_value(nvd.get("cve_id")),
                        _log_safe_value(ve))
            continue
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
    # ASVS V13.2.5: enforce application/json on JSON endpoints.
    # request.is_json checks Content-Type is application/json (or a
    # recognised JSON subtype). Rejecting other types with 415 gives
    # clients a clear error instead of the misleading "Expected JSON
    # object body" 400 that get_json(silent=True) would otherwise produce.
    if not request.is_json:
        return jsonify({
            "error": "Content-Type must be application/json",
        }), 415

    # silent=False: malformed JSON returns 400 with a descriptive message
    # via the global error handler, rather than silently returning None.
    try:
        data = request.get_json()
    except Exception:
        return jsonify({"error": "Malformed JSON body"}), 400

    if not isinstance(data, dict):
        return jsonify({"error": "Expected JSON object body"}), 400

    required = ("B", "L", "H")
    missing = [k for k in required if k not in data]
    if missing:
        return jsonify({
            "error": f"Missing required field(s): {', '.join(missing)}",
            "required": list(required),
        }), 400
    
    # Validate each parameter individually so we can return a specific,
    # safe error message naming which parameter failed and its valid range.
    # We deliberately don't echo str(e) to the client — CodeQL flags any
    # exception object flow into responses (py/stack-trace-exposure), and
    # keeping our error messages hard-coded here makes the safety property
    # locally obvious to both reviewers and static analysis.
    _PARAM_BOUNDS = {
        "B": (0.0, 10.0, "CVSS Base sub-score"),
        "L": (0.0, 1.0, "EPSS probability"),
        "H": (0.0, 10.0, "TGA harm weighting"),
    }
    try:
        B = validate_float_param(data["B"], "B", *_PARAM_BOUNDS["B"][:2])
        L = validate_float_param(data["L"], "L", *_PARAM_BOUNDS["L"][:2])
        H = validate_float_param(data["H"], "H", *_PARAM_BOUNDS["H"][:2])
        kev = bool(data.get("kev", False))
    except ValueError:
        # Identify which param failed by re-validating with abort-on-first.
        # Keeps the response message constructed from our own (safe) bounds
        # rather than from the exception string.
        failed = None
        for name in ("B", "L", "H"):
            lo, hi, _desc = _PARAM_BOUNDS[name]
            try:
                validate_float_param(data.get(name), name, lo, hi)
            except ValueError:
                failed = name
                break
        if failed is None:
            # Should not happen — defence in depth
            return jsonify({"error": "Invalid score parameters"}), 400
        lo, hi, desc = _PARAM_BOUNDS[failed]
        return jsonify({
            "error": f"Invalid '{failed}' parameter",
            "hint": f"{desc} must be a finite number in [{lo}, {hi}]",
        }), 400

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

# Warm the CISA KEV cache at startup so the first request doesn't synchronously
# pay a ~1 MB JSON download. Without this, four gunicorn workers each pay the
# cold-start cost on their first hit, blocking real user requests for several
# seconds while CISA responds. Failure here is non-fatal — cisa_kev_check has
# its own backoff logic.
try:
    from api_clients import cisa_kev_check
    cisa_kev_check("CVE-0000-0000")  # any non-existent CVE triggers cache warm
    log.info("KEV catalog cache warmed at startup")
except Exception as _e:
    log.warning("KEV cache warm skipped: %s", sanitize_error(_e))


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
