"""
DTVSS Security Hardening Module
================================
Drop-in security hardening for the DTVSS Flask application.

This module centralizes security controls identified in the penetration test:
  - XXE-safe XML parsing
  - SSRF protection for URL fetching
  - CORS allowlist
  - Security headers
  - Input validation helpers
  - Safe JSON fetching with size limits
  - Error message sanitization
  - Atomic file writes

USAGE:
  from security import apply_hardening, safe_fetch_json, validate_external_url
  
  app = Flask(__name__)
  apply_hardening(app)  # Adds headers, CORS, ProxyFix

Copyright 2026 Andrew Broglio. All rights reserved.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import math
import os
import re
import socket
import tempfile
import urllib.parse
import urllib.request
import uuid
from typing import Any, Optional
from functools import wraps

log = logging.getLogger("dtvss.security")


# =============================================================================
# CONFIGURATION
# =============================================================================

# SSRF: hosts the server is permitted to fetch from
ALLOWED_EXTERNAL_HOSTS = {
    "services.nvd.nist.gov",
    "cveawg.mitre.org",
    "api.first.org",
    "www.cisa.gov",
    "cisa.gov",
    "api.fda.gov",
    "raw.githubusercontent.com",
    "api.github.com",
}

ALLOWED_SCHEMES = {"https"}

# Hostname suffixes to block even before DNS resolution.
# Catches Railway private networking (*.railway.internal) and similar
# internal TLDs. The post-DNS IP check also catches these via is_private,
# but blocking at the hostname level is faster and avoids unnecessary DNS.
BLOCKED_DOMAIN_SUFFIXES = (
    ".railway.internal",  # Railway private networking
    ".internal",          # General internal TLD convention
    ".local",             # mDNS / Bonjour
    ".localhost",         # Loopback alias
    ".lan",               # Home / office LANs
    ".intranet",          # Corporate intranets
)

# CORS: origins permitted to call the API from browsers
# Override via DTVSS_CORS_ORIGINS env var (comma-separated)
DEFAULT_CORS_ORIGINS = [
    "https://dtvss.app",
    "https://www.dtvss.app",
]

# Response size caps to prevent memory exhaustion
MAX_RESPONSE_BYTES = 10 * 1024 * 1024    # 10 MB for JSON APIs
MAX_HTML_PAGE_BYTES = 2 * 1024 * 1024    # 2 MB for HTML advisory pages
MAX_RSS_BYTES = 5 * 1024 * 1024          # 5 MB for RSS feeds

# Query / input caps
MAX_QUERY_LENGTH = 100
MAX_CVE_ID_LENGTH = 30       # "CVE-YYYY-NNNNNNN" maxes around 20
MAX_JSON_BODY_BYTES = 1024   # /api/score body is tiny


# =============================================================================
# SSRF PROTECTION
# =============================================================================

def validate_external_url(url: str, extra_allowed_hosts: Optional[set] = None) -> bool:
    """
    Return True if the URL is safe to fetch server-side.
    
    Blocks:
      - Non-HTTPS schemes (file://, gopher://, ftp://)
      - Hosts not in allowlist
      - Private/loopback/link-local/reserved IPs (after DNS resolution)
      - Cloud metadata endpoints
    """
    if not url or not isinstance(url, str):
        return False
    
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False
    
    # Scheme check
    if parsed.scheme not in ALLOWED_SCHEMES:
        log.warning("SSRF: rejected scheme %s for %s", parsed.scheme, _redact_url(url))
        return False
    
    # Host check
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False
    
    # Block internal/private DNS suffixes before DNS lookup.
    # Catches Railway private networking, mDNS, and corporate intranets.
    for suffix in BLOCKED_DOMAIN_SUFFIXES:
        if hostname.endswith(suffix):
            log.warning("SSRF: rejected internal suffix %s", hostname)
            return False
    
    allowed = set(ALLOWED_EXTERNAL_HOSTS)
    if extra_allowed_hosts:
        allowed |= extra_allowed_hosts
    
    if hostname not in allowed:
        log.warning("SSRF: rejected host %s", hostname)
        return False
    
    # Resolve to IP and verify it's public.
    # This catches DNS rebinding where a public hostname resolves to internal IP.
    try:
        # Resolve all addresses, block if ANY is private
        addr_info = socket.getaddrinfo(hostname, None, family=socket.AF_UNSPEC)
        for info in addr_info:
            ip_str = info[4][0]
            # IPv6 link-local sometimes appends %iface; strip it
            ip_str = ip_str.split("%")[0]
            try:
                addr = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if (addr.is_private or addr.is_loopback or addr.is_link_local
                    or addr.is_reserved or addr.is_multicast
                    or addr.is_unspecified):
                log.warning("SSRF: %s resolves to non-public %s", hostname, ip_str)
                return False
    except socket.gaierror:
        log.warning("SSRF: DNS resolution failed for %s", hostname)
        return False
    
    return True


def _redact_url(url: str) -> str:
    """Strip query strings and auth from URL for safe logging."""
    try:
        p = urllib.parse.urlparse(url)
        return f"{p.scheme}://{p.hostname}{p.path}"
    except Exception:
        return "[INVALID_URL]"


# =============================================================================
# SAFE JSON / HTML / XML FETCHING
# =============================================================================

def safe_fetch_bytes(
    url: str,
    headers: Optional[dict] = None,
    timeout: int = 15,
    max_bytes: int = MAX_RESPONSE_BYTES,
    extra_allowed_hosts: Optional[set] = None,
) -> bytes:
    """
    Fetch URL with SSRF protection, size cap, and timeout.
    Raises ValueError if URL is invalid or response is too large.
    """
    if not validate_external_url(url, extra_allowed_hosts):
        raise ValueError(f"URL rejected by SSRF policy")
    
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        # Content-Length early check
        content_length = resp.headers.get("Content-Length")
        if content_length:
            try:
                if int(content_length) > max_bytes:
                    raise ValueError(
                        f"Response too large: {content_length} > {max_bytes}"
                    )
            except ValueError:
                pass  # Unparseable Content-Length, continue with read cap
        
        # Read with hard cap. Read one extra byte to detect overflow.
        raw = resp.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise ValueError(f"Response exceeded {max_bytes} bytes")
        return raw


def safe_fetch_json(
    url: str,
    headers: Optional[dict] = None,
    timeout: int = 15,
    max_bytes: int = MAX_RESPONSE_BYTES,
    extra_allowed_hosts: Optional[set] = None,
) -> Any:
    """Fetch JSON with all safety checks. Returns parsed JSON."""
    raw = safe_fetch_bytes(url, headers, timeout, max_bytes, extra_allowed_hosts)
    # Reject if it looks like HTML (error page)
    stripped = raw.lstrip()
    if stripped.startswith(b"<"):
        raise ValueError("Response is HTML, not JSON")
    return json.loads(raw.decode("utf-8"))


# XXE protection is a hard requirement. Import at module load time so a
# missing dependency fails deployment immediately rather than silently
# degrading security at runtime.
try:
    from defusedxml import ElementTree as _DefusedET
except ImportError as _e:
    raise ImportError(
        "defusedxml is required for XXE-safe XML parsing. "
        "Add 'defusedxml==0.7.1' to requirements.txt and reinstall. "
        "This is a hard requirement — DTVSS will not start without it."
    ) from _e


def safe_parse_xml(raw: bytes):
    """
    Parse XML with XXE protection via defusedxml.
    Blocks external entities, DTDs, and entity expansion (billion-laughs).
    """
    return _DefusedET.fromstring(raw)


# =============================================================================
# INPUT VALIDATION
# =============================================================================

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,10}$")

def validate_cve_id(cve_id: str) -> Optional[str]:
    """
    Normalize and validate a CVE ID.
    Returns canonical form or None if invalid.
    """
    if not cve_id or not isinstance(cve_id, str):
        return None
    if len(cve_id) > MAX_CVE_ID_LENGTH:
        return None
    normalized = cve_id.strip().upper()
    if not normalized.startswith("CVE-"):
        normalized = "CVE-" + normalized
    if not CVE_ID_RE.match(normalized):
        return None
    return normalized


def validate_query(query: str) -> Optional[str]:
    """
    Validate and sanitize a search query.
    Returns cleaned query or None if invalid.
    """
    if not query or not isinstance(query, str):
        return None
    # Length cap
    query = query.strip()[:MAX_QUERY_LENGTH]
    if not query:
        return None
    # No control chars, no null bytes
    if "\x00" in query or not query.isprintable():
        return None
    return query


def validate_float_param(
    value: Any,
    name: str,
    min_val: float,
    max_val: float,
) -> float:
    """
    Validate a float parameter. Raises ValueError with user-safe message.
    Rejects NaN and infinity.
    """
    try:
        f = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a number")
    
    if math.isnan(f) or math.isinf(f):
        raise ValueError(f"{name} must be a finite number")
    
    if not (min_val <= f <= max_val):
        raise ValueError(f"{name} must be between {min_val} and {max_val}")
    
    return f


def validate_int_param(
    value: Any,
    name: str,
    min_val: int,
    max_val: int,
) -> int:
    """Validate an integer parameter with bounds."""
    try:
        i = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be an integer")
    if not (min_val <= i <= max_val):
        raise ValueError(f"{name} must be between {min_val} and {max_val}")
    return i


# =============================================================================
# ERROR SANITIZATION
# =============================================================================

_URL_RE = re.compile(r'https?://[^\s\'"<>]+')
_KEY_RE = re.compile(r'\b[a-zA-Z0-9]{32,}\b')
_PATH_RE = re.compile(r'(?:/[\w\-.]+){2,}')
_HOME_RE = re.compile(r'/home/\w+|/root|/Users/\w+|C:\\Users\\\w+')


def sanitize_error(exc: Exception, max_len: int = 200) -> str:
    """
    Strip sensitive data from exception messages before returning to client.
    
    Redacts:
      - URLs (may contain API keys or internal hosts)
      - Long hex/base64 strings (likely keys/tokens)
      - File paths (reveal deployment layout)
      - Home directories
    """
    msg = str(exc)
    msg = _HOME_RE.sub('[HOME]', msg)
    msg = _URL_RE.sub('[URL]', msg)
    msg = _KEY_RE.sub('[KEY]', msg)
    msg = _PATH_RE.sub('[PATH]', msg)
    return msg[:max_len]


# =============================================================================
# ATOMIC FILE WRITES
# =============================================================================

def atomic_write_json(path: str, data: Any, indent: int = 2) -> None:
    """
    Write JSON atomically. Crash-safe: either the full new file is written
    or the old file remains untouched.
    
    On POSIX, os.replace() is atomic within a single filesystem.
    """
    dirname = os.path.dirname(path) or "."
    os.makedirs(dirname, exist_ok=True)
    
    # Write to temp file in same directory (must be same FS for atomic rename)
    fd, tmp_path = tempfile.mkstemp(
        prefix=".",
        suffix=".tmp",
        dir=dirname,
    )
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=indent, default=str)
            f.flush()
            os.fsync(f.fileno())
        
        # Keep a backup of the previous version
        if os.path.exists(path):
            try:
                os.replace(path, path + ".bak")
            except OSError:
                pass  # bak failure shouldn't prevent the update
        
        os.replace(tmp_path, path)  # atomic on POSIX
    except Exception:
        # Clean up temp file on any failure
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# =============================================================================
# FLASK INTEGRATION
# =============================================================================

def apply_hardening(app, cors_origins: Optional[list[str]] = None) -> None:
    """
    Apply all Flask-level hardening to the app:
      - ProxyFix for accurate client IPs behind Railway/Heroku/etc
      - Security headers on every response
      - CORS with allowlist
      - Request ID correlation
      - Global error handler with sanitization
    """
    from flask import g, request, jsonify
    from werkzeug.middleware.proxy_fix import ProxyFix
    from werkzeug.exceptions import HTTPException
    
    # ProxyFix: trust exactly one hop of X-Forwarded-* headers
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=1,
        x_proto=1,
        x_host=1,
        x_port=0,
        x_prefix=0,
    )
    
    # CORS with allowlist
    try:
        from flask_cors import CORS
        env_origins = os.environ.get("DTVSS_CORS_ORIGINS", "").strip()
        if env_origins:
            origins = [o.strip() for o in env_origins.split(",") if o.strip()]
        else:
            origins = cors_origins or DEFAULT_CORS_ORIGINS
        
        CORS(
            app,
            resources={
                r"/api/*": {
                    "origins": origins,
                    "methods": ["GET", "POST", "OPTIONS"],
                    "allow_headers": ["Content-Type", "X-Request-ID"],
                    "expose_headers": ["X-Request-ID", "X-RateLimit-Remaining"],
                    "supports_credentials": False,
                    "max_age": 3600,
                }
            },
        )
        log.info("CORS configured for origins: %s", origins)
    except ImportError:
        log.warning("flask-cors not installed; CORS not configured")
    
    # Request ID
    @app.before_request
    def _assign_request_id():
        g.request_id = (
            request.headers.get("X-Request-ID")
            or uuid.uuid4().hex
        )
    
    # Security headers + request ID on every response
    @app.after_request
    def _security_headers(response):
        response.headers["X-Request-ID"] = getattr(g, "request_id", "unknown")
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), "
            "payment=(), usb=(), interest-cohort=()"
        )
        # Only set HSTS over HTTPS
        if request.is_secure or request.headers.get("X-Forwarded-Proto") == "https":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        
        # CSP — relaxed for the HTML pages, strict for JSON
        if response.mimetype == "application/json":
            response.headers["Content-Security-Policy"] = "default-src 'none'"
        else:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "connect-src 'self'; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self'"
            )
        
        return response
    
    # Sanitized global error handler
    @app.errorhandler(Exception)
    def _handle_exception(e):
        if isinstance(e, HTTPException):
            return jsonify({
                "error": e.description,
                "type": e.__class__.__name__,
                "request_id": getattr(g, "request_id", None),
            }), e.code
        
        error_id = uuid.uuid4().hex[:16]  # 64 bits, lower collision risk
        log.exception("Unhandled exception [%s] for %s %s",
                      error_id, request.method, request.path)
        
        return jsonify({
            "error": "Internal server error",
            "error_id": error_id,
            "request_id": getattr(g, "request_id", None),
        }), 500


def get_real_client_ip():
    """
    Return the real client IP for rate limiting.
    Only safe to call after ProxyFix middleware is installed.
    """
    from flask import request
    
    # ProxyFix updates request.remote_addr to the client IP
    ip = request.remote_addr or ""
    
    # Validate it's a real IP
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        # Fallback to a hash-based key so requests without valid IP
        # still get bucketed, just into one shared bucket
        return "invalid-ip"


# =============================================================================
# PAYLOAD SIZE GUARD
# =============================================================================

def require_max_body_size(max_bytes: int):
    """
    Decorator to reject requests with body larger than max_bytes.
    Use on POST endpoints to prevent memory exhaustion.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            from flask import request, jsonify
            cl = request.content_length
            if cl is not None and cl > max_bytes:
                return jsonify({
                    "error": f"Payload too large (max {max_bytes} bytes)",
                }), 413
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# =============================================================================
# KEV CATALOG VALIDATION
# =============================================================================

_CVE_ID_STRICT = re.compile(r"^CVE-\d{4}-\d+$")

def validate_kev_catalog(catalog: dict, min_entries: int = 500) -> Optional[dict]:
    """
    Validate the structure of the CISA KEV catalog before trusting it.
    Returns indexed dict on success, None on failure.
    """
    if not isinstance(catalog, dict):
        log.error("KEV catalog is not a dict")
        return None
    
    vulns = catalog.get("vulnerabilities")
    if not isinstance(vulns, list):
        log.error("KEV vulnerabilities field is not a list")
        return None
    
    indexed = {}
    skipped = 0
    for v in vulns:
        if not isinstance(v, dict):
            skipped += 1
            continue
        cve_id = v.get("cveID", "")
        if not _CVE_ID_STRICT.match(cve_id):
            skipped += 1
            continue
        required = {"dateAdded", "vendorProject", "product", "vulnerabilityName"}
        if not required.issubset(v.keys()):
            skipped += 1
            continue
        indexed[cve_id] = v
    
    # Sanity: KEV has ~1100 entries as of 2026. Sudden drop is suspicious.
    if len(indexed) < min_entries:
        log.error(
            "KEV catalog suspiciously small: %d valid, %d skipped",
            len(indexed), skipped,
        )
        return None
    
    if skipped > 0:
        log.warning("KEV: skipped %d malformed entries", skipped)
    
    return indexed
