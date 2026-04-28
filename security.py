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
import ssl
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import urllib3
import urllib3.connection
import urllib3.exceptions
import uuid
from typing import Any, Optional
from functools import wraps

def _sanitize_for_log(value: Any) -> str:
    """
    Sanitize untrusted values before logging to prevent log injection.
    Removes CR/LF and other control characters.
    """
    s = str(value)
    return "".join(ch for ch in s if ch >= " " and ch != "\x7f")


def _log_safe_value(value: Any) -> str:
    """
    Return a log-safe representation of untrusted input.

    1) Remove control characters that can alter log structure.
    2) Encode remaining bytes as unicode escapes so unusual characters are
       represented safely and unambiguously in log output.
    """
    cleaned = _sanitize_for_log(value)
    return cleaned.encode("unicode_escape", errors="backslashreplace").decode("ascii")


# =============================================================================
# CONSTANTS
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
#
# Pentest finding (MEDIUM): the default allowlist previously used dtvss.app,
# but the production deployment is at dtvss.io (matches sitemap.xml,
# SECURITY.md, and security.txt Canonical). On any deploy that doesn't set
# DTVSS_CORS_ORIGINS, browser API calls from the real frontend would have
# been blocked by CORS. Defaults now match the canonical domain.
DEFAULT_CORS_ORIGINS = [
    "https://dtvss.io",
    "https://www.dtvss.io",
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

def validate_and_resolve_external_url(
    url: str, extra_allowed_hosts: Optional[set] = None
) -> Optional[str]:
    """
    Return a verified public IP if the URL is safe to fetch server-side,
    or None if rejected.

    Blocks:
      - Non-HTTPS schemes (file://, gopher://, ftp://)
      - Hosts not in allowlist
      - Private/loopback/link-local/reserved IPs (after DNS resolution)
      - Cloud metadata endpoints
      - Path traversal segments, control bytes, CRLF, backslash, non-ASCII

    The returned IP is the address the caller MUST connect to (DNS pinning)
    to close the TOCTOU window: a second DNS lookup at connection time could
    otherwise resolve to a different (internal) address. See safe_fetch_bytes
    for the pinning implementation. Closes CodeQL alert #20 (py/partial-ssrf).
    """
    if not url or not isinstance(url, str):
        return None

    # Defence in depth: reject control characters, NUL bytes, CRLF, and
    # backslashes anywhere in the original URL string BEFORE urlparse has
    # a chance to silently strip or reassign them. urlparse will, for
    # example, swallow CRLF in the path silently, and put a backslash in
    # the hostname rather than rejecting it. Catching these at the raw
    # string level is more reliable.
    for ch in url:
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            log.warning("SSRF: rejected URL with control char")
            return None
    if "\\" in url:
        log.warning("SSRF: rejected URL with backslash")
        return None

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return None

    # Scheme check
    if parsed.scheme not in ALLOWED_SCHEMES:
        log.warning("SSRF: rejected scheme %s for %s", parsed.scheme, _redact_url(url))
        return None

    # Path-traversal check: ".." as a discrete path segment is never
    # legitimate in our API URLs and is the canonical path-injection vector.
    # Use parsed.path so that ".." inside a longer name (e.g. "..foo") is
    # not falsely flagged.
    if ".." in parsed.path.split("/"):
        log.warning("SSRF: rejected URL with path traversal segment")
        return None

    # ASCII-only check: any non-ASCII in the URL must be percent-encoded
    # before reaching us. Raw Unicode in the path/query is suspicious and
    # not used by any of our legitimate upstreams.
    try:
        target = (parsed.path or "/")
        if parsed.query:
            target = f"{target}?{parsed.query}"
        target.encode("ascii")
    except UnicodeEncodeError:
        log.warning("SSRF: rejected URL with non-ASCII in path/query")
        return None

    # Host check
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return None
    safe_hostname = _log_safe_value(hostname)

    # Block internal/private DNS suffixes before DNS lookup.
    # Catches Railway private networking, mDNS, and corporate intranets.
    for suffix in BLOCKED_DOMAIN_SUFFIXES:
        if hostname.endswith(suffix):
            log.warning("SSRF: rejected internal suffix %s", safe_hostname)
            return None

    allowed = set(ALLOWED_EXTERNAL_HOSTS)
    if extra_allowed_hosts:
        allowed |= extra_allowed_hosts

    if hostname not in allowed:
        log.warning("SSRF: rejected host not in allowlist")
        return None

    # Resolve to IP and verify it's public.
    # We require ALL resolved addresses to be public (rebinding may rotate
    # multiple records), then return the first for the caller to pin to.
    try:
        addr_info = socket.getaddrinfo(hostname, None, family=socket.AF_UNSPEC)
        first_public_ip: Optional[str] = None
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
                log.warning("SSRF: %s resolves to non-public %s", safe_hostname, ip_str)
                return None
            if first_public_ip is None:
                first_public_ip = ip_str
        if first_public_ip is None:
            log.warning("SSRF: no usable IPs for %s", safe_hostname)
            return None
        return first_public_ip
    except socket.gaierror:
        log.warning("SSRF: DNS resolution failed for %s", safe_hostname)
        return None


def validate_external_url(url: str, extra_allowed_hosts: Optional[set] = None) -> bool:
    """
    Backward-compatible wrapper: True if the URL is safe to fetch.

    Existing callers that just want a yes/no answer keep working. New code
    that performs network I/O after this check should call
    validate_and_resolve_external_url() and connect to the returned IP
    (DNS pinning). Otherwise an attacker controlling DNS for an allowlisted
    hostname can flip the answer between this validation and the connection.
    """
    return validate_and_resolve_external_url(url, extra_allowed_hosts) is not None


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
    Raises urllib.error.URLError on network failure (compatibility with
    callers that catch urlopen-shaped exceptions).

    DNS pinning (closes CodeQL alert #20, py/partial-ssrf): the validator
    returns the resolved public IP, and we connect directly to that IP
    rather than letting the HTTP client perform a second DNS resolution.
    This closes the TOCTOU window where an attacker controlling DNS for an
    allowlisted hostname could flip the answer between validation and
    connection. SNI and certificate validation still use the original
    hostname so TLS works correctly.

    Caller contract - URL construction safety:
        Callers MUST construct the URL such that any user-controlled
        substring is properly encoded for the position it occupies:

          OK:  Query parameter values - use urllib.parse.urlencode(...)
          OK:  Path segments - use urllib.parse.quote(value, safe='')
          BAD: NEVER interpolate raw user input directly into a path with
               f-string/format unless the value passes a strict regex first
               (see validate_cve_id for an example of acceptable practice).

        safe_fetch_bytes does defence-in-depth checks (rejects path
        traversal, control bytes, CRLF, backslash, non-ASCII) but those
        are a safety net, not a substitute for correct URL construction
        at the call site. The host allowlist is a hard boundary; the
        path safety check is conservative; if a caller bypasses the
        validator entirely (e.g. by calling urllib.request directly)
        none of these protections apply.
    """
    pinned_ip = validate_and_resolve_external_url(url, extra_allowed_hosts)
    if pinned_ip is None:
        raise ValueError("URL rejected by SSRF policy")

    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or 443  # HTTPS only per ALLOWED_SCHEMES

    # Build the request path including query string
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    # Use urllib3's HTTPSConnection with explicit server_hostname and
    # assert_hostname so the connection goes to the pinned IP but TLS
    # SNI and cert validation use the original hostname. Both kwargs
    # are documented public API.
    conn = urllib3.connection.HTTPSConnection(
        host=pinned_ip,
        port=port,
        timeout=timeout,
        server_hostname=hostname,
        assert_hostname=hostname,
    )

    try:
        # Build headers; ensure Host is the original hostname (some servers
        # route on Host even on a single IP). Do not let the caller override
        # Host, since that would defeat the SNI/cert match.
        request_headers = dict(headers or {})
        request_headers["Host"] = hostname
        if "User-Agent" not in request_headers:
            request_headers["User-Agent"] = "DTVSS/3.0"

        try:
            conn.request(
                "GET", path,
                headers=request_headers,
                preload_content=False,  # stream so we can enforce max_bytes early
            )
            resp = conn.getresponse()
        except urllib3.exceptions.HTTPError as e:
            # Re-raise as urllib.error.URLError so existing call sites that
            # catch urlopen-shaped exceptions keep working unchanged.
            raise urllib.error.URLError(str(e)) from e
        except (OSError, ssl.SSLError) as e:
            # OSError covers socket-level failures; SSLError covers TLS
            # handshake failures (including assert_hostname mismatches -
            # the pinning safety net). Both should look like network
            # errors to callers.
            raise urllib.error.URLError(str(e)) from e

        # Content-Length early check.
        # Bug fix history: previously the over-cap raise lived inside the
        # same try as int(content_length), so an except ValueError swallowed
        # the size-cap rejection. We now narrow the try to the int() only
        # and check the bound outside.
        #
        # Caveat: chunked Transfer-Encoding responses don't send
        # Content-Length, so this fast-path is bypassed. The hard read-cap
        # below is the actual security boundary; the Content-Length check
        # is a bandwidth optimisation when the server is honest about size.
        content_length = resp.getheader("Content-Length")
        if content_length:
            try:
                cl_int = int(content_length)
            except ValueError:
                cl_int = None
            if cl_int is not None and cl_int > max_bytes:
                raise ValueError(
                    f"Response too large: {content_length} > {max_bytes}"
                )

        # Read with hard cap. AUTHORITATIVE size enforcement - works for
        # both Content-Length and chunked Transfer-Encoding responses.
        #
        # urllib3's HTTPResponse exposes the body via the .data attribute,
        # which is preloaded. To enforce a streaming cap before the entire
        # body lands in memory, iterate via .stream() and accumulate up to
        # max_bytes + 1 bytes.
        chunks: list[bytes] = []
        total = 0
        for chunk in resp.stream(8192, decode_content=False):
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"Response exceeded {max_bytes} bytes")
        return b"".join(chunks)
    finally:
        conn.close()


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
        "This is a hard requirement - DTVSS will not start without it."
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

# Search-query character allowlist (used by validate_query). See the
# function docstring for the rationale on each character class.
_QUERY_ALLOWED_RE = re.compile(r"^[A-Za-z0-9 ._,\-():]+$")

def validate_cve_id(cve_id: str) -> Optional[str]:
    """
    Normalize and validate a CVE ID.
    Returns canonical form or None if invalid.

    Order of operations matters: strip whitespace BEFORE the length check so
    pasted CVE IDs with surrounding whitespace are accepted, but pathological
    inputs (e.g. 30 KB of leading whitespace) are rejected by the pre-strip
    bound below.
    """
    if not cve_id or not isinstance(cve_id, str):
        return None
    # Pre-strip bound: defends against pathological whitespace-padded inputs.
    # Use a generous multiplier so a few extra spaces never reach strip().
    if len(cve_id) > MAX_CVE_ID_LENGTH * 4:
        return None
    normalized = cve_id.strip().upper()
    if len(normalized) > MAX_CVE_ID_LENGTH:
        return None
    if not normalized.startswith("CVE-"):
        normalized = "CVE-" + normalized
    if not CVE_ID_RE.match(normalized):
        return None
    return normalized


def validate_query(query: str) -> Optional[str]:
    r"""
    Validate and sanitize a search query.
    Returns cleaned query or None if invalid.

    Tight character allowlist (closes CodeQL alert #42 / py/partial-ssrf
    at the source): the validated query becomes part of an outbound URL
    sent to the NVD keyword API. Constraining input to letters, digits,
    spaces, and a small set of safe punctuation here means no character
    that can affect URL parsing or HTTP request semantics ever reaches
    the URL-construction layer.

    Allowed characters:
      A-Z a-z 0-9     letters and digits (medical device / vendor names)
      space            multi-word queries
      . , - _          common punctuation in product/version strings
      ( ) :            version numbers, model designators (e.g. "v1.0 (rev 2)")

    Rejected (would otherwise affect URL/HTTP semantics):
      & = ? #         query/fragment separators
      / \              path injection
      %                percent-encoding manipulation
      < > " '          HTML/XSS in any reflected context
      { } [ ] | ^ ` ~ $ @ ; *  rarely needed; can break parsers
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
    # Strict character allowlist
    if not _QUERY_ALLOWED_RE.match(query):
        log.warning("validate_query: rejected query containing disallowed characters")
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
# Pentest finding (LOW): the previous _HOME_RE missed container paths
# (/mnt/..., /app/..., /workspace/...) and Railway/Docker conventions
# (/data/..., /var/lib/...). _PATH_RE catches them generically as [PATH],
# but listing the well-known sensitive prefixes here means they get tagged
# as [HOME] (more accurate signal in logs) and ensures we don't accidentally
# leak a deployment layout if _PATH_RE is ever loosened.
_HOME_RE = re.compile(
    r'/home/\w+'
    r'|/root(?:/|\b)'
    r'|/Users/\w+'
    r'|C:\\Users\\\w+'
    r'|/mnt/[\w\-]+'           # container mounts (e.g. /mnt/user-data)
    r'|/app(?:/|\b)'           # Heroku/Docker app dir
    r'|/workspace(?:/|\b)'     # GitHub Codespaces / Cloud Shell
    r'|/data(?:/|\b)'          # Railway persistent volume convention
    r'|/var/lib/\w+'           # systemd / packaged service data dirs
)


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
    
    # ProxyFix: trust N hops of X-Forwarded-* headers.
    #
    # Default is 1 hop (client -> Railway edge -> gunicorn), which matches
    # Railway's documented edge topology at time of writing. If Railway
    # changes to a multi-hop architecture (e.g. CDN in front of edge, or
    # separate LB + proxy), set DTVSS_PROXY_HOPS=N on the deploy.
    #
    # UNDERCOUNTING HOPS: trusts attacker-forged XFF values (security issue).
    # OVERCOUNTING HOPS: collapses rate-limit buckets (availability issue).
    # Getting this right requires empirical verification against the actual
    # edge - see the F-03 verification procedure in the audit report.
    _hops = int(os.environ.get("DTVSS_PROXY_HOPS", "1"))
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=_hops,
        x_proto=_hops,
        x_host=_hops,
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
    
    # Request ID + per-request CSP nonce
    @app.before_request
    def _assign_request_id():
        g.request_id = (
            request.headers.get("X-Request-ID")
            or uuid.uuid4().hex
        )
        # Per-request nonce for CSP. Templates can opt in by emitting
        # <script nonce="{{ g.csp_nonce }}">...</script> on inline scripts.
        # Once all inline scripts/styles use the nonce, set
        # DTVSS_CSP_STRICT=1 to drop 'unsafe-inline' from the CSP entirely.
        g.csp_nonce = uuid.uuid4().hex

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

        # CSP - strict for JSON; nonce-based for HTML.
        #
        # Strict CSP is default-on. DTVSS_CSP_STRICT=0 opts out (permissive
        # with 'unsafe-inline' as a fallback for <script>/<style> blocks)
        # but this should only be used as a temporary unblocker while
        # migrating code - please open a security advisory rather than
        # disabling permanently.
        #
        # In strict mode (default), 'unsafe-inline' is absent from
        # script-src and style-src; nonce-based authorisation is the real
        # control. Inline style="..." attributes are permitted via
        # style-src-attr by explicit design (see rationale on lines
        # ~560-572 below).
        if response.mimetype == "application/json":
            response.headers["Content-Security-Policy"] = "default-src 'none'"
        else:
            nonce = getattr(g, "csp_nonce", "")
            # Strict CSP is now the default (Fix #11). Every inline event
            # handler in the HTML was migrated to addEventListener / event
            # delegation, and Fix #8 wired up nonce injection on the static-
            # file path so every <script>/<style> block carries the per-
            # request nonce.
            #
            # If a future contributor adds an inline onclick=/onmouseover=/
            # etc. handler, strict CSP will break it visibly in the browser
            # console - that's the desired feedback loop. Use the opt-out
            # below ONLY as a temporary unblocker while migrating, never
            # as a permanent setting.
            #
            # Opt-out: DTVSS_CSP_STRICT=0  (drops back to permissive
            # 'unsafe-inline' behaviour). The Fix #11 inline-handler
            # migration removed the legitimate need for this; please open a
            # security advisory rather than disabling permanently.
            strict = os.environ.get("DTVSS_CSP_STRICT", "1") != "0"
            inline = "" if strict else " 'unsafe-inline'"
            # style-src-attr governs inline `style="..."` attributes
            # specifically (CSP Level 3). The Fix #11 inline-handler
            # migration converted all event handlers to addEventListener,
            # but the project still has hundreds of inline style attributes
            # in its templates (e.g. dynamic per-tier colors). Migrating
            # every one of them into a stylesheet would be a massive
            # refactor with no real security benefit - inline style
            # attributes can't load resources, can't execute expressions,
            # and can't exfiltrate data. We allow them explicitly here so
            # `style-src` can still be strict for <style> blocks (which
            # ARE a real injection vector). Older browsers that don't
            # understand style-src-attr fall back to style-src, which
            # already includes 'unsafe-inline' when DTVSS_CSP_STRICT=0.
            style_attr = " 'unsafe-inline'" if strict else ""
            response.headers["Content-Security-Policy"] = (
                f"default-src 'self'; "
                f"script-src 'self' 'nonce-{nonce}'{inline} "
                f"https://cdnjs.cloudflare.com; "
                f"style-src 'self' 'nonce-{nonce}'{inline} "
                f"https://fonts.googleapis.com; "
                f"style-src-attr{style_attr}; "
                f"font-src 'self' https://fonts.gstatic.com; "
                f"img-src 'self' data:; "
                f"connect-src 'self'; "
                f"frame-ancestors 'none'; "
                f"base-uri 'self'; "
                f"form-action 'self'"
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
        # still get bucketed, just into one shared bucket.
        #
        # Logged at WARNING so operators can detect when Railway's edge
        # (or any upstream proxy) emits a malformed or missing XFF value.
        # Without this telemetry, a misconfigured edge could silently
        # collapse every request into one shared rate-limit bucket and
        # we'd have no signal until rate limits stopped working.
        log.warning(
            "get_real_client_ip fell back to 'invalid-ip'; original remote_addr=%r",
            request.remote_addr,
        )
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
