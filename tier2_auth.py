"""
DTVSS Tier 2 — RSS authentication middleware
============================================

Stage 2 of the Tier 2 implementation plan: a Flask decorator that turns any
route into a Tier-2-only endpoint, plus the audit log and Sentry failure
reporting hooks that go with it.

Design summary (tier2-design.md §5.4, tier2-implementation-plan.md Stage 2):

  - `@require_tier2` extracts an opaque token from the URL path, validates
    it through `tier2_customers.validate_token`, and either sets
    `g.customer` and runs the wrapped view OR returns 404 (never 401:
    leaking "the URL exists but you're not allowed" is itself a signal).

  - Successful validations append one JSON line to the audit log at
    `audit_log_path()` (see path resolution below). One line per request.

  - Failed validations are reported to Sentry as a `warning` event with
    enough structure to investigate (route, source IP, validation outcome,
    truncated token prefix) but never the full token plaintext.

  - Per-token rate limiting is set at 60 requests per hour, the Stage 2
    default from the design doc. Per-customer overrides are deferred to
    Stage 5.

  - The decorator is intentionally narrow: it only knows about tokens.
    Everything downstream (RSS feed generation, manufacturer filtering,
    patent-claim toggles) lives in later stages and reads `g.customer`.

Security properties (per design §5.2 Assertions 5–10):

  - Valid token → 200 with `g.customer = record` available to view
  - Expired customer → 404, no leak that the URL was valid pre-expiry
  - Revoked customer → 404, with a Sentry warning fired
  - Malformed token (wrong length, bad charset, percent-encoded payload,
    null byte) → 404, refused without a customers.json lookup
  - Missing token → 404
  - Token replay (RSS readers poll repeatedly) → permitted up to the
    per-token rate limit (60/hour by default)

Path-handling threat model (Stage 2 risk: auth bypass via URL parsing):

  - The token segment is captured by Flask's URL converter, not parsed
    from the raw URL. That eliminates ../ traversal, double-slash
    collapse, and most percent-encoding tricks at the framework layer.
  - Tokens are validated against a strict regex (43 char base64url, the
    output of `secrets.token_urlsafe(32)`) BEFORE any DB lookup. Anything
    that doesn't match the regex 404s immediately, so no DB I/O happens
    on a bad token.
  - hmac.compare_digest on the hash comparison (already implemented in
    tier2_customers.validate_token) closes the timing-leak side channel.

ADR: 002-stage2-rss-auth-middleware.md
Copyright 2026 Andrew Broglio. Licensed under BSL 1.1.
"""
from __future__ import annotations

import json
import logging
import os
import re
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path
from typing import Any, Callable

from flask import abort, g, jsonify, request

from tier2_customers import validate_token

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Token format
# ---------------------------------------------------------------------------
# tier2_customers.generate_token() returns secrets.token_urlsafe(32), which
# produces a 43-character base64url string (32 bytes → ceil(32*4/3) = 43 chars,
# no padding because 32 is not a multiple of 3 in a way that needs it for
# urlsafe). Anything that doesn't match this regex is rejected without a DB
# hit, which protects against enumeration attacks and percent-encoding
# tricks (the regex doesn't include %).
#
# Why 43 specifically: token_urlsafe(n) returns ceil(n * 4 / 3) chars of
# unpadded base64url. For n=32: 32*4/3 = 42.67 → 43.
TOKEN_REGEX = re.compile(r"^[A-Za-z0-9_-]{43}$")


def is_well_formed_token(value: str | None) -> bool:
    """Cheap pre-flight check; returns True iff value could possibly be a
    valid Tier 2 token. Does NOT confirm the token exists or is active —
    that's validate_token's job. The point is to refuse obviously-bogus
    inputs (wrong length, illegal characters, null bytes) without touching
    the customer database at all.
    """
    if not value or not isinstance(value, str):
        return False
    # Null byte check is redundant given the regex's character class, but
    # included explicitly so the intent is visible in code review.
    if "\x00" in value:
        return False
    return bool(TOKEN_REGEX.match(value))


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------
# Successful validations append one JSON line per request to access.log.
# Format choice rationale (vs plain text columns):
#   - Greppable by jq for ad-hoc queries
#   - Survives field additions in later stages (Stage 5 adds enabled_claims,
#     Stage 6 adds update_interval) without breaking parsers
#   - Trivial to ship to a SIEM later if a customer asks
#
# Path resolution mirrors customers_path(): env var override + sensible
# defaults that "just work" in dev and require explicit prod config.
DEFAULT_AUDIT_PATH_DEV = "private/audit/access.log"
DEFAULT_AUDIT_PATH_PROD = "/data/audit/access.log"


def audit_log_path() -> Path:
    """Resolve the audit log path from environment.

    Reads DTVSS_AUDIT_LOG_PATH if set. Otherwise:
      - In production (RAILWAY_ENVIRONMENT set): /data/audit/access.log
      - In development: private/audit/access.log relative to cwd

    The production default lives under the same /data volume as
    customers.json, so audit retention follows the same backup strategy
    (Railway-native nightly snapshots, see tier2-design §1.6).
    """
    override = os.environ.get("DTVSS_AUDIT_LOG_PATH")
    if override:
        return Path(override)
    if os.environ.get("RAILWAY_ENVIRONMENT"):
        return Path(DEFAULT_AUDIT_PATH_PROD)
    return Path(DEFAULT_AUDIT_PATH_DEV)


def _write_audit_line(entry: dict[str, Any]) -> None:
    """Append a JSON line to the audit log. Best-effort: never raises.

    If the audit log can't be written (disk full, permission error, missing
    directory), the request still succeeds — we log a warning to stderr so
    operators see something is broken, but we don't fail customer requests
    because of an internal logging issue. This is the standard "logging is
    a non-functional concern" pattern; audit completeness is monitored
    separately (Stage 4 onboarding doc covers the runbook).
    """
    path = audit_log_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n")
    except OSError as e:
        # Don't let a failed audit write break the request. Log and move on.
        # In production, Sentry will pick up the warning via its logging
        # integration if SENTRY_DSN is set.
        log.warning("Failed to write audit log entry: %s", e)


def _utcnow_iso() -> str:
    """ISO 8601 UTC timestamp, second precision, explicit Z suffix.
    Matches tier2_customers._utcnow_iso() format for consistency.
    """
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _client_ip() -> str:
    """Best-effort client IP extraction. Uses the ProxyFix-corrected
    request.remote_addr because app.py installs ProxyFix at the WSGI layer
    (see security.py). Returns "unknown" if extraction fails so audit log
    entries never have a null IP field.

    Defence-in-depth: strip ASCII control characters before returning,
    so that even if ProxyFix is misconfigured or an attacker controls the
    XFF chain in a future deployment, they cannot forge multiline log
    entries by stuffing CR/LF/NUL into the IP field. Closes CodeQL
    py/log-injection.
    """
    try:
        raw_ip = request.remote_addr or "unknown"
        # Remove ASCII control characters (0x00-0x1f, 0x7f). These should
        # never appear in a valid IP literal; if they do, the input is
        # adversarial.
        safe_ip = re.sub(r"[\x00-\x1f\x7f]+", " ", raw_ip).strip()
        return safe_ip or "unknown"
    except Exception:  # noqa: BLE001 - defence in depth, never break the request
        return "unknown"


def _route_pattern() -> str:
    """Return the URL rule (with placeholders) instead of request.path.

    request.path returns the concrete URL e.g. "/rss/feed/Ckis8...XYZ.xml"
    which embeds the token plaintext. Logging that would defeat the
    "token plaintext is never persisted at rest" property (design §2.3).

    request.url_rule.rule returns the registered pattern e.g.
    "/rss/feed/<token>.xml", which identifies the route without revealing
    the token. This is what we want in audit log and Sentry contexts.

    Falls back to a safe placeholder if url_rule isn't set (would only
    happen for unmatched routes; the decorator wouldn't be running in
    that case, but defence in depth).
    """
    try:
        rule = getattr(request, "url_rule", None)
        if rule is not None and getattr(rule, "rule", None):
            return rule.rule
    except Exception:  # noqa: BLE001
        pass
    return "<unknown_route>"


def _token_prefix(token: str | None) -> str:
    """Return the first 8 characters of a token for audit log diagnostics.

    Eight characters of urlsafe-base64 is 48 bits, which is too short to
    brute-force the rest from a hash but long enough to distinguish
    different rejected attempts when investigating an incident. Full
    plaintext tokens are NEVER written to the audit log or Sentry, by
    design (tier2-design §2.3).
    """
    if not token:
        return ""
    return token[:8]


# ---------------------------------------------------------------------------
# Sentry failure reporting
# ---------------------------------------------------------------------------
# Failures (every 404 from this decorator) go to Sentry as warning-level
# events. The split between "successes → file" and "failures → Sentry"
# matches design assertions A16 / A17 and is documented in ADR-002.
#
# Why warning and not info or error:
#   - info: Sentry's default sampling drops info-level events; we'd lose
#     visibility of failed validations.
#   - error: implies "something is broken on our side". A bad token isn't
#     our error; it's an attempted-misuse signal.
#   - warning: surfaces in the Sentry dashboard, alertable if it spikes,
#     doesn't trigger PagerDuty.
def _report_failure(
    reason: str,
    token: str | None,
    *,
    customer_id: str | None = None,
) -> None:
    """Send a failed-validation event to Sentry at warning level.

    Includes:
      - reason ('malformed', 'unknown', 'expired', 'suspended', 'revoked', 'missing')
      - token prefix (8 chars; never the full token)
      - customer_id if the token resolved to a known customer (for revoked
        / suspended / expired cases) — useful for spotting reactivation
        attempts on a known-revoked record
      - request route and client IP
    """
    route = _route_pattern()  # NOT request.path — that would leak the token
    if not os.environ.get("SENTRY_DSN"):
        # Sentry not configured (dev, CI, etc.). Log to stderr instead so
        # the failure is at least visible somewhere.
        log.warning(
            "Tier 2 auth failure: reason=%s route=%s ip=%s token_prefix=%s customer=%s",
            reason,
            route,
            _client_ip(),
            _token_prefix(token),
            customer_id or "",
        )
        return

    # Lazy import: matches the pattern in app.py for caa_report.
    import sentry_sdk

    with sentry_sdk.push_scope() as scope:
        scope.set_tag("tier2.auth_failure", reason)
        scope.set_extra("token_prefix", _token_prefix(token))
        scope.set_extra("route", route)
        scope.set_extra("source_ip", _client_ip())
        if customer_id:
            scope.set_extra("customer_id", customer_id)
        sentry_sdk.capture_message(
            f"Tier 2 auth failure: {reason}",
            level="warning",
        )


# ---------------------------------------------------------------------------
# The decorator
# ---------------------------------------------------------------------------
def require_tier2(view_func: Callable) -> Callable:
    """Flask decorator: gate a view behind a valid Tier 2 token.

    Usage:
        @app.route("/rss/feed/<token>.xml")
        @require_tier2
        def rss_feed():
            customer = g.customer
            return generate_feed(customer)

    The token is taken from the `token` URL kwarg (Flask path converter).
    Routes that need the decorator MUST capture the token segment as
    `<token>`. Using a different name will cause a 404 because no token
    is found.

    Success: sets `g.customer` to the Customer record and calls view_func
    with the original args/kwargs minus the token (which is removed from
    kwargs because views shouldn't need to handle it).

    Failure: returns abort(404) with no body. The Sentry warning carries
    the diagnostic detail.
    """

    @wraps(view_func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        token = kwargs.pop("token", None)

        # 1. Missing token → 404 (no DB hit, no Sentry — this would be
        # noisy on any route misconfiguration)
        if token is None or token == "":
            _report_failure("missing", token)
            abort(404)

        # 2. Malformed token → 404 (no DB hit)
        # This refuses path traversal, percent-encoding payloads, null bytes,
        # oversized inputs, and anything with the wrong length / charset.
        if not is_well_formed_token(token):
            _report_failure("malformed", token)
            abort(404)

        # 3. Look up the customer. validate_token already enforces:
        #    - sha256 of plaintext token equals stored hash (hmac.compare_digest)
        #    - status == "active"
        #    - expires_at not in the past
        # If any of those fail, validate_token returns None and we 404.
        #
        # Pre-initialise to None so static analysers (CodeQL
        # py/uninitialized-local-variable) can prove the post-try
        # `if customer is None` check has a defined operand. The except
        # branch calls abort() which raises, so this never actually reads
        # the None at runtime — but proving that requires whole-program
        # analysis CodeQL won't do.
        customer = None
        try:
            customer = validate_token(token)
        except Exception as e:  # noqa: BLE001
            # validate_token can raise EncryptionKeyError / SchemaError if
            # the customers file is unreadable. Those are operator errors,
            # not customer errors. Surface to Sentry as a real error.
            log.exception("Tier 2 token validation raised: %s", e)
            if os.environ.get("SENTRY_DSN"):
                import sentry_sdk
                sentry_sdk.capture_exception(e)
            abort(404)

        if customer is None:
            # We can't tell from validate_token's None whether the token was
            # unknown, expired, or attached to a non-active customer — by
            # design, the function doesn't differentiate (D11 in ADR-001).
            # For audit purposes that's fine: from a security standpoint
            # all three outcomes are "404, do not pass go".
            _report_failure("rejected", token)
            abort(404)

        # 4. Success path. Stash the customer in flask.g for the view and
        # the rest of the request lifecycle to use.
        g.customer = customer

        # 5. Audit log AFTER setting g.customer so any chained decorators
        # can also see the customer. The audit write happens before the
        # view runs; if the view raises, we still have a record that the
        # access happened.
        _write_audit_line({
            "ts": _utcnow_iso(),
            "customer_id": customer.id,
            "route": _route_pattern(),  # pattern, never the URL with the token
            "method": getattr(request, "method", ""),
            "source_ip": _client_ip(),
            "user_agent": (request.headers.get("User-Agent") or "")[:200],
        })

        return view_func(*args, **kwargs)

    return wrapper


# ---------------------------------------------------------------------------
# Rate limiting key (60 requests/hour per token, design default)
# ---------------------------------------------------------------------------
# Flask-Limiter's per-route limit is set on the route (see app.py for the
# decorator integration). The KEY function below is what determines who
# the rate limit applies to. We key on the customer ID after validation
# rather than the IP, because:
#   - One customer's RSS reader might rotate IPs (mobile, VPN, fleet)
#   - One IP might host many customers (shared corporate egress)
# So customer-ID is the right unit of fairness.
def tier2_rate_limit_key() -> str:
    """Return the rate-limit key for the current request.

    Called by Flask-Limiter. Must work both before and after the
    require_tier2 decorator runs. Before validation we have no customer,
    so we fall back to the token prefix (rate-limits a malformed bombardment
    too, by token, which is what we want).
    """
    customer = getattr(g, "customer", None)
    if customer is not None:
        return f"tier2:{customer.id}"
    # Pre-validation path: limit by token prefix, falling back to IP.
    # view_args is set by Flask's URL routing before any view runs, which
    # includes before the decorator. So we can read the in-flight token here.
    token = (request.view_args or {}).get("token") if request else None
    if token and isinstance(token, str):
        return f"tier2:tok:{_token_prefix(token)}"
    return f"tier2:ip:{_client_ip()}"


# Stage 2 default. Per design: 60 requests/hour. Per-customer overrides
# arrive in Stage 5 (per customer.rate_limit_per_hour field).
TIER2_RATE_LIMIT = "60 per hour"


# ---------------------------------------------------------------------------
# Health-check view: /tier2/ping
# ---------------------------------------------------------------------------
# Registered permanently in app.py as the canonical "is my token still
# good?" endpoint for Tier 2 customers. Returns minimal info — confirming
# that a token works, the rough subscription state, and nothing about
# other customers or the manufacturer index.
def tier2_ping_view() -> Any:
    """View function for GET /tier2/ping/<token>.

    Returns 200 + JSON when the token validates. The require_tier2
    decorator handles all the 404 cases.
    """
    customer = g.customer
    return jsonify({
        "ok": True,
        "customer_id": customer.id,
        "status": customer.status,
        "expires_at": customer.expires_at,
        "manufacturers": customer.manufacturers,
        "tier": "tier2",
    })
