"""
Cloudflare-only origin enforcement.
==================================

Optional middleware that rejects any request whose source IP is not within
Cloudflare's published IP ranges. This closes the "origin bypass" attack
vector: an attacker who fingerprints your Railway URL can otherwise hit it
directly and skip every Cloudflare WAF rule, rate limit, and bot check.

Activation
----------
Set DTVSS_CLOUDFLARE_ONLY=1 in the deploy environment. Default off so:
  - Local development still works (requests come from 127.0.0.1)
  - Existing deploys don't break when this code lands
  - You can roll out by env-var flip rather than code change

When active, every request is checked against Cloudflare's official IP
ranges. Requests outside those ranges return 403 with a minimal body.

Cloudflare publishes their ranges at:
  - https://www.cloudflare.com/ips-v4/   (IPv4)
  - https://www.cloudflare.com/ips-v6/   (IPv6)

The ranges change rarely (a few times per year). We fetch on startup and
again every 24 hours. If the fetch fails on startup, we fall back to a
hardcoded snapshot of the ranges (current as of May 2026) so deploy
succeeds even if Cloudflare's IPs endpoint is briefly unreachable.

Health-check exception
----------------------
Railway's health checker hits /health from inside Railway's network, not
through Cloudflare. We exempt /health from the Cloudflare-only check so
health probes don't fail. This is safe because /health returns no
sensitive data and is the only path most platforms need internal access to.

What this DOES NOT protect against
----------------------------------
- An attacker spoofing the X-Forwarded-For header to look like Cloudflare.
  That's why this check uses request.remote_addr (the actual TCP peer IP)
  and not any forwarded header. ProxyFix transforms remote_addr from the
  XFF chain, so we check the chain's tail (the immediate peer), which on
  Railway is the Railway edge - itself only reachable via Cloudflare if
  you've configured Railway to reject non-Cloudflare traffic.
- Whitelist abuse if someone hosts on Cloudflare and points it at your
  origin. This is mitigated separately by Cloudflare Authenticated Origin
  Pulls (mTLS), which is the proper enterprise solution but is more setup.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import threading
import time
from typing import Iterable, Optional

log = logging.getLogger(__name__)


# Cloudflare's published IP ranges as of May 2026. Used as a fallback if the
# live fetch from www.cloudflare.com fails. Update annually or whenever
# Cloudflare announces a change at https://www.cloudflare.com/ips/
_FALLBACK_CF_RANGES_V4 = (
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
)
_FALLBACK_CF_RANGES_V6 = (
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
)

# Refresh published ranges every 24 hours
_REFRESH_INTERVAL_SECONDS = 24 * 60 * 60

# Network paths exempt from the Cloudflare-only check. These need to be
# reachable from inside Railway's network for platform-level health probes.
_EXEMPT_PATHS = ("/health",)


class CloudflareIPCheck:
    """Validate that incoming requests originate from Cloudflare's IP ranges."""

    def __init__(self) -> None:
        self._networks: list = []
        self._last_refresh: float = 0.0
        self._lock = threading.Lock()
        self._refresh(use_fallback=False)  # try live fetch on init

    def _parse_ranges(self, ranges: Iterable[str]) -> list:
        """Convert a list of CIDR strings into ip_network objects."""
        parsed = []
        for r in ranges:
            try:
                parsed.append(ipaddress.ip_network(r, strict=False))
            except ValueError as e:
                log.warning("CloudflareIPCheck: skipping bad CIDR %r: %s", r, e)
        return parsed

    def _refresh(self, use_fallback: bool = False) -> None:
        """Refresh the IP range list. On any error, fall back to hardcoded list."""
        if not use_fallback:
            try:
                # Lazy import: only pulled in when the module is active so a
                # disabled deploy doesn't pay for the import.
                import requests
                v4 = requests.get(
                    "https://www.cloudflare.com/ips-v4/",
                    timeout=10,
                ).text.strip().splitlines()
                v6 = requests.get(
                    "https://www.cloudflare.com/ips-v6/",
                    timeout=10,
                ).text.strip().splitlines()
                if v4 and v6:
                    with self._lock:
                        self._networks = self._parse_ranges(v4 + v6)
                        self._last_refresh = time.time()
                    log.info(
                        "CloudflareIPCheck: refreshed %d ranges from cloudflare.com",
                        len(self._networks),
                    )
                    return
            except Exception as e:
                log.warning(
                    "CloudflareIPCheck: live fetch failed (%s), using fallback list",
                    e,
                )

        # Fallback path
        with self._lock:
            self._networks = self._parse_ranges(
                list(_FALLBACK_CF_RANGES_V4) + list(_FALLBACK_CF_RANGES_V6)
            )
            self._last_refresh = time.time()
        log.info(
            "CloudflareIPCheck: using fallback list of %d ranges",
            len(self._networks),
        )

    def _maybe_refresh(self) -> None:
        """Refresh the range list if the cache is older than the interval."""
        if time.time() - self._last_refresh > _REFRESH_INTERVAL_SECONDS:
            # Don't block requests if refresh fails; we'll retry next interval.
            try:
                self._refresh(use_fallback=False)
            except Exception:
                pass

    def is_cloudflare_ip(self, ip_str: str) -> bool:
        """Return True if ip_str is within a known Cloudflare range."""
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        # Snapshot the network list under the lock so we're not iterating
        # while a refresh swaps it out.
        with self._lock:
            networks = list(self._networks)
        for net in networks:
            if ip.version == net.version and ip in net:
                return True
        return False


def install_cloudflare_only_check(app) -> None:
    """
    Install a before_request hook that rejects requests not from Cloudflare.

    No-op unless DTVSS_CLOUDFLARE_ONLY=1 is set in the environment. Path
    /health is exempt for platform health probes.

    Call this from apply_hardening() *after* ProxyFix has been applied,
    so request.remote_addr reflects the immediate peer (Railway edge for
    Cloudflare-fronted traffic, raw client for direct hits).
    """
    if os.environ.get("DTVSS_CLOUDFLARE_ONLY", "").lower() not in ("1", "true", "yes"):
        log.info(
            "CloudflareIPCheck: disabled (set DTVSS_CLOUDFLARE_ONLY=1 to enable)"
        )
        return

    from flask import request, abort

    checker = CloudflareIPCheck()

    @app.before_request
    def _enforce_cloudflare_origin():
        # Exempt platform health probes
        if request.path in _EXEMPT_PATHS:
            return None

        # Refresh the range list periodically (cheap if not due)
        checker._maybe_refresh()

        # Use remote_addr (post-ProxyFix). On Railway behind Cloudflare,
        # this should always be a Cloudflare edge IP.
        client_ip = request.remote_addr
        if not client_ip:
            log.warning("CloudflareIPCheck: no remote_addr on request, blocking")
            abort(403)
        if not checker.is_cloudflare_ip(client_ip):
            log.warning(
                "CloudflareIPCheck: blocking non-Cloudflare origin from %s "
                "(path=%s)",
                client_ip, request.path,
            )
            abort(403)
        return None

    log.info("CloudflareIPCheck: ENABLED - non-Cloudflare requests will be 403'd")
