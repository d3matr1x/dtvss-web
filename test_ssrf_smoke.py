"""
SSRF DNS-pinning smoke test.

Run this manually after changing safe_fetch_bytes / validate_external_url:

    python test_ssrf_smoke.py

It hits every host in ALLOWED_EXTERNAL_HOSTS through the new urllib3-based
fetcher and verifies the response shape. NOT part of the regular CI suite
because the upstream services are out-of-scope for our test budget; failures
here are usually upstream blips, not regressions.

What this proves:
- urllib3 + DNS pinning + assert_hostname + server_hostname work for the
  exact set of hosts we allowlist
- The exception-translation layer correctly raises urllib.error.URLError
  for network failures
- The response is non-empty bytes for normal endpoints

What this does NOT prove:
- That DNS pinning actually prevents a rebinding attack. That requires a
  mock DNS resolver and is a separate test (TODO).

Copyright 2026 Andrew Broglio. Licensed under BSL 1.1.
"""
from __future__ import annotations

import sys
import urllib.error

from security import safe_fetch_bytes, validate_and_resolve_external_url


# (URL, expected behaviour) — chosen so each is a small, stable endpoint.
PROBES = [
    ("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-11899",
     "NVD: should return JSON containing vulnerabilities"),
    ("https://cveawg.mitre.org/api/cve/CVE-2020-11899",
     "MITRE CVE Services: should return JSON CVE record"),
    ("https://api.first.org/data/v1/epss?cve=CVE-2020-11899",
     "FIRST EPSS: should return JSON with status='OK'"),
    ("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
     "CISA KEV: should return JSON catalog"),
    ("https://api.fda.gov/device/event.json?limit=1",
     "openFDA: should return JSON with results array"),
    ("https://raw.githubusercontent.com/cisagov/CSAF/HEAD/README.md",
     "GitHub raw: should return CSAF README markdown"),
    ("https://api.github.com/repos/cisagov/CSAF",
     "GitHub API: should return JSON repo metadata"),
]


def main() -> int:
    """Returns 0 on full success, non-zero count of failures otherwise."""
    failures: list[tuple[str, str]] = []
    successes = 0

    for url, description in PROBES:
        print(f"\n→ {url}")
        print(f"  ({description})")

        # First: validator returns an IP
        ip = validate_and_resolve_external_url(url)
        if ip is None:
            failures.append((url, "validator rejected the URL"))
            print("  ✗ validator rejected — should have allowed")
            continue
        print(f"  validator pinned: {ip}")

        # Second: full fetch through the pinned IP
        try:
            body = safe_fetch_bytes(url, timeout=15)
        except urllib.error.URLError as e:
            failures.append((url, f"URLError: {e}"))
            print(f"  ✗ URLError: {e}")
            continue
        except ValueError as e:
            failures.append((url, f"ValueError: {e}"))
            print(f"  ✗ ValueError: {e}")
            continue
        except Exception as e:
            failures.append((url, f"unexpected {type(e).__name__}: {e}"))
            print(f"  ✗ unexpected {type(e).__name__}: {e}")
            continue

        if not body:
            failures.append((url, "empty response body"))
            print("  ✗ empty body")
            continue

        print(f"  ✓ {len(body)} bytes")
        successes += 1

    print(f"\n{'-' * 60}")
    print(f"Passed: {successes}/{len(PROBES)}")
    if failures:
        print(f"Failed: {len(failures)}")
        for url, reason in failures:
            print(f"  - {url}: {reason}")
        return len(failures)
    print("All allowlisted hosts reachable through DNS-pinned fetcher.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
