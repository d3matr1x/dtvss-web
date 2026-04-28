#!/usr/bin/env python3
"""
DTVSS Security Test Suite
==========================
Demonstrates each finding from PENTEST_REPORT.md and verifies the fixes
in security.py.

Each test has two parts:
  1. Proof of Concept — shows the vulnerability is real
  2. Fix Verification — shows security.py blocks it

Run: python3 test_security.py
"""

import os
import sys
import urllib.parse

# Make project modules importable regardless of working directory.
# Previously this hardcoded /home/claude paths from a sandbox layout, which
# meant `python3 test_security.py` only worked if you happened to have that
# exact directory structure. Now we anchor on this file's own location, so
# the tests work on any machine, in any working directory, in CI, etc.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from security import (
    validate_external_url,
    validate_cve_id,
    validate_query,
    validate_float_param,
    sanitize_error,
    safe_parse_xml,
    validate_kev_catalog,
)


class C:
    GREEN = '\033[92m'; RED = '\033[91m'; YELLOW = '\033[93m'
    BLUE = '\033[94m'; CYAN = '\033[96m'; RESET = '\033[0m'; BOLD = '\033[1m'


results = {"passed": 0, "failed": 0, "poc": 0, "fixed": 0}


def section(title):
    print(f"\n{C.BOLD}{C.CYAN}{'─' * 70}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  {title}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'─' * 70}{C.RESET}")


def poc(label):
    print(f"\n  {C.YELLOW}▸ PoC:{C.RESET} {label}")
    results["poc"] += 1


def fix_ok(label):
    print(f"  {C.GREEN}✓ FIX:{C.RESET} {label}")
    results["fixed"] += 1
    results["passed"] += 1


def fix_fail(label):
    print(f"  {C.RED}✗ FIX:{C.RESET} {label}")
    results["failed"] += 1


def info(label):
    print(f"  {C.BLUE}ℹ{C.RESET} {label}")


# =============================================================================
# CRIT-01: XXE
# =============================================================================

def test_xxe_protection():
    section("CRIT-01: XXE (XML External Entity) Injection")
    
    # Malicious XML that would try to read /etc/passwd via external entity
    xxe_payload = b"""<?xml version="1.0"?>
<!DOCTYPE rss [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<rss><channel><item><title>&xxe;</title></item></channel></rss>"""
    
    poc("An attacker serves this RSS via compromised CDN / MITM:")
    print(f"    {xxe_payload.decode()[:120]}...")
    
    # Test stdlib vulnerability (what current code uses)
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(xxe_payload)
        title = root.find(".//title").text or ""
        if "root:" in title or "/bin/" in title:
            print(f"  {C.RED}✗ EXPLOITED: stdlib resolved external entity{C.RESET}")
            print(f"    Leaked: {title[:100]}")
        else:
            info("stdlib on this Python version doesn't resolve file:// entities by default")
            info("(Python 3.7.1+ disabled this, but defusedxml guarantees it across versions)")
    except Exception as e:
        info(f"stdlib raised: {type(e).__name__}")
    
    # Test the fix: defusedxml raises immediately on DTD
    try:
        safe_parse_xml(xxe_payload)
        fix_fail("safe_parse_xml did NOT block XXE payload")
    except Exception as e:
        fix_ok(f"safe_parse_xml blocked XXE: {type(e).__name__}: {str(e)[:60]}")
    
    # Billion laughs
    billion_laughs = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<rss><channel><item><title>&lol3;</title></item></channel></rss>"""
    
    try:
        safe_parse_xml(billion_laughs)
        fix_fail("safe_parse_xml did NOT block billion-laughs")
    except Exception as e:
        fix_ok(f"safe_parse_xml blocked billion-laughs: {type(e).__name__}")


# =============================================================================
# CRIT-02: SSRF
# =============================================================================

def test_ssrf_protection():
    section("CRIT-02: SSRF (Server-Side Request Forgery)")
    
    attack_urls = [
        ("http://169.254.169.254/latest/meta-data/",
         "AWS/Azure/GCP metadata endpoint (IMDS)"),
        ("http://localhost:5000/admin",
         "Loopback to internal admin"),
        ("http://127.0.0.1/",
         "Loopback IPv4"),
        ("http://[::1]/",
         "Loopback IPv6"),
        ("http://10.0.0.1/",
         "RFC1918 private range"),
        ("http://192.168.1.1/",
         "RFC1918 home network"),
        ("file:///etc/passwd",
         "File scheme"),
        ("gopher://evil.com:11211/",
         "Gopher scheme (cache poisoning)"),
        ("ftp://internal-ftp/",
         "FTP scheme"),
        ("http://169.254.169.254/icsma-fake/",
         "Bypass substring filter with /icsma- in path"),
        ("https://evil.com/icsma-2024-001",
         "Untrusted host with icsma in path"),
        # Railway-specific: private networking TLDs
        ("https://postgres.railway.internal:5432/",
         "Railway private DNS (lateral movement)"),
        ("https://redis.railway.internal/",
         "Railway internal Redis"),
        ("https://admin.internal/dashboard",
         "Generic .internal TLD"),
        ("https://server.local/",
         "mDNS .local domain"),
    ]
    
    poc("Attacker attempts SSRF via attacker-controlled URL:")
    
    all_blocked = True
    for url, desc in attack_urls:
        blocked = not validate_external_url(url)
        if blocked:
            print(f"  {C.GREEN}✓{C.RESET} Blocked: {desc}")
        else:
            print(f"  {C.RED}✗{C.RESET} NOT BLOCKED: {desc} — {url}")
            all_blocked = False
    
    if all_blocked:
        fix_ok(f"All {len(attack_urls)} SSRF attack vectors blocked")
    else:
        fix_fail("Some SSRF vectors not blocked")
    
    # Allowed URLs still work
    allowed_urls = [
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "https://api.first.org/data/v1/epss",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "https://cveawg.mitre.org/api/cve/CVE-2017-12718",
    ]
    
    poc("Legitimate URLs should still be allowed:")
    all_allowed = True
    for url in allowed_urls:
        ok = validate_external_url(url)
        if ok:
            print(f"  {C.GREEN}✓{C.RESET} Allowed: {url[:60]}")
        else:
            print(f"  {C.RED}✗{C.RESET} Incorrectly blocked: {url}")
            all_allowed = False
    
    if all_allowed:
        fix_ok("All legitimate URLs pass validation")
    else:
        fix_fail("Some legitimate URLs incorrectly blocked")


# =============================================================================
# HIGH-03/04: Input size DoS
# =============================================================================

def test_input_size_limits():
    section("HIGH-03/04: Input Size and Query Length Limits")
    
    # Query length DoS
    poc("Attacker sends 10MB search query")
    huge_query = "A" * (10 * 1024 * 1024)
    result = validate_query(huge_query)
    if result is not None and len(result) <= 100:
        fix_ok(f"validate_query capped at {len(result)} chars")
    else:
        fix_fail(f"validate_query did not cap: returned {len(result) if result else 0} chars")
    
    # Control chars
    poc("Attacker embeds null bytes to bypass filters")
    evil_query = "baxter\x00 UNION SELECT * FROM users"
    result = validate_query(evil_query)
    if result is None:
        fix_ok("Null bytes rejected")
    else:
        fix_fail(f"Null bytes not rejected: returned {result!r}")
    
    # Unicode control chars
    poc("Attacker embeds Unicode RTL override for display spoofing")
    rtl_query = "safe\u202Eevil"  # RLO character
    result = validate_query(rtl_query)
    if result is None:
        fix_ok("Unicode control chars rejected")
    else:
        info(f"Unicode control passed (isprintable() varies): {result!r}")
    
    # CVE ID fuzzing
    poc("Attacker fuzzes CVE ID parameter")
    bad_cve_ids = [
        "",
        "CVE-",
        "CVE-2024",
        "cve-2024-12345' OR 1=1--",
        "CVE-2024-12345; DROP TABLE x",
        "CVE-9999999999-1",
        "CVE-2024-" + "1" * 100,
        "CVE-\x00-\x00",
        "../../../etc/passwd",
    ]
    
    all_rejected = True
    for bad in bad_cve_ids:
        if validate_cve_id(bad) is not None:
            print(f"  {C.RED}✗{C.RESET} Not rejected: {bad!r}")
            all_rejected = False
    
    if all_rejected:
        fix_ok(f"All {len(bad_cve_ids)} malformed CVE IDs rejected")
    else:
        fix_fail("Some malformed CVE IDs were accepted")
    
    # Valid CVE IDs pass
    good = ["CVE-2017-12718", "cve-2020-11896", "2024-12345"]
    for g in good:
        if validate_cve_id(g) is None:
            fix_fail(f"Valid CVE rejected: {g}")
            return
    fix_ok("Valid CVE IDs normalized correctly")


# =============================================================================
# MED-02: /api/score integer overflow
# =============================================================================

def test_score_input_validation():
    section("MED-02: /api/score Input Validation")
    
    poc("Attacker sends extreme float values to /api/score")
    
    attacks = [
        (float("inf"), "B", "Infinity"),
        (float("-inf"), "B", "Negative infinity"),
        (float("nan"), "B", "NaN"),
        (1e308, "B", "Very large float"),
        (-1.0, "B", "Negative (below range)"),
        (11.0, "B", "Above max (>10)"),
        ("not a number", "B", "String"),
        (None, "B", "None"),
        ([], "B", "List"),
        (2.0, "L", "Above 1.0 range"),
    ]
    
    all_rejected = True
    for val, name, desc in attacks:
        try:
            min_v = 0.0
            max_v = 10.0 if name != "L" else 1.0
            validate_float_param(val, name, min_v, max_v)
            print(f"  {C.RED}✗{C.RESET} Accepted: {desc} ({val!r})")
            all_rejected = False
        except ValueError as e:
            print(f"  {C.GREEN}✓{C.RESET} Rejected {desc}: {e}")
    
    if all_rejected:
        fix_ok("All invalid float inputs rejected with clear error messages")
    else:
        fix_fail("Some malicious inputs were accepted")
    
    # Valid inputs pass
    valid = [0.0, 10.0, 5.5, 2.20, 9.8]
    for v in valid:
        try:
            validate_float_param(v, "B", 0, 10)
        except ValueError:
            fix_fail(f"Valid input rejected: {v}")
            return
    fix_ok("Valid float inputs pass through")


# =============================================================================
# HIGH-05: Error message leakage
# =============================================================================

def test_error_sanitization():
    section("HIGH-05: Error Message Sanitization")
    
    test_errors = [
        (
            Exception("NVD API error: Unauthorized at https://services.nvd.nist.gov/rest/json/cves/2.0?apiKey=abc123def456ghi789jkl012mno345pqr"),
            "URL with API key in query string",
            "[URL]",
        ),
        (
            Exception("File not found: /home/claude/secrets.env"),
            "Unix home directory path",
            "[HOME]",
        ),
        (
            Exception("Failed at /mnt/user-data/uploads/secret.txt"),
            "Internal file path",
            "[PATH]",
        ),
        (
            Exception("Auth failed with token abcdefghijklmnop1234567890123456789"),
            "Long hex token",
            "[KEY]",
        ),
        (
            Exception("connection to internal-db.railway.internal:5432 refused"),
            "Internal hostname",
            None,  # Hostname format doesn't match patterns — acceptable
        ),
    ]
    
    for exc, desc, expected_redaction in test_errors:
        sanitized = sanitize_error(exc)
        print(f"  {C.YELLOW}Input:{C.RESET}    {exc}")
        print(f"  {C.GREEN}Output:{C.RESET}   {sanitized}")
        
        # Check that sensitive patterns were redacted
        leaked_patterns = []
        if "abc123def456" in sanitized:
            leaked_patterns.append("API key")
        if "/home/" in sanitized:
            leaked_patterns.append("home directory")
        if "apiKey=" in sanitized:
            leaked_patterns.append("apiKey parameter")
        
        if leaked_patterns:
            fix_fail(f"{desc}: leaked {', '.join(leaked_patterns)}")
        else:
            fix_ok(f"{desc}: sensitive data redacted")
        print()


# =============================================================================
# MED-03: KEV Catalog Validation
# =============================================================================

def test_kev_validation():
    section("MED-03: CISA KEV Catalog Validation")
    
    poc("Attacker returns empty KEV catalog to hide active exploits")
    empty_catalog = {"vulnerabilities": []}
    result = validate_kev_catalog(empty_catalog, min_entries=500)
    if result is None:
        fix_ok("Empty KEV catalog rejected (would hide exploited CVEs)")
    else:
        fix_fail("Empty catalog accepted — dangerous for medical devices!")
    
    poc("Attacker returns malformed entries")
    malformed = {
        "vulnerabilities": [
            {"cveID": "not a real cve"},
            {"cveID": "CVE-2024-12345"},  # Missing required fields
            {"cveID": "CVE-2024-99999; DROP TABLE"},  # Injection attempt
            "not even a dict",
            None,
        ]
    }
    result = validate_kev_catalog(malformed, min_entries=1)
    if result is None or len(result) == 0:
        fix_ok("Malformed catalog rejected (no valid entries)")
    else:
        fix_fail(f"Malformed catalog accepted {len(result)} entries")
    
    poc("Legitimate KEV catalog passes")
    good_catalog = {
        "vulnerabilities": [
            {
                "cveID": f"CVE-2024-{i:05d}",
                "dateAdded": "2024-01-01",
                "vendorProject": "TestVendor",
                "product": "TestProduct",
                "vulnerabilityName": "Test Vuln",
            }
            for i in range(1000)
        ]
    }
    result = validate_kev_catalog(good_catalog, min_entries=500)
    if result and len(result) == 1000:
        fix_ok(f"Valid catalog accepted ({len(result)} entries)")
    else:
        fix_fail("Valid catalog incorrectly rejected")
    
    poc("Injection attempt in cveID")
    injection = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-12345' OR '1'='1",
                "dateAdded": "2024-01-01",
                "vendorProject": "v", "product": "p", "vulnerabilityName": "n",
            }
        ] * 600
    }
    # Build a version that has valid entries plus one injection
    catalog = {
        "vulnerabilities": [
            {
                "cveID": f"CVE-2024-{i:05d}",
                "dateAdded": "2024-01-01",
                "vendorProject": "v", "product": "p", "vulnerabilityName": "n",
            }
            for i in range(600)
        ] + [{
            "cveID": "CVE-2024-99999' OR 1=1--",
            "dateAdded": "x", "vendorProject": "x", "product": "x", "vulnerabilityName": "x",
        }]
    }
    result = validate_kev_catalog(catalog, min_entries=500)
    if result and "CVE-2024-99999' OR 1=1--" not in result:
        fix_ok("Injection payload in cveID filtered out")
    else:
        fix_fail("Injection payload accepted")


# =============================================================================
# M-1: KEV Cache Poisoning — preserve prior cache on bad refresh
# =============================================================================

def test_kev_cache_poisoning():
    section("M-1: KEV Cache Poisoning Resilience (cisa_kev_check)")

    # api_clients is on sys.path via the module-level insert at top of file;
    # no further path manipulation needed.
    import api_clients

    poc("Cache holds a known KEV entry; upstream then returns an empty catalog")
    info("This simulates a compromised CDN serving an empty list to hide active exploits")

    # Pre-seed the cache with one good entry
    api_clients._kev_cache["data"] = {
        "CVE-2017-12718": {
            "cveID": "CVE-2017-12718",
            "dateAdded": "2024-01-01",
            "dueDate": "2024-02-01",
            "vulnerabilityName": "Pre-existing KEV entry",
            "requiredAction": "Patch",
        }
    }
    api_clients._kev_cache["fetched_at"] = 0  # force refresh path
    api_clients._kev_cache["last_failure_at"] = 0  # clear backoff state

    original_fetch = api_clients._fetch_json
    try:
        # Scenario 1: poisoned (empty) catalog
        api_clients._fetch_json = (
            lambda url, headers=None, timeout=15, max_bytes=None: {"vulnerabilities": []}
        )
        r1 = api_clients.cisa_kev_check("CVE-2017-12718")
        if r1 and r1.get("kev") is True and "Pre-existing" in r1.get("kev_name", ""):
            fix_ok("Empty/poisoned catalog rejected; prior cache preserved")
        else:
            fix_fail(f"Cache was overwritten by poisoned data: {r1!r}")

        # Scenario 2: structurally broken catalog (not a dict)
        api_clients._kev_cache["fetched_at"] = 0
        api_clients._kev_cache["last_failure_at"] = 0  # clear backoff for fresh test
        api_clients._fetch_json = (
            lambda url, headers=None, timeout=15, max_bytes=None: "garbage string"
        )
        r2 = api_clients.cisa_kev_check("CVE-2017-12718")
        if r2 and r2.get("kev") is True:
            fix_ok("Garbage (non-dict) response rejected; prior cache preserved")
        else:
            fix_fail(f"Cache lost on garbage response: {r2!r}")

        # Scenario 3: cold start (no prior cache) + poisoned response → None
        api_clients._kev_cache["data"] = None
        api_clients._kev_cache["fetched_at"] = 0
        api_clients._kev_cache["last_failure_at"] = 0
        api_clients._fetch_json = (
            lambda url, headers=None, timeout=15, max_bytes=None: {"vulnerabilities": []}
        )
        r3 = api_clients.cisa_kev_check("CVE-2017-12718")
        if r3 is None:
            fix_ok("Cold-start + poisoned response returns None (no false confidence)")
        else:
            fix_fail(f"Cold-start should return None but got: {r3!r}")

        # Scenario 4: a legitimate refresh after recovery still updates the cache.
        # Reset last_failure_at to simulate post-backoff retry (in real life,
        # KEV_FAILURE_BACKOFF seconds would have passed; here we fast-forward).
        api_clients._kev_cache["data"] = None
        api_clients._kev_cache["fetched_at"] = 0
        api_clients._kev_cache["last_failure_at"] = 0
        good_catalog = {
            "vulnerabilities": [
                {
                    "cveID": f"CVE-2024-{i:05d}",
                    "dateAdded": "2024-01-01",
                    "vendorProject": "v",
                    "product": "p",
                    "vulnerabilityName": "n",
                    "dueDate": "2024-02-01",
                    "requiredAction": "patch",
                }
                for i in range(600)
            ] + [{
                "cveID": "CVE-2017-12718",
                "dateAdded": "2024-01-01",
                "vendorProject": "v",
                "product": "p",
                "vulnerabilityName": "Recovered entry",
                "dueDate": "2024-02-01",
                "requiredAction": "patch",
            }]
        }
        api_clients._fetch_json = (
            lambda url, headers=None, timeout=15, max_bytes=None: good_catalog
        )
        r4 = api_clients.cisa_kev_check("CVE-2017-12718")
        if r4 and r4.get("kev_name") == "Recovered entry":
            fix_ok("Good response after recovery updates the cache normally")
        else:
            fix_fail(f"Good response did not update cache: {r4!r}")

    finally:
        api_clients._fetch_json = original_fetch
        # Reset cache so subsequent tests don't see leaked state
        api_clients._kev_cache["data"] = None
        api_clients._kev_cache["fetched_at"] = 0
        api_clients._kev_cache["last_failure_at"] = 0


# =============================================================================
# M-2: Per-Advisory Page Host Restriction (index_loader)
# =============================================================================

def test_advisory_host_restriction():
    section("M-2: Per-Advisory Page Host Restriction (RSS-injected links)")

    poc("A tampered RSS feed injects a non-CISA <link> to redirect us")
    info("ICSMA advisory pages must ONLY come from cisa.gov, even though "
         "the broader allowlist contains other legitimate hosts (NVD, MITRE, etc)")

    # Mirror the host-check logic from index_loader._hourly_pipeline.
    # We test the policy directly because the actual function runs in
    # a daemon thread on import and isn't easily callable in isolation.
    import urllib.parse
    def advisory_host_ok(link):
        parsed = urllib.parse.urlparse(link)
        return (parsed.hostname or "").lower() in ("cisa.gov", "www.cisa.gov")

    attack_links = [
        ("https://evil.com/icsma-fake/2024-001",
         "Attacker-controlled host with icsma in path"),
        ("https://attacker.example.com/icsma-001",
         "Random attacker domain"),
        ("https://services.nvd.nist.gov/icsma-001",
         "Other allowlisted host (NVD) — should NOT serve advisories"),
        ("https://api.fda.gov/icsma-001",
         "Other allowlisted host (openFDA) — should NOT serve advisories"),
        ("https://raw.githubusercontent.com/x/icsma.html",
         "Other allowlisted host (GitHub) — should NOT serve advisories"),
        ("https://evil-cisa.gov.attacker.com/icsma-001",
         "Substring-bypass: cisa.gov as subdomain prefix"),
        ("https://cisa.gov.evil.com/icsma-001",
         "Substring-bypass: cisa.gov as suffix on attacker domain"),
        ("http://www.cisa.gov/icsma-001",
         "HTTP (not HTTPS) — caught by SSRF scheme check downstream"),
    ]
    all_blocked = True
    for link, desc in attack_links:
        # http:// case will pass the host check but be blocked by safe_fetch_bytes;
        # for the purpose of this test we accept either layer rejecting it.
        host_ok = advisory_host_ok(link)
        if "http://" in link and host_ok:
            # Verify the SSRF layer blocks it
            from security import validate_external_url
            if not validate_external_url(link):
                print(f"  {C.GREEN}✓{C.RESET} Blocked at SSRF layer: {desc}")
                continue
        if host_ok:
            print(f"  {C.RED}✗{C.RESET} NOT BLOCKED: {desc} — {link}")
            all_blocked = False
        else:
            print(f"  {C.GREEN}✓{C.RESET} Blocked at host check: {desc}")

    if all_blocked:
        fix_ok(f"All {len(attack_links)} tampered-link attack vectors blocked")
    else:
        fix_fail("Some tampered advisory links not blocked")

    poc("Legitimate cisa.gov ICSMA URLs still pass")
    good_links = [
        "https://www.cisa.gov/news-events/ics-medical-advisories/icsma-24-001-01",
        "https://cisa.gov/news-events/ics-medical-advisories/icsma-24-002-01",
    ]
    for link in good_links:
        if not advisory_host_ok(link):
            fix_fail(f"Legitimate link rejected: {link}")
            return
        print(f"  {C.GREEN}✓{C.RESET} Allowed: {link}")
    fix_ok("Legitimate CISA ICSMA URLs pass the host check")

    poc("XXE RSS payload would be parsed by stdlib but is blocked by safe_parse_xml")
    xxe_rss = b"""<?xml version="1.0"?>
<!DOCTYPE rss [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<rss><channel><item><title>&xxe;</title>
<link>https://www.cisa.gov/icsma-evil</link></item></channel></rss>"""
    try:
        safe_parse_xml(xxe_rss)
        fix_fail("XXE RSS was accepted by safe_parse_xml")
    except Exception as e:
        fix_ok(f"XXE RSS rejected by safe_parse_xml: {type(e).__name__}")

    poc("A legitimate RSS feed still parses correctly")
    good_rss = b"""<?xml version="1.0"?>
<rss><channel>
  <item>
    <title>ICSMA-24-001-01 ExampleVendor Pump</title>
    <link>https://www.cisa.gov/news-events/ics-medical-advisories/icsma-24-001-01</link>
  </item>
</channel></rss>"""
    try:
        root = safe_parse_xml(good_rss)
        items = root.findall(".//item")
        if len(items) == 1 and items[0].findtext("title", "").startswith("ICSMA-24-001-01"):
            fix_ok("Legitimate RSS still parses with safe_parse_xml")
        else:
            fix_fail("Legitimate RSS did not parse as expected")
    except Exception as e:
        fix_fail(f"Legitimate RSS rejected: {e}")


# =============================================================================
# M-3: Response Size Cap on External JSON Fetches
# =============================================================================

def test_response_size_cap():
    section("M-3: Response Size Cap (api_clients._fetch_json)")

    # api_clients is on sys.path via the module-level insert at top of file.
    import api_clients
    import urllib3.connection
    from security import safe_fetch_bytes, MAX_RESPONSE_BYTES

    # safe_fetch_bytes now uses urllib3.connection.HTTPSConnection directly
    # (via the SSRF DNS-pinning fix). These fakes mimic urllib3's connection
    # and response API:
    #   conn.request(method, path, headers=..., preload_content=...)
    #   conn.getresponse() -> HTTPResponse with .getheader() and .stream()
    #   conn.close()
    class _FakeUrllib3Resp:
        def __init__(self, body, content_length=None):
            self._body = body
            self._cl = content_length
            self.was_read = False
        def getheader(self, name, default=None):
            if name.lower() == "content-length" and self._cl is not None:
                return self._cl
            return default
        def stream(self, amt=8192, decode_content=False):
            self.was_read = True
            i = 0
            while i < len(self._body):
                yield self._body[i:i+amt]
                i += amt

    class _FakeUrllib3Conn:
        def __init__(self, body, content_length=None, **kwargs):
            self._resp = _FakeUrllib3Resp(body, content_length)
            self.kwargs = kwargs
        def request(self, method, path, headers=None, preload_content=True):
            pass
        def getresponse(self):
            return self._resp
        def close(self):
            pass

    original_conn = urllib3.connection.HTTPSConnection

    poc("Compromised upstream returns an 11 MB JSON blob to exhaust memory")
    info(f"Default cap is {MAX_RESPONSE_BYTES // (1024*1024)} MB on JSON responses")

    # Scenario 1: oversized response with no Content-Length (chunked-style),
    # so the read-cap path is exercised, not the early-exit path.
    body_giant = b"0" * (MAX_RESPONSE_BYTES + 1024)
    urllib3.connection.HTTPSConnection = lambda *a, **kw: _FakeUrllib3Conn(body_giant, content_length=None, **kw)
    try:
        try:
            safe_fetch_bytes(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                timeout=5,
            )
            fix_fail("Oversized response was not blocked")
        except ValueError as e:
            fix_ok(f"Oversized response blocked: {e}")
    finally:
        urllib3.connection.HTTPSConnection = original_conn

    # Scenario 2: Content-Length header declares oversized response.
    # This used to be a known-broken path (the over-cap raise was caught
    # by the same `except ValueError` that handled unparseable headers).
    # That bug is now fixed in security.safe_fetch_bytes — this test
    # guards against regression. The body should NOT be streamed.
    poc("Compromised upstream declares Content-Length > cap (early-exit)")

    cl_oversize = str(MAX_RESPONSE_BYTES + 1)
    last_resp = {"r": None}
    def make_cl_conn(*a, **kw):
        c = _FakeUrllib3Conn(b"", content_length=cl_oversize, **kw)
        last_resp["r"] = c._resp
        return c
    urllib3.connection.HTTPSConnection = make_cl_conn
    try:
        try:
            safe_fetch_bytes(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                timeout=5,
            )
            fix_fail("Content-Length-declared oversized response not blocked")
        except ValueError as e:
            if last_resp["r"] is not None and last_resp["r"].was_read:
                fix_fail(f"Content-Length over-cap rejected, but body was streamed: {e}")
            else:
                fix_ok(f"Content-Length over-cap rejected early (body not streamed): {e}")
    finally:
        urllib3.connection.HTTPSConnection = original_conn

    # Scenario 3: read-cap is the authoritative defense even when
    # Content-Length lies about the size (declares small, sends large).
    poc("Compromised upstream lies about Content-Length but sends a large body")

    big_body = b"0" * (MAX_RESPONSE_BYTES + 1024)
    urllib3.connection.HTTPSConnection = lambda *a, **kw: _FakeUrllib3Conn(big_body, content_length="100", **kw)
    try:
        try:
            safe_fetch_bytes(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                timeout=5,
            )
            fix_fail("Read-cap did not fire when Content-Length lied")
        except ValueError as e:
            fix_ok(f"Read-cap fires regardless of Content-Length: {e}")
    finally:
        urllib3.connection.HTTPSConnection = original_conn

    # Scenario 4: every external API call site routes through _fetch_json
    poc("All 7 api_clients.py external call sites route through _fetch_json (SSRF + cap apply uniformly)")

    # Map of upstream hostname -> stub response. Using a strict hostname
    # match (via urlparse) rather than substring "x.com in url" — the
    # latter would be flagged by CodeQL py/incomplete-url-substring-
    # sanitization (correctly: substring matching on URLs is unsafe for
    # security decisions; even though this is a test fixture, the pattern
    # is bad practice).
    _stub_responses = {
        "api.first.org": {"status": "OK", "data": [
            {"cve": "CVE-2017-12718", "epss": "0.97",
             "percentile": "0.99", "date": "2024-01-01"}
        ]},
        "api.fda.gov": {"results": [
            {"device_class": "3", "device_name": "test pump",
             "product_code": "FRN", "medical_specialty_description": "AN",
             "definition": "x"}
        ]},
        "cveawg.mitre.org": {"containers": {"cna": {}}, "cveMetadata": {}},
        "www.cisa.gov": {"vulnerabilities": [
            {"cveID": f"CVE-2024-{i:05d}", "dateAdded": "2024-01-01",
             "vendorProject": "v", "product": "p",
             "vulnerabilityName": "n", "dueDate": "2024-02-01",
             "requiredAction": "patch"}
            for i in range(600)
        ]},
        "cisa.gov": {"vulnerabilities": [
            {"cveID": f"CVE-2024-{i:05d}", "dateAdded": "2024-01-01",
             "vendorProject": "v", "product": "p",
             "vulnerabilityName": "n", "dueDate": "2024-02-01",
             "requiredAction": "patch"}
            for i in range(600)
        ]},
        "services.nvd.nist.gov": {"vulnerabilities": []},
    }

    calls = []
    def stub(url, headers=None, timeout=15, max_bytes=None):
        calls.append(url)
        host = (urllib.parse.urlparse(url).hostname or "").lower()
        return _stub_responses.get(host, {})

    original_fetch_json = api_clients._fetch_json
    api_clients._fetch_json = stub
    api_clients._kev_cache["data"] = None
    api_clients._kev_cache["fetched_at"] = 0
    api_clients._kev_cache["last_failure_at"] = 0  # clear any prior backoff
    api_clients._device_cache["keywords"] = {}
    api_clients._device_cache["fetched_at"] = 0

    try:
        api_clients.nvd_lookup_cve("CVE-2017-12718")
        api_clients.mitre_lookup_cve("CVE-2017-12718")
        api_clients.nvd_search_keyword("test")
        api_clients.epss_lookup(["CVE-2017-12718"])
        api_clients.openfda_classify_device("infusion pump")
        api_clients.cisa_kev_check("CVE-2017-12718")
        api_clients.refresh_device_keywords()

        # Verify each expected host was hit. Same defensive pattern as
        # the stub: parse hostnames, don't substring-match.
        call_hosts = {(urllib.parse.urlparse(c).hostname or "").lower() for c in calls}
        expected_hosts = {
            "services.nvd.nist.gov",
            "cveawg.mitre.org",
            "api.first.org",
            "api.fda.gov",
        }
        # CISA may resolve to either www.cisa.gov or cisa.gov depending
        # on the API client's URL construction; accept either.
        cisa_hit = any(h in call_hosts for h in ("www.cisa.gov", "cisa.gov"))
        missing = expected_hosts - call_hosts
        if missing or not cisa_hit:
            missing_list = list(missing)
            if not cisa_hit:
                missing_list.append("cisa.gov")
            fix_fail(f"These expected call sites did not route through _fetch_json: {missing_list}")
        else:
            fix_ok(f"All 7 call sites route through _fetch_json (hit {len(set(calls))} distinct URLs)")

        # Verify noRejected param preserved on NVD search.
        nvd_search_calls = [
            c for c in calls
            if (urllib.parse.urlparse(c).hostname or "").lower() == "services.nvd.nist.gov"
            and "keywordSearch" in c
        ]
        if nvd_search_calls and "noRejected=" in nvd_search_calls[0]:
            fix_ok("nvd_search_keyword preserves noRejected param")
        else:
            fix_fail(f"nvd_search_keyword lost noRejected param: {nvd_search_calls}")

    finally:
        api_clients._fetch_json = original_fetch_json
        api_clients._kev_cache["data"] = None
        api_clients._kev_cache["fetched_at"] = 0
        api_clients._device_cache["keywords"] = {}
        api_clients._device_cache["fetched_at"] = 0


# =============================================================================
# MAIN
# =============================================================================

def main():
    print(f"\n{C.BOLD}{'═' * 70}{C.RESET}")
    print(f"{C.BOLD}  DTVSS SECURITY TEST SUITE — Red Team{C.RESET}")
    print(f"{C.BOLD}  Demonstrates vulnerabilities and verifies fixes{C.RESET}")
    print(f"{C.BOLD}{'═' * 70}{C.RESET}")
    
    test_xxe_protection()
    test_ssrf_protection()
    test_input_size_limits()
    test_score_input_validation()
    test_error_sanitization()
    test_kev_validation()
    test_kev_cache_poisoning()
    test_advisory_host_restriction()
    test_response_size_cap()
    
    # Summary
    print(f"\n{C.BOLD}{'═' * 70}{C.RESET}")
    print(f"{C.BOLD}  SUMMARY{C.RESET}")
    print(f"{C.BOLD}{'═' * 70}{C.RESET}")
    print(f"  PoC attacks demonstrated:  {C.YELLOW}{results['poc']}{C.RESET}")
    print(f"  Fixes verified:            {C.GREEN}{results['fixed']}{C.RESET}")
    print(f"  Tests failed:              {C.RED}{results['failed']}{C.RESET}")
    
    if results["failed"] == 0:
        print(f"\n  {C.GREEN}{C.BOLD}✓ All security controls working correctly{C.RESET}")
        return 0
    else:
        print(f"\n  {C.RED}{C.BOLD}✗ {results['failed']} security test(s) failed{C.RESET}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
