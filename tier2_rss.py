"""
DTVSS Tier 2 — Manufacturer-filtered RSS feed generation
========================================================

Stage 3 of the Tier 2 implementation plan: customers with a valid token
get an RSS 2.0 feed of CVEs filtered to their selected manufacturers,
with each entry scored using the DTVSS algorithm.

Design summary (tier2-design.md §3-5, tier2-implementation-plan.md Stage 3):

  - Customer-scoped feed: only CVEs for manufacturers in customer.manufacturers
  - DTVSS scores computed per-request, NOT cached in the index
    (KEV catalogue and device-keyword index are already cached at the
    api_clients layer; EPSS is one batched API call per request)
  - RSS 2.0 XML with custom xmlns:dtvss namespace exposing the patent
    variables (B, L_eff, H, score) plus severity_tier and tga_class
  - Cache-Control: max-age=300 (5 minutes) - lets RSS readers poll
    frequently without hammering us

Architectural decisions (ADR-003):

  D1: Request-time scoring (not index-time storage). EPSS scores update
      daily and customers paying for "live threat-aligned" intel deserve
      fresh values. Existing caching (KEV 1h, device keywords 24h) plus
      EPSS batching keeps per-request latency under 1 second for typical
      feed sizes.

  D2: Filter before any data leaves generate_feed(). The unit test
      'test_filter_isolation_no_other_manufacturers' is a regression
      guard against the design's documented R-risk: feed leaks data
      customer shouldn't see.

  D3: KEV-overridden CVEs are flagged in the entry title prefix as
      [CRITICAL] regardless of their pre-override score. This is what
      a security-aware ops team wants to see at a glance.

  D4: severity_tier maps the DTVSS score band:
        score >= 8.0  -> "critical"
        score >= 6.0  -> "high"
        score >= 3.0  -> "medium"
        score <  3.0  -> "low"
      Matches THRESHOLDS in dtvss_engine.py.

  D5: Stage 3 emits all CVEs for selected manufacturers (no time limit,
      no score filter). RSS readers handle their own mark-as-read /
      archive workflows. Premium-tier filtering is Stage 5.

  D6: pubDate = NVD published date when available, fallback to feed
      generation time. guid = CVE ID (stable, unique across feeds).

  D7: When EPSS lookup fails, fall back to L=0.0 (effectively scores
      become B*H/10 static baseline). Customer still gets a usable
      feed; the underlying API issue surfaces in Sentry via the
      existing logging in api_clients.epss_lookup.

ADR: 003-stage3-rss-feed-generation.md
Copyright 2026 Andrew Broglio. Licensed under BSL 1.1.
"""
from __future__ import annotations

import logging
from datetime import UTC, datetime
from email.utils import format_datetime, parsedate_to_datetime
from typing import Any
from xml.sax.saxutils import escape as xml_escape

from api_clients import (
    cisa_kev_check,
    epss_lookup,
    parse_cvss31_exploitability,
)
from dtvss_engine import TGA_CLASSES, classify_device, compute_dtvss
from index_loader import search_manufacturer_cves
from tier2_customers import Customer

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
RSS_NAMESPACE = "https://dtvss.io/rss/1.0"
DEFAULT_TGA_CLASS = "IIb"  # fallback when device classification fails
DEFAULT_L = 0.0            # EPSS fallback when API fails (yields B*H/10)


# ---------------------------------------------------------------------------
# Severity tier mapping (D4)
# ---------------------------------------------------------------------------
# These thresholds match the THRESHOLDS list in dtvss_engine.py:
#   < 3.0  Low      "Monitor..."
#   < 6.0  Medium   "Remediate within 30 days..."
#   < 8.0  High     "Remediate within 7 days..."
#   <= 10  Critical "Immediate action..."
def _severity_tier(score: float, kev_override: bool) -> str:
    """Map a DTVSS score to a severity tier string for RSS consumers.

    KEV-overridden CVEs ARE critical regardless of score - the
    compute_dtvss function already returns score=10.0 in that case,
    but we surface it explicitly here too.
    """
    if kev_override:
        return "critical"
    if score >= 8.0:
        return "critical"
    if score >= 6.0:
        return "high"
    if score >= 3.0:
        return "medium"
    return "low"


def _title_prefix(severity: str, kev_override: bool) -> str:
    """Title prefix surfaces severity at a glance in RSS readers.

    [CRITICAL] [KEV] CVE-2024-1234 - some description...
    [HIGH] CVE-2024-5678 - description...
    """
    if kev_override:
        return "[CRITICAL] [KEV] "
    if severity == "critical":
        return "[CRITICAL] "
    if severity == "high":
        return "[HIGH] "
    if severity == "medium":
        return "[MEDIUM] "
    return ""


# ---------------------------------------------------------------------------
# CVE -> RSS entry scoring (request-time)
# ---------------------------------------------------------------------------
# Each CVE in the manufacturer's CVE list is scored as follows:
#
#   B = parse_cvss31_exploitability(cve.cvss_vector) or 0.0
#   L = epss_map.get(cve.cve_id, {}).get("epss", 0.0)  # batched lookup
#   H = TGA_CLASSES[tga_class]["H"]                     # from classify_device
#   kev = bool(cisa_kev_check(cve.cve_id))              # uses existing 1h cache
#
# compute_dtvss(B, L, H, kev) returns the DTVSS score dict.
#
# All four lookups handle their own failure modes:
#   - CVSS parse failure -> B=0
#   - EPSS unavailable -> L=0 (caller logs via epss_lookup warnings)
#   - Classification failure -> TGA defaults to IIb
#   - KEV cache stale-but-good is served on API failure
def _score_cve(cve: dict, epss_map: dict, default_tga: str = DEFAULT_TGA_CLASS) -> dict:
    """Compute the DTVSS score for one CVE entry. Returns a dict with
    score components and the device class. Never raises; all failure
    modes are handled inline so feed generation is robust to API
    transients."""
    cve_id = cve.get("cve_id", "")
    description = cve.get("description", "")
    cvss_vector = cve.get("cvss_vector", "")

    # B: exploitability sub-score from CVSS vector
    try:
        B = parse_cvss31_exploitability(cvss_vector) or 0.0
    except Exception:  # noqa: BLE001
        B = 0.0
    B = max(0.0, min(10.0, B))

    # L: EPSS probability from batched lookup
    try:
        epss_val = epss_map.get(cve_id, {}).get("epss", DEFAULT_L)
        L = float(epss_val)
    except (TypeError, ValueError):
        L = DEFAULT_L
    L = max(0.0, min(1.0, L))

    # H: TGA harm weighting from device classification.
    # classify_device(description, use_openfda=True) does local keyword
    # matching only (Layer 3 live API is disabled in request path per
    # dtvss_engine.py comments).
    try:
        tga_class, _classification_source = classify_device(description)
        if tga_class not in TGA_CLASSES:
            tga_class = default_tga
    except Exception:  # noqa: BLE001
        tga_class = default_tga
    H = TGA_CLASSES[tga_class]["H"]

    # KEV check (existing 1-hour cache in api_clients.cisa_kev_check)
    try:
        kev = bool(cisa_kev_check(cve_id))
    except Exception:  # noqa: BLE001
        kev = False

    # Compute the score. strict=False since we've already clamped inputs;
    # this also matches the calculator route's behaviour for consistency.
    try:
        result = compute_dtvss(B, L, H, kev=kev, strict=False)
    except Exception as e:  # noqa: BLE001
        log.warning("compute_dtvss failed for %s: %s", cve_id, e)
        # Build a minimal result so the entry can still appear in the feed
        result = {
            "B": round(B, 3), "L": round(L, 4), "H": round(H, 1),
            "score": round(B * H / 10, 2),
            "risk_level": "Unknown",
            "kev_override": False,
        }

    return {
        "B": result["B"],
        "L": result["L"],          # EPSS as fractional probability
        "H": result["H"],
        "L_eff": result["L"],      # alias used by some doc text; same value
        "score": result["score"],
        "kev_override": result.get("kev_override", False),
        "tga_class": tga_class,
        "risk_level": result.get("risk_level", ""),
    }


# ---------------------------------------------------------------------------
# Time formatting
# ---------------------------------------------------------------------------
# RSS 2.0 pubDate is RFC 822 format (Tue, 18 May 2026 11:30:00 +0000)
# NVD's published dates come as ISO 8601. Convert at emit time.
def _format_rss_date(value: Any) -> str:
    """Convert various date formats to RFC 822 for RSS pubDate.
    Falls back to current time if parsing fails."""
    if not value:
        return format_datetime(datetime.now(UTC))
    try:
        if isinstance(value, datetime):
            dt = value
        elif isinstance(value, str):
            # Try ISO 8601 first (most common from NVD)
            try:
                # Handle both with-Z and with-offset forms
                cleaned = value.rstrip("Z")
                # Try parseable ISO subsets
                if "T" in cleaned:
                    dt = datetime.fromisoformat(cleaned)
                else:
                    # Date-only string like "2024-01-15"
                    dt = datetime.fromisoformat(cleaned + "T00:00:00")
            except ValueError:
                # Fallback: try parsing as RFC 822
                dt = parsedate_to_datetime(value)
        else:
            return format_datetime(datetime.now(UTC))
        # Ensure timezone-aware
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return format_datetime(dt)
    except Exception:  # noqa: BLE001
        return format_datetime(datetime.now(UTC))


# ---------------------------------------------------------------------------
# Filter integrity (D2 - the design's R-marker)
# ---------------------------------------------------------------------------
# The most important security property in Stage 3: a customer's feed
# MUST contain ONLY CVEs from manufacturers in customer.manufacturers.
# This function is the single place where that filter is applied; tests
# assert against this behaviour directly.
def _gather_filtered_cves(customer: Customer) -> list[dict]:
    """Return CVEs ONLY for the customer's selected manufacturers.

    NEVER returns CVEs for any other manufacturer regardless of caller
    intent. The customer.manufacturers list is the sole authority for
    what's emitted.

    De-duplication: a CVE may appear in multiple manufacturer entries
    in the MDM index (e.g. a multi-vendor advisory). We de-duplicate by
    cve_id so the customer sees each CVE once.
    """
    if not customer.manufacturers:
        return []

    seen_ids: set[str] = set()
    cves: list[dict] = []
    for manufacturer in customer.manufacturers:
        # search_manufacturer_cves is in index_loader and is the public
        # API for reading MDM data. It returns a deep copy (per its
        # docstring) so we can safely build on the result.
        for cve in search_manufacturer_cves(manufacturer):
            cve_id = cve.get("cve_id")
            if not cve_id or cve_id in seen_ids:
                continue
            seen_ids.add(cve_id)
            # Tag the CVE with which manufacturer it surfaced under, so
            # the RSS entry can mention it. If a CVE appears under
            # multiple manufacturers, the first one wins (deterministic
            # by the order of customer.manufacturers).
            cve["_manufacturer"] = manufacturer
            cves.append(cve)
    return cves


# ---------------------------------------------------------------------------
# RSS XML generation
# ---------------------------------------------------------------------------
def _xml_escape_attr(value: str) -> str:
    """Escape for use in an XML attribute value. xml.sax.saxutils.escape
    handles & < > and we add quote escaping."""
    return xml_escape(str(value), {'"': "&quot;", "'": "&apos;"})


def _format_entry(cve: dict, scored: dict, gen_now: datetime) -> str:
    """Generate one <item> XML block for a CVE.

    Includes:
      - title (with severity prefix per D3)
      - link (NVD lookup URL)
      - description (CVE description, HTML-escaped)
      - pubDate (NVD published date or fallback)
      - guid (stable: cve_id)
      - manufacturer (the customer's selector that surfaced this CVE)
      - dtvss:* custom elements (B, L_eff, H, score, severity_tier, tga_class)
    """
    cve_id = cve.get("cve_id", "")
    description = cve.get("description", "") or "No description available."
    published = cve.get("published") or gen_now.isoformat()
    manufacturer = cve.get("_manufacturer", "")

    severity = _severity_tier(scored["score"], scored["kev_override"])
    prefix = _title_prefix(severity, scored["kev_override"])
    # Truncate description for the title (first 80 chars or first sentence)
    short_desc = description.split(".")[0][:80].strip()
    if not short_desc:
        short_desc = cve_id
    title = f"{prefix}{cve_id} - {short_desc}"

    # NVD CVE detail URL is canonical and stable
    link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    return f"""    <item>
      <title>{xml_escape(title)}</title>
      <link>{xml_escape(link)}</link>
      <description>{xml_escape(description)}</description>
      <pubDate>{xml_escape(_format_rss_date(published))}</pubDate>
      <guid isPermaLink="false">{xml_escape(cve_id)}</guid>
      <category>{xml_escape(manufacturer)}</category>
      <dtvss:score>{scored["score"]}</dtvss:score>
      <dtvss:severity_tier>{severity}</dtvss:severity_tier>
      <dtvss:tga_class>{xml_escape(scored["tga_class"])}</dtvss:tga_class>
      <dtvss:B>{scored["B"]}</dtvss:B>
      <dtvss:L_eff>{scored["L_eff"]}</dtvss:L_eff>
      <dtvss:H>{scored["H"]}</dtvss:H>
      <dtvss:kev_override>{"true" if scored["kev_override"] else "false"}</dtvss:kev_override>
    </item>"""


def generate_feed(customer: Customer, gen_time: datetime | None = None) -> str:
    """Build the customer-scoped RSS 2.0 feed.

    Args:
        customer: validated Customer record (from @require_tier2)
        gen_time: override for "now" — tests use this for deterministic output.

    Returns:
        A complete RSS 2.0 XML string. UTF-8 encoded as a Python str;
        the Flask route is responsible for setting the content type.

    Safety property (D2): the returned XML contains entries ONLY for
    manufacturers in customer.manufacturers. This is enforced by
    _gather_filtered_cves(); see test_filter_isolation_no_other_manufacturers.
    """
    gen_now = gen_time or datetime.now(UTC)

    # Step 1: Filter CVEs by customer's manufacturers
    cves = _gather_filtered_cves(customer)

    # Step 2: Batch-lookup EPSS scores for all CVE IDs at once
    cve_ids = [cve.get("cve_id", "") for cve in cves if cve.get("cve_id")]
    try:
        epss_map = epss_lookup(cve_ids) if cve_ids else {}
    except Exception as e:  # noqa: BLE001
        # epss_lookup already logs warnings on failure; here we just
        # ensure the feed still renders with L=0 fallbacks.
        log.warning("EPSS lookup failed for customer %s: %s", customer.id, e)
        epss_map = {}

    # Step 3: Score each CVE
    scored_entries: list[tuple[dict, dict]] = []
    for cve in cves:
        scored = _score_cve(cve, epss_map)
        scored_entries.append((cve, scored))

    # Step 4: Sort by score descending (highest-risk first)
    # KEV-overridden entries float to the top because their score is 10.0
    scored_entries.sort(key=lambda pair: pair[1]["score"], reverse=True)

    # Step 5: Build the RSS XML
    last_build_date = _format_rss_date(gen_now)

    manufacturers_str = ", ".join(customer.manufacturers) or "(none)"
    channel_description = (
        f"DTVSS-scored medical device vulnerability feed for "
        f"{xml_escape(customer.organisation)}. "
        f"Manufacturers: {xml_escape(manufacturers_str)}."
    )

    items_xml = "\n".join(_format_entry(cve, scored, gen_now)
                          for cve, scored in scored_entries)

    feed_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:dtvss="{RSS_NAMESPACE}">
  <channel>
    <title>DTVSS Tier 2 Feed - {xml_escape(customer.organisation)}</title>
    <link>https://dtvss.io/</link>
    <description>{channel_description}</description>
    <language>en-AU</language>
    <lastBuildDate>{xml_escape(last_build_date)}</lastBuildDate>
    <ttl>5</ttl>
{items_xml}
  </channel>
</rss>
"""
    return feed_xml


# ---------------------------------------------------------------------------
# Flask view (called by app.py route)
# ---------------------------------------------------------------------------
# The route registration lives in app.py to keep all route declarations
# in one place; this view function is the body.
def tier2_rss_feed_view() -> Any:
    """View function for GET /rss/feed/<token>.xml.

    @require_tier2 has already validated the token and set g.customer.
    Returns the RSS XML with appropriate caching headers per the
    design spec (Cache-Control: max-age=300).
    """
    from flask import Response, g

    customer = g.customer
    feed_xml = generate_feed(customer)
    response = Response(feed_xml, mimetype="application/rss+xml")
    response.headers["Cache-Control"] = "private, max-age=300"
    # Last-Modified per spec - matches feed generation time
    response.headers["Last-Modified"] = format_datetime(datetime.now(UTC))
    return response
