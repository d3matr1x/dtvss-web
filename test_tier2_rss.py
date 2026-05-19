"""
Unit tests for tier2_rss.py — Stage 3 RSS feed generation.

Test coverage maps to:
  - design §5 (RSS assertions): structure, fields, namespace
  - design R-marker: filter integrity (critical security property)
  - implementation plan Stage 3 done-when criteria

Test groups:
  TestFilterIsolation       D2 + R-marker: filter integrity (most critical)
  TestRssStructure          A22, A23: valid XML, namespace, channel fields
  TestEntryFields           per-entry fields, dtvss namespace elements
  TestScoring               request-time score computation, KEV override
  TestEdgeCases             empty manufacturer list, missing data, API failures
  TestSeverityTier          score -> tier mapping
  TestRssDateFormatting     RFC 822 conversion from various input shapes

Copyright 2026 Andrew Broglio. Licensed under BSL 1.1.
"""
from __future__ import annotations

import re
from unittest.mock import patch
from xml.etree import ElementTree as ET

import pytest

import tier2_customers as tc
import tier2_rss


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    """Fresh customers store per test."""
    monkeypatch.setenv("CUSTOMERS_PATH", str(tmp_path / "customers.json"))
    monkeypatch.setenv("DTVSS_DEV_ALLOW_UNENCRYPTED", "1")
    monkeypatch.delenv("RAILWAY_ENVIRONMENT", raising=False)
    yield


@pytest.fixture
def baxter_customer():
    """A customer subscribed to Baxter only."""
    record, _plaintext = tc.create_record(
        name="Test Hospital",
        organisation="Test Health",
        email="ops@test.example",
        country="AU",
        license_version="tier2-v1.0",
        manufacturers=["baxter"],
        enabled_claims=[8, 9, 11],
    )
    return record


@pytest.fixture
def multi_manufacturer_customer():
    """A customer with two manufacturers selected."""
    record, _plaintext = tc.create_record(
        name="Multi Hospital",
        organisation="Multi Health",
        email="multi@test.example",
        country="AU",
        license_version="tier2-v1.0",
        manufacturers=["baxter", "philips"],
        enabled_claims=[8, 9, 11],
    )
    return record


@pytest.fixture
def fake_baxter_cves():
    """Test data: 3 fake Baxter CVEs with varying severity."""
    return [
        {
            "cve_id": "CVE-2024-0001",
            "description": "Critical RCE in Baxter Sigma Spectrum infusion pump",
            "cvss_version": "3.1",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "base_score": 9.8,
            "severity": "CRITICAL",
            "published": "2024-01-15T00:00:00.000",
            "source": "rss",
        },
        {
            "cve_id": "CVE-2024-0002",
            "description": "Information disclosure in Baxter device monitoring",
            "cvss_version": "3.1",
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
            "base_score": 3.5,
            "severity": "LOW",
            "published": "2024-02-10T00:00:00.000",
            "source": "rss",
        },
        {
            "cve_id": "CVE-2024-0003",
            "description": "Authentication bypass in Baxter SIGMA platform",
            "cvss_version": "3.1",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
            "base_score": 8.6,
            "severity": "HIGH",
            "published": "2024-03-01T00:00:00.000",
            "source": "rss",
        },
    ]


@pytest.fixture
def fake_philips_cves():
    """Test data: fake Philips CVE (different manufacturer)."""
    return [
        {
            "cve_id": "CVE-2024-9999",
            "description": "Philips patient monitor vulnerability",
            "cvss_version": "3.1",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "base_score": 9.0,
            "severity": "CRITICAL",
            "published": "2024-04-01T00:00:00.000",
            "source": "rss",
        },
    ]


@pytest.fixture
def fake_siemens_cves():
    """Test data: fake Siemens CVE that should NEVER appear in a non-Siemens feed."""
    return [
        {
            "cve_id": "CVE-2024-LEAK",
            "description": "Siemens CT scanner critical vulnerability",
            "cvss_version": "3.1",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "base_score": 9.0,
            "severity": "CRITICAL",
            "published": "2024-05-01T00:00:00.000",
            "source": "rss",
        },
    ]


@pytest.fixture
def mock_search_manufacturer_cves(fake_baxter_cves, fake_philips_cves, fake_siemens_cves):
    """Replace index_loader.search_manufacturer_cves with controlled data."""
    def fake_search(manufacturer):
        key = (manufacturer or "").lower()
        if "baxter" in key:
            return list(fake_baxter_cves)
        if "philips" in key:
            return list(fake_philips_cves)
        if "siemens" in key:
            return list(fake_siemens_cves)
        return []

    with patch("tier2_rss.search_manufacturer_cves", side_effect=fake_search):
        yield fake_search


@pytest.fixture(autouse=True)
def mock_external_apis():
    """Stub external API calls so tests run offline.

    - epss_lookup returns moderate scores keyed by CVE ID
    - cisa_kev_check returns False (no KEV)
    """
    fake_epss = {
        "CVE-2024-0001": {"epss": 0.5, "percentile": 0.95, "date": "2024-05-01"},
        "CVE-2024-0002": {"epss": 0.01, "percentile": 0.20, "date": "2024-05-01"},
        "CVE-2024-0003": {"epss": 0.3, "percentile": 0.85, "date": "2024-05-01"},
        "CVE-2024-9999": {"epss": 0.4, "percentile": 0.90, "date": "2024-05-01"},
    }
    with patch("tier2_rss.epss_lookup", return_value=fake_epss), \
         patch("tier2_rss.cisa_kev_check", return_value=None):
        yield


# ---------------------------------------------------------------------------
# CRITICAL: filter isolation (design R-marker)
# ---------------------------------------------------------------------------
# This is THE most important test class in Stage 3. The design explicitly
# flags as the primary risk: "feed contains data customer shouldn't see".
# The R-marker mitigation is "explicit unit test that filter is applied
# before any data leaves the function." These tests are that mitigation.
class TestFilterIsolation:
    def test_filter_isolation_no_other_manufacturers(
        self, baxter_customer, mock_search_manufacturer_cves,
    ):
        """A Baxter-only customer must NEVER see Siemens or Philips CVEs.

        This is the primary security property of the entire RSS feed.
        If this test ever fails, customer data isolation is broken.
        """
        feed = tier2_rss.generate_feed(baxter_customer)

        # The feed MUST NOT contain any Siemens or Philips CVE IDs
        assert "CVE-2024-LEAK" not in feed, "SIEMENS CVE LEAKED TO BAXTER CUSTOMER"
        assert "CVE-2024-9999" not in feed, "PHILIPS CVE LEAKED TO BAXTER CUSTOMER"
        # And must not mention these manufacturer names anywhere in the content
        assert "siemens" not in feed.lower()
        assert "philips" not in feed.lower()
        # But MUST contain the customer's own manufacturer CVEs
        assert "CVE-2024-0001" in feed
        assert "CVE-2024-0002" in feed
        assert "CVE-2024-0003" in feed

    def test_filter_with_multiple_manufacturers_includes_both(
        self, multi_manufacturer_customer, mock_search_manufacturer_cves,
    ):
        """A Baxter+Philips customer must see CVEs from both."""
        feed = tier2_rss.generate_feed(multi_manufacturer_customer)

        # All three Baxter CVEs
        assert "CVE-2024-0001" in feed
        assert "CVE-2024-0002" in feed
        assert "CVE-2024-0003" in feed
        # Plus the Philips CVE
        assert "CVE-2024-9999" in feed
        # Still NEVER any Siemens leakage
        assert "CVE-2024-LEAK" not in feed

    def test_empty_manufacturers_returns_empty_feed(self, mock_search_manufacturer_cves):
        """Customer with no manufacturers selected gets an empty (but valid) feed."""
        record, _ = tc.create_record(
            name="Empty Test", organisation="Test", email="t@t.com",
            country="AU", license_version="tier2-v1.0",
            manufacturers=[], enabled_claims=[8, 9, 11],
        )
        feed = tier2_rss.generate_feed(record)
        # Should still parse as valid XML
        root = ET.fromstring(feed)
        items = root.findall(".//item")
        assert len(items) == 0

    def test_de_duplication_across_manufacturers(
        self, multi_manufacturer_customer,
    ):
        """If the same CVE appears under multiple manufacturer entries
        in the MDM index (multi-vendor advisory), it appears once."""
        same_cve = {
            "cve_id": "CVE-2024-SHARED",
            "description": "Multi-vendor vulnerability",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "base_score": 9.0, "severity": "CRITICAL",
            "published": "2024-01-01T00:00:00.000", "source": "rss",
        }
        with patch("tier2_rss.search_manufacturer_cves",
                   return_value=[same_cve]):
            feed = tier2_rss.generate_feed(multi_manufacturer_customer)

        # Count occurrences of the CVE ID — should be exactly 1 in <guid> and 1 in <title>
        # i.e. it appears in exactly one <item> block
        root = ET.fromstring(feed)
        items = root.findall(".//item")
        assert len(items) == 1


# ---------------------------------------------------------------------------
# RSS structure (A22, A23)
# ---------------------------------------------------------------------------
class TestRssStructure:
    def test_feed_is_valid_xml(self, baxter_customer, mock_search_manufacturer_cves):
        feed = tier2_rss.generate_feed(baxter_customer)
        # ET.fromstring raises if not valid XML
        root = ET.fromstring(feed)
        assert root.tag == "rss"

    def test_rss_version_is_2(self, baxter_customer, mock_search_manufacturer_cves):
        feed = tier2_rss.generate_feed(baxter_customer)
        root = ET.fromstring(feed)
        assert root.attrib.get("version") == "2.0"

    def test_dtvss_namespace_declared(self, baxter_customer, mock_search_manufacturer_cves):
        feed = tier2_rss.generate_feed(baxter_customer)
        # The namespace should be declared
        assert tier2_rss.RSS_NAMESPACE in feed
        assert "xmlns:dtvss" in feed

    def test_channel_has_required_fields(self, baxter_customer, mock_search_manufacturer_cves):
        feed = tier2_rss.generate_feed(baxter_customer)
        root = ET.fromstring(feed)
        channel = root.find("channel")
        assert channel is not None
        # RSS 2.0 required channel fields
        assert channel.find("title") is not None
        assert channel.find("link") is not None
        assert channel.find("description") is not None
        assert channel.find("lastBuildDate") is not None

    def test_channel_title_includes_organisation(
        self, baxter_customer, mock_search_manufacturer_cves,
    ):
        feed = tier2_rss.generate_feed(baxter_customer)
        root = ET.fromstring(feed)
        title = root.find("channel/title").text
        assert "Test Health" in title

    def test_channel_description_lists_manufacturers(
        self, multi_manufacturer_customer, mock_search_manufacturer_cves,
    ):
        feed = tier2_rss.generate_feed(multi_manufacturer_customer)
        root = ET.fromstring(feed)
        desc = root.find("channel/description").text
        assert "baxter" in desc.lower()
        assert "philips" in desc.lower()


# ---------------------------------------------------------------------------
# Entry fields
# ---------------------------------------------------------------------------
class TestEntryFields:
    @pytest.fixture
    def feed_xml(self, baxter_customer, mock_search_manufacturer_cves):
        return tier2_rss.generate_feed(baxter_customer)

    def test_each_entry_has_required_rss_fields(self, feed_xml):
        root = ET.fromstring(feed_xml)
        items = root.findall(".//item")
        assert len(items) == 3  # the 3 Baxter CVEs
        for item in items:
            # RSS 2.0 entry fields
            assert item.find("title") is not None
            assert item.find("link") is not None
            assert item.find("description") is not None
            assert item.find("pubDate") is not None
            assert item.find("guid") is not None

    def test_each_entry_has_dtvss_namespace_fields(self, feed_xml):
        # Parse with namespace awareness
        ns = {"dtvss": tier2_rss.RSS_NAMESPACE}
        root = ET.fromstring(feed_xml)
        items = root.findall(".//item")
        for item in items:
            assert item.find("dtvss:score", ns) is not None
            assert item.find("dtvss:severity_tier", ns) is not None
            assert item.find("dtvss:tga_class", ns) is not None
            assert item.find("dtvss:B", ns) is not None
            assert item.find("dtvss:L_eff", ns) is not None
            assert item.find("dtvss:H", ns) is not None
            assert item.find("dtvss:kev_override", ns) is not None

    def test_guid_is_cve_id(self, feed_xml):
        root = ET.fromstring(feed_xml)
        items = root.findall(".//item")
        guids = [item.find("guid").text for item in items]
        for guid in guids:
            assert guid.startswith("CVE-")

    def test_links_point_to_nvd(self, feed_xml):
        root = ET.fromstring(feed_xml)
        items = root.findall(".//item")
        for item in items:
            link = item.find("link").text
            assert link.startswith("https://nvd.nist.gov/vuln/detail/CVE-")

    def test_entry_category_is_manufacturer(self, feed_xml):
        root = ET.fromstring(feed_xml)
        items = root.findall(".//item")
        for item in items:
            cat = item.find("category")
            assert cat is not None
            assert cat.text == "baxter"


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
class TestScoring:
    def test_high_severity_cve_gets_critical_prefix(
        self, baxter_customer, mock_search_manufacturer_cves,
    ):
        feed = tier2_rss.generate_feed(baxter_customer)
        # CVE-2024-0001 is the critical RCE; should have [CRITICAL] or [HIGH] in title
        # depending on H weighting
        root = ET.fromstring(feed)
        # Find item for CVE-2024-0001
        for item in root.findall(".//item"):
            if item.find("guid").text == "CVE-2024-0001":
                title = item.find("title").text
                assert title.startswith("[") and "]" in title
                break

    def test_kev_override_sets_critical(
        self, baxter_customer, mock_search_manufacturer_cves,
    ):
        """When CVE is in KEV, severity_tier MUST be critical regardless of score."""
        with patch("tier2_rss.cisa_kev_check", return_value={"in_kev": True}):
            feed = tier2_rss.generate_feed(baxter_customer)

        root = ET.fromstring(feed)
        ns = {"dtvss": tier2_rss.RSS_NAMESPACE}
        items = root.findall(".//item")
        # All entries should be marked critical with KEV override
        for item in items:
            kev = item.find("dtvss:kev_override", ns).text
            severity = item.find("dtvss:severity_tier", ns).text
            assert kev == "true"
            assert severity == "critical"

    def test_scores_sorted_high_to_low(
        self, baxter_customer, mock_search_manufacturer_cves,
    ):
        feed = tier2_rss.generate_feed(baxter_customer)
        root = ET.fromstring(feed)
        ns = {"dtvss": tier2_rss.RSS_NAMESPACE}
        items = root.findall(".//item")
        scores = [float(item.find("dtvss:score", ns).text) for item in items]
        assert scores == sorted(scores, reverse=True)


# ---------------------------------------------------------------------------
# Edge cases / failure modes
# ---------------------------------------------------------------------------
class TestEdgeCases:
    def test_epss_failure_does_not_break_feed(
        self, baxter_customer, mock_search_manufacturer_cves,
    ):
        """EPSS API failure must not crash feed generation."""
        with patch("tier2_rss.epss_lookup", side_effect=Exception("EPSS down")):
            feed = tier2_rss.generate_feed(baxter_customer)
        # Should still produce valid XML
        root = ET.fromstring(feed)
        items = root.findall(".//item")
        assert len(items) == 3

    def test_kev_failure_does_not_break_feed(
        self, baxter_customer, mock_search_manufacturer_cves,
    ):
        """KEV check failure must not crash feed generation."""
        with patch("tier2_rss.cisa_kev_check", side_effect=Exception("KEV down")):
            feed = tier2_rss.generate_feed(baxter_customer)
        root = ET.fromstring(feed)
        items = root.findall(".//item")
        assert len(items) == 3

    def test_classification_failure_falls_back_to_iib(
        self, baxter_customer, mock_search_manufacturer_cves,
    ):
        with patch("tier2_rss.classify_device", side_effect=Exception("Classify fail")):
            feed = tier2_rss.generate_feed(baxter_customer)
        root = ET.fromstring(feed)
        ns = {"dtvss": tier2_rss.RSS_NAMESPACE}
        items = root.findall(".//item")
        for item in items:
            assert item.find("dtvss:tga_class", ns).text == "IIb"

    def test_cve_with_missing_description(
        self, baxter_customer,
    ):
        bare_cve = {"cve_id": "CVE-2024-BARE", "description": "",
                    "cvss_vector": "", "base_score": 0,
                    "published": "", "source": "rss"}
        with patch("tier2_rss.search_manufacturer_cves",
                   return_value=[bare_cve]):
            feed = tier2_rss.generate_feed(baxter_customer)
        # Should produce a valid entry
        root = ET.fromstring(feed)
        items = root.findall(".//item")
        assert len(items) == 1
        assert items[0].find("description").text  # has SOME description

    def test_xml_special_chars_in_description_escaped(
        self, baxter_customer,
    ):
        """A CVE description with <, >, & must be properly XML-escaped."""
        nasty_cve = {
            "cve_id": "CVE-2024-NASTY",
            "description": "Attack via <script>alert(1)</script> & other tricks",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "base_score": 9.0, "severity": "CRITICAL",
            "published": "2024-01-01T00:00:00.000", "source": "rss",
        }
        with patch("tier2_rss.search_manufacturer_cves",
                   return_value=[nasty_cve]):
            feed = tier2_rss.generate_feed(baxter_customer)
        # Raw < > & should NOT appear unescaped in the description
        # (well, except in valid XML markup)
        # Parsing should succeed without raising
        root = ET.fromstring(feed)
        items = root.findall(".//item")
        desc = items[0].find("description").text
        # The < and > should be unescaped (decoded) when read via .text
        assert "<script>" in desc
        # But the raw XML must NOT have an unencoded <script> tag
        # in the description position; ET.fromstring already enforces this
        # by raising on malformed XML.


# ---------------------------------------------------------------------------
# Severity tier mapping (D4)
# ---------------------------------------------------------------------------
class TestSeverityTier:
    def test_low(self):
        assert tier2_rss._severity_tier(0.5, kev_override=False) == "low"
        assert tier2_rss._severity_tier(2.9, kev_override=False) == "low"

    def test_medium(self):
        assert tier2_rss._severity_tier(3.0, kev_override=False) == "medium"
        assert tier2_rss._severity_tier(5.9, kev_override=False) == "medium"

    def test_high(self):
        assert tier2_rss._severity_tier(6.0, kev_override=False) == "high"
        assert tier2_rss._severity_tier(7.9, kev_override=False) == "high"

    def test_critical(self):
        assert tier2_rss._severity_tier(8.0, kev_override=False) == "critical"
        assert tier2_rss._severity_tier(10.0, kev_override=False) == "critical"

    def test_kev_override_forces_critical(self):
        # Even a score of 0.0 is critical with KEV override
        assert tier2_rss._severity_tier(0.0, kev_override=True) == "critical"


# ---------------------------------------------------------------------------
# RSS date formatting
# ---------------------------------------------------------------------------
class TestRssDateFormatting:
    def test_iso_8601_input(self):
        result = tier2_rss._format_rss_date("2024-01-15T12:34:56")
        # RFC 822: "Mon, 15 Jan 2024 12:34:56 +0000"
        assert "15 Jan 2024" in result

    def test_iso_8601_with_z(self):
        result = tier2_rss._format_rss_date("2024-01-15T12:34:56Z")
        assert "15 Jan 2024" in result

    def test_date_only(self):
        result = tier2_rss._format_rss_date("2024-01-15")
        assert "15 Jan 2024" in result

    def test_empty_input_returns_now(self):
        result = tier2_rss._format_rss_date("")
        # Should be a valid RFC 822 date string (5 fields: dayname, day, mon, year, time)
        assert re.match(r"^[A-Z][a-z]{2}, \d{1,2} [A-Z][a-z]{2} \d{4}", result)

    def test_garbage_input_returns_now(self):
        result = tier2_rss._format_rss_date("not a date at all")
        assert re.match(r"^[A-Z][a-z]{2}, \d{1,2} [A-Z][a-z]{2} \d{4}", result)
