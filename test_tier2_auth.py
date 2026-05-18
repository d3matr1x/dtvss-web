"""
Unit tests for tier2_auth.py — the Stage 2 RSS authentication middleware.

Coverage maps to design §5.2 assertions A5–A10 plus the path-handling
edge cases called out as the Stage 2 risk:

    A5  Valid token returns customer record       → test_valid_token_*
    A6  Expired customer returns 404              → test_expired_*
    A7  Revoked customer returns 404              → test_revoked_*
    A8  Malformed token returns 404 without DB    → test_malformed_*
    A9  Missing token returns 404                 → test_missing_*
    A10 Token replay permitted (rate limit only)  → test_replay_*

Plus security-specific:
    test_token_regex_*           — character class, length, null byte
    test_audit_log_*             — JSON Lines format, append semantics
    test_sentry_*                — failure events fire with correct level
    test_rate_limit_key_*        — keying by customer, not IP

Test isolation: each test gets a fresh customers.json and a fresh audit
log via tmp_path, with monkeypatched env vars. No test touches real
production paths.

Copyright 2026 Andrew Broglio. Licensed under BSL 1.1.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from flask import Flask, g

import tier2_customers as tc
import tier2_auth


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    """Every test runs against a fresh tmp customers file + audit log."""
    customers_file = tmp_path / "customers.json"
    audit_file = tmp_path / "audit" / "access.log"

    monkeypatch.setenv("CUSTOMERS_PATH", str(customers_file))
    monkeypatch.setenv("DTVSS_AUDIT_LOG_PATH", str(audit_file))
    monkeypatch.setenv("DTVSS_DEV_ALLOW_UNENCRYPTED", "1")
    monkeypatch.delenv("RAILWAY_ENVIRONMENT", raising=False)
    monkeypatch.delenv("SENTRY_DSN", raising=False)

    yield {"customers": customers_file, "audit": audit_file}


@pytest.fixture
def app():
    """Minimal Flask app with the Tier 2 endpoint wired up."""
    app = Flask(__name__)
    app.config["TESTING"] = True

    @app.route("/tier2/ping/<token>")
    @tier2_auth.require_tier2
    def ping():
        return tier2_auth.tier2_ping_view()

    @app.route("/rss/feed/<token>.xml")
    @tier2_auth.require_tier2
    def feed():
        return f"<rss>{g.customer.id}</rss>", 200, {"Content-Type": "application/rss+xml"}

    return app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def active_customer():
    """Create an active Tier 2 customer; return (record, plaintext_token)."""
    record, plaintext = tc.create_record(
        name="Acme Hospital",
        organisation="Acme Health",
        email="ops@acme.example",
        country="AU",
        license_version="tier2-v1.0",
        manufacturers=["baxter", "philips"],
        enabled_claims=[8, 9, 11],
    )
    return record, plaintext


# ---------------------------------------------------------------------------
# A8: Token regex — refuses malformed input without a DB hit
# ---------------------------------------------------------------------------
class TestTokenRegex:
    def test_correct_length_passes(self):
        # secrets.token_urlsafe(32) produces 43 chars
        valid = "A" * 43
        assert tier2_auth.is_well_formed_token(valid)

    def test_wrong_length_42_rejected(self):
        assert not tier2_auth.is_well_formed_token("A" * 42)

    def test_wrong_length_44_rejected(self):
        assert not tier2_auth.is_well_formed_token("A" * 44)

    def test_empty_rejected(self):
        assert not tier2_auth.is_well_formed_token("")

    def test_none_rejected(self):
        assert not tier2_auth.is_well_formed_token(None)

    def test_non_string_rejected(self):
        assert not tier2_auth.is_well_formed_token(12345)  # type: ignore[arg-type]
        assert not tier2_auth.is_well_formed_token(b"A" * 43)  # type: ignore[arg-type]

    def test_null_byte_rejected(self):
        # Null byte injection — a real concern on systems that pass through
        # to filesystem operations elsewhere in the stack.
        assert not tier2_auth.is_well_formed_token("A" * 42 + "\x00")

    def test_path_traversal_chars_rejected(self):
        # '/' and '.' are not in the urlsafe base64 alphabet
        assert not tier2_auth.is_well_formed_token("../" + "A" * 40)
        assert not tier2_auth.is_well_formed_token("." * 43)

    def test_percent_encoding_rejected(self):
        # '%' is not in the alphabet — percent-encoded payloads can't match
        assert not tier2_auth.is_well_formed_token("%41" + "A" * 40)

    def test_only_urlsafe_base64_chars(self):
        # Real generated tokens have A-Z a-z 0-9 _ -
        import secrets
        real_token = secrets.token_urlsafe(32)
        assert tier2_auth.is_well_formed_token(real_token)
        assert len(real_token) == 43

    def test_other_charsets_rejected(self):
        # '+' is base64 standard but not urlsafe; '/' likewise
        assert not tier2_auth.is_well_formed_token("+" + "A" * 42)
        assert not tier2_auth.is_well_formed_token("/" + "A" * 42)
        assert not tier2_auth.is_well_formed_token("=" + "A" * 42)


# ---------------------------------------------------------------------------
# A5: Valid token success path
# ---------------------------------------------------------------------------
class TestValidToken:
    def test_valid_token_200(self, client, active_customer):
        _, plaintext = active_customer
        resp = client.get(f"/tier2/ping/{plaintext}")
        assert resp.status_code == 200

    def test_valid_token_returns_customer_id(self, client, active_customer):
        record, plaintext = active_customer
        resp = client.get(f"/tier2/ping/{plaintext}")
        body = resp.get_json()
        assert body["ok"] is True
        assert body["customer_id"] == record.id
        assert body["status"] == "active"
        assert body["manufacturers"] == ["baxter", "philips"]
        assert body["tier"] == "tier2"

    def test_valid_token_on_rss_route(self, client, active_customer):
        record, plaintext = active_customer
        resp = client.get(f"/rss/feed/{plaintext}.xml")
        assert resp.status_code == 200
        assert resp.content_type.startswith("application/rss+xml")
        assert record.id in resp.get_data(as_text=True)

    def test_valid_token_sets_g_customer(self, app, active_customer):
        record, plaintext = active_customer

        @app.route("/probe/<token>")
        @tier2_auth.require_tier2
        def probe():
            return {"id": g.customer.id, "email": g.customer.email}

        with app.test_client() as c:
            resp = c.get(f"/probe/{plaintext}")
            assert resp.status_code == 200
            body = resp.get_json()
            assert body["id"] == record.id
            assert body["email"] == "ops@acme.example"


# ---------------------------------------------------------------------------
# A9: Missing token → 404
# ---------------------------------------------------------------------------
class TestMissingToken:
    def test_no_token_kwarg_404s(self, app):
        # Route that doesn't capture <token> at all
        @app.route("/broken")
        @tier2_auth.require_tier2
        def broken():
            return "should not run"

        with app.test_client() as c:
            resp = c.get("/broken")
            assert resp.status_code == 404


# ---------------------------------------------------------------------------
# A8: Malformed token → 404 without DB hit
# ---------------------------------------------------------------------------
class TestMalformedToken:
    def test_short_token_404(self, client):
        resp = client.get("/tier2/ping/short")
        assert resp.status_code == 404

    def test_long_token_404(self, client):
        resp = client.get("/tier2/ping/" + "A" * 200)
        assert resp.status_code == 404

    def test_special_chars_404(self, client):
        # Flask's path converter rejects '/' in the segment, so we use the
        # URL-encoded form to get the bytes to our handler. The decorator
        # MUST 404 these.
        resp = client.get("/tier2/ping/" + "@" * 43)
        assert resp.status_code == 404

    def test_malformed_does_not_call_validate_token(self, client):
        """The pre-flight regex must reject malformed tokens BEFORE any
        DB lookup happens. This is a security property: a bombardment of
        malformed requests should not be able to slow the DB down."""
        with patch("tier2_auth.validate_token") as mock_validate:
            resp = client.get("/tier2/ping/" + "@" * 43)
            assert resp.status_code == 404
            mock_validate.assert_not_called()

    def test_wrong_length_does_not_call_validate_token(self, client):
        with patch("tier2_auth.validate_token") as mock_validate:
            resp = client.get("/tier2/ping/" + "A" * 30)
            assert resp.status_code == 404
            mock_validate.assert_not_called()


# ---------------------------------------------------------------------------
# A6: Expired customer → 404
# ---------------------------------------------------------------------------
class TestExpiredCustomer:
    def test_expired_returns_404(self, client, active_customer):
        record, plaintext = active_customer
        # Push expires_at into the past
        tc.update_record(record.id, expires_at="2020-01-01T00:00:00Z")
        resp = client.get(f"/tier2/ping/{plaintext}")
        assert resp.status_code == 404

    def test_expired_does_not_leak_in_body(self, client, active_customer):
        record, plaintext = active_customer
        tc.update_record(record.id, expires_at="2020-01-01T00:00:00Z")
        resp = client.get(f"/tier2/ping/{plaintext}")
        # 404 must not leak that the token *was* valid pre-expiry
        body = resp.get_data(as_text=True)
        assert record.id not in body
        assert "expired" not in body.lower()


# ---------------------------------------------------------------------------
# A7: Revoked customer → 404
# ---------------------------------------------------------------------------
class TestRevokedCustomer:
    def test_revoked_returns_404(self, client, active_customer):
        record, plaintext = active_customer
        tc.revoke_record(record.id, reason="test revocation")
        resp = client.get(f"/tier2/ping/{plaintext}")
        assert resp.status_code == 404

    def test_suspended_returns_404(self, client, active_customer):
        record, plaintext = active_customer
        tc.suspend_record(record.id, reason="test suspension")
        resp = client.get(f"/tier2/ping/{plaintext}")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# A10: Token replay (RSS readers poll repeatedly) — permitted
# ---------------------------------------------------------------------------
class TestTokenReplay:
    def test_same_token_works_repeatedly(self, client, active_customer):
        _, plaintext = active_customer
        # 10 sequential hits — should all succeed (no rate limit yet at
        # this layer; Flask-Limiter integration is at the route level)
        for _ in range(10):
            resp = client.get(f"/tier2/ping/{plaintext}")
            assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------
class TestAuditLog:
    def test_successful_access_writes_audit_line(
        self, client, active_customer, isolated_env
    ):
        record, plaintext = active_customer
        client.get(f"/tier2/ping/{plaintext}")
        audit = isolated_env["audit"]
        assert audit.exists()
        lines = audit.read_text().strip().split("\n")
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["customer_id"] == record.id
        # Route is the URL rule pattern, not the concrete URL with the token
        assert "<token>" in entry["route"]
        assert "/tier2/ping/" in entry["route"]
        assert entry["method"] == "GET"
        assert "ts" in entry
        # ISO 8601 UTC format check
        assert entry["ts"].endswith("Z")
        assert "T" in entry["ts"]

    def test_failed_access_does_not_write_audit_line(
        self, client, isolated_env
    ):
        client.get("/tier2/ping/" + "A" * 43)  # unknown but well-formed
        audit = isolated_env["audit"]
        # Either file doesn't exist, or it's empty. Failed validations go
        # to Sentry, not the audit log.
        if audit.exists():
            assert audit.read_text() == ""

    def test_audit_log_is_jsonl_format(self, client, active_customer, isolated_env):
        _, plaintext = active_customer
        for _ in range(3):
            client.get(f"/tier2/ping/{plaintext}")
        audit = isolated_env["audit"]
        lines = audit.read_text().strip().split("\n")
        assert len(lines) == 3
        for line in lines:
            entry = json.loads(line)  # each line is self-contained JSON
            assert "ts" in entry
            assert "customer_id" in entry

    def test_audit_log_never_contains_plaintext_token(
        self, client, active_customer, isolated_env
    ):
        _, plaintext = active_customer
        client.get(f"/tier2/ping/{plaintext}")
        audit_text = isolated_env["audit"].read_text()
        # Plaintext token must never appear
        assert plaintext not in audit_text
        # But the route pattern (with placeholder) should
        entry = json.loads(audit_text.strip())
        assert "<token>" in entry["route"]

    def test_audit_log_writes_directory_if_missing(
        self, tmp_path, monkeypatch, client, active_customer
    ):
        # Wipe and use a deeper missing-parent path
        deep_path = tmp_path / "a" / "b" / "c" / "access.log"
        monkeypatch.setenv("DTVSS_AUDIT_LOG_PATH", str(deep_path))
        _, plaintext = active_customer
        client.get(f"/tier2/ping/{plaintext}")
        assert deep_path.exists()

    def test_audit_failure_does_not_break_request(
        self, client, active_customer, tmp_path, monkeypatch
    ):
        # Point audit log at something we can't write (a directory)
        bad_path = tmp_path / "blocked"
        bad_path.mkdir()
        monkeypatch.setenv("DTVSS_AUDIT_LOG_PATH", str(bad_path))
        _, plaintext = active_customer
        # Customer request must still succeed
        resp = client.get(f"/tier2/ping/{plaintext}")
        assert resp.status_code == 200


class TestAuditPath:
    def test_explicit_override_wins(self, monkeypatch, tmp_path):
        target = str(tmp_path / "x.log")
        monkeypatch.setenv("DTVSS_AUDIT_LOG_PATH", target)
        monkeypatch.setenv("RAILWAY_ENVIRONMENT", "production")
        assert str(tier2_auth.audit_log_path()) == target

    def test_railway_default(self, monkeypatch):
        monkeypatch.delenv("DTVSS_AUDIT_LOG_PATH", raising=False)
        monkeypatch.setenv("RAILWAY_ENVIRONMENT", "production")
        assert tier2_auth.audit_log_path() == Path("/data/audit/access.log")

    def test_dev_default(self, monkeypatch):
        monkeypatch.delenv("DTVSS_AUDIT_LOG_PATH", raising=False)
        monkeypatch.delenv("RAILWAY_ENVIRONMENT", raising=False)
        assert tier2_auth.audit_log_path() == Path("private/audit/access.log")


# ---------------------------------------------------------------------------
# Sentry failure reporting
# ---------------------------------------------------------------------------
class TestSentryReporting:
    def test_malformed_token_fires_sentry_warning(
        self, client, monkeypatch
    ):
        monkeypatch.setenv("SENTRY_DSN", "https://fake@example.com/1")
        captured: list[dict] = []

        def fake_capture(msg, level=None):
            captured.append({"msg": msg, "level": level})

        class FakeScope:
            def set_tag(self, *a, **kw): pass
            def set_extra(self, *a, **kw): pass

        class FakeContext:
            def __enter__(self): return FakeScope()
            def __exit__(self, *a): return False

        fake_sentry = type("S", (), {
            "push_scope": lambda *a, **kw: FakeContext(),
            "capture_message": staticmethod(fake_capture),
        })

        with patch.dict("sys.modules", {"sentry_sdk": fake_sentry}):
            client.get("/tier2/ping/" + "@" * 43)

        assert len(captured) == 1
        assert captured[0]["level"] == "warning"
        assert "malformed" in captured[0]["msg"]

    def test_unknown_token_fires_sentry_warning(self, client, monkeypatch):
        monkeypatch.setenv("SENTRY_DSN", "https://fake@example.com/1")
        captured: list[dict] = []

        def fake_capture(msg, level=None):
            captured.append({"msg": msg, "level": level})

        class FakeScope:
            def set_tag(self, *a, **kw): pass
            def set_extra(self, *a, **kw): pass

        class FakeContext:
            def __enter__(self): return FakeScope()
            def __exit__(self, *a): return False

        fake_sentry = type("S", (), {
            "push_scope": lambda *a, **kw: FakeContext(),
            "capture_message": staticmethod(fake_capture),
        })

        with patch.dict("sys.modules", {"sentry_sdk": fake_sentry}):
            client.get("/tier2/ping/" + "A" * 43)  # well-formed but unknown

        assert len(captured) == 1
        assert captured[0]["level"] == "warning"

    def test_no_sentry_dsn_falls_back_to_stderr(
        self, client, monkeypatch, caplog
    ):
        monkeypatch.delenv("SENTRY_DSN", raising=False)
        # Set log level so the warning isn't filtered out
        import logging
        with caplog.at_level(logging.WARNING, logger="tier2_auth"):
            client.get("/tier2/ping/" + "@" * 43)
        assert any("auth failure" in r.message.lower() for r in caplog.records)

    def test_sentry_event_never_contains_full_token(
        self, client, monkeypatch
    ):
        monkeypatch.setenv("SENTRY_DSN", "https://fake@example.com/1")
        captured_extras: list[str] = []

        class FakeScope:
            def set_tag(self, *a, **kw): pass
            def set_extra(self, key, value):
                captured_extras.append(f"{key}={value}")

        class FakeContext:
            def __enter__(self): return FakeScope()
            def __exit__(self, *a): return False

        fake_sentry = type("S", (), {
            "push_scope": lambda *a, **kw: FakeContext(),
            "capture_message": lambda *a, **kw: None,
        })

        token = "Z" * 43
        with patch.dict("sys.modules", {"sentry_sdk": fake_sentry}):
            client.get(f"/tier2/ping/{token}")

        # The full token must NOT appear anywhere in the extras
        all_extras = "\n".join(captured_extras)
        assert token not in all_extras
        # But the prefix should, for diagnostics
        assert "token_prefix=ZZZZZZZZ" in all_extras


# ---------------------------------------------------------------------------
# Rate limiting key
# ---------------------------------------------------------------------------
class TestRateLimitKey:
    def test_key_uses_customer_id_when_validated(self, app, active_customer):
        record, plaintext = active_customer
        with app.test_request_context(f"/rss/feed/{plaintext}.xml"):
            g.customer = record
            key = tier2_auth.tier2_rate_limit_key()
            assert key == f"tier2:{record.id}"

    def test_key_uses_token_prefix_before_validation(self, app):
        token = "ABCDEFGHIJ" * 4 + "ABC"  # 43 chars
        # Simulate Flask having set view_args before the view runs
        with app.test_request_context(f"/rss/feed/{token}.xml"):
            from flask import request as flask_request
            flask_request.view_args = {"token": token}
            key = tier2_auth.tier2_rate_limit_key()
            assert key.startswith("tier2:tok:")
            assert "ABCDEFGH" in key  # first 8 chars

    def test_key_falls_back_to_ip_when_no_token(self, app):
        with app.test_request_context("/"):
            key = tier2_auth.tier2_rate_limit_key()
            assert key.startswith("tier2:ip:")

    def test_rate_limit_default_is_60_per_hour(self):
        assert tier2_auth.TIER2_RATE_LIMIT == "60 per hour"


# ---------------------------------------------------------------------------
# Token prefix helper (sanity)
# ---------------------------------------------------------------------------
class TestTokenPrefix:
    def test_prefix_is_8_chars(self):
        assert tier2_auth._token_prefix("A" * 43) == "AAAAAAAA"

    def test_prefix_of_none(self):
        assert tier2_auth._token_prefix(None) == ""

    def test_prefix_of_empty(self):
        assert tier2_auth._token_prefix("") == ""

    def test_prefix_shorter_than_8(self):
        assert tier2_auth._token_prefix("abc") == "abc"


# ---------------------------------------------------------------------------
# Client IP sanitisation (closes CodeQL py/log-injection)
# ---------------------------------------------------------------------------
class TestClientIPSanitisation:
    """The _client_ip() helper must return only valid IPv4/IPv6 literals,
    or the literal string "unknown". Anything else is a log-injection
    vector — see ADR-002 D5 and the CodeQL finding.
    """

    def _ip_with_mocked_remote_addr(self, app, value):
        """Helper: simulate request.remote_addr = value and call _client_ip."""
        with app.test_request_context("/"):
            with patch.object(
                __import__("flask").request.__class__, "remote_addr",
                new_callable=lambda: value,
            ):
                # Easier: just patch the attribute via a wrapper context
                pass

    def test_valid_ipv4_passes_through(self, app):
        from flask import request as flask_request
        with app.test_request_context("/", environ_overrides={"REMOTE_ADDR": "192.168.1.1"}):
            assert tier2_auth._client_ip() == "192.168.1.1"

    def test_valid_ipv6_canonicalised(self, app):
        # 2001:0db8::0001 → 2001:db8::1 (canonical form)
        with app.test_request_context("/", environ_overrides={"REMOTE_ADDR": "2001:0db8::0001"}):
            assert tier2_auth._client_ip() == "2001:db8::1"

    def test_loopback_passes(self, app):
        with app.test_request_context("/", environ_overrides={"REMOTE_ADDR": "127.0.0.1"}):
            assert tier2_auth._client_ip() == "127.0.0.1"

    def test_newline_injection_rejected(self, app):
        # The classic log-injection payload
        with app.test_request_context("/", environ_overrides={
            "REMOTE_ADDR": "1.2.3.4\nINJECTED: fake audit entry"
        }):
            assert tier2_auth._client_ip() == "unknown"

    def test_crlf_injection_rejected(self, app):
        with app.test_request_context("/", environ_overrides={
            "REMOTE_ADDR": "1.2.3.4\r\nHost: evil.com"
        }):
            assert tier2_auth._client_ip() == "unknown"

    def test_null_byte_rejected(self, app):
        with app.test_request_context("/", environ_overrides={
            "REMOTE_ADDR": "1.2.3.4\x00garbage"
        }):
            assert tier2_auth._client_ip() == "unknown"

    def test_ansi_escape_rejected(self, app):
        # ANSI escape sequences in a terminal log would clear screen / move cursor
        with app.test_request_context("/", environ_overrides={
            "REMOTE_ADDR": "1.2.3.4\x1b[2J"
        }):
            assert tier2_auth._client_ip() == "unknown"

    def test_hostname_rejected(self, app):
        # A hostname is not an IP literal; reject it.
        with app.test_request_context("/", environ_overrides={
            "REMOTE_ADDR": "evil.example.com"
        }):
            assert tier2_auth._client_ip() == "unknown"

    def test_empty_falls_back_to_unknown(self, app):
        with app.test_request_context("/", environ_overrides={"REMOTE_ADDR": ""}):
            assert tier2_auth._client_ip() == "unknown"

    def test_garbage_rejected(self, app):
        with app.test_request_context("/", environ_overrides={
            "REMOTE_ADDR": "this is not an IP"
        }):
            assert tier2_auth._client_ip() == "unknown"


# ---------------------------------------------------------------------------
# Regression: views must NOT declare `token` in their signature
# ---------------------------------------------------------------------------
# Captured production bug 2026-05-18: app.py declared `def tier2_ping(token):`
# which raised TypeError because @require_tier2 pops `token` from kwargs
# before calling the view. This test documents the contract.
class TestViewSignatureContract:
    def test_view_without_token_param_works(self, app, active_customer):
        """Views must NOT declare `token` — the decorator pops it."""
        record, plaintext = active_customer
        # Route already registered in fixture as `def ping():` (no token param)
        resp = app.test_client().get(f"/tier2/ping/{plaintext}")
        assert resp.status_code == 200

    def test_view_with_token_param_raises_typeerror(self, app, active_customer):
        """If a view DOES declare `token`, the decorator's kwargs.pop()
        leaves nothing to pass, and Python raises TypeError. This test
        documents that contract so it shows up in test output if anyone
        re-introduces the bug. In production, Flask catches the TypeError
        and serves a 500; in test mode (TESTING=True) the exception
        propagates and pytest catches it via pytest.raises."""
        record, plaintext = active_customer

        @app.route("/tier2/buggy/<token>")
        @tier2_auth.require_tier2
        def buggy_view(token):  # WRONG — declares token
            return "should never reach here"

        # In test mode the TypeError propagates rather than being converted
        # to a 500 response. Either way, the bug surfaces clearly.
        with pytest.raises(TypeError, match="missing 1 required positional argument"):
            app.test_client().get(f"/tier2/buggy/{plaintext}")
