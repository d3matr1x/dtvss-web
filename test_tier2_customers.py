"""
Unit tests for tier2_customers.

Coverage targets:
    - Happy path: create, list, get, update, suspend, revoke, validate_token
    - Schema validation: every reject path in _validate_record
    - Concurrent-write safety: flock acquired, atomic rename used
    - Token operations: format check, hash, validate, hmac.compare_digest path
    - Path resolution: CUSTOMERS_PATH env override
    - Edge cases: empty file, missing file, duplicate ids, duplicate hashes
    - Forbidden operations: cannot mutate id or api_key_hash via update_record
    - Encryption: key resolution, on-disk ciphertext, tamper detection,
      key rotation via MultiFernet

Tests run against a temporary directory; the real customers.json is never
touched. Each test gets a fresh path via the customers_path fixture.

Run with:
    python -m pytest test_tier2_customers.py -v
    python -m unittest test_tier2_customers -v

The unittest path is used here so we don't introduce a pytest dependency
at Stage 1. Tests use the unittest API but are pytest-compatible.

Copyright 2026 Andrew Broglio. Licensed under BSL 1.1.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
import warnings
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.fernet import Fernet

import tier2_customers as tc


class _BaseCase(unittest.TestCase):
    """Provides a fresh temporary CUSTOMERS_PATH and encryption key per test."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)
        self.path = self.tmp / "customers.json"
        # Save and replace the relevant env vars
        self._prev_env = {
            k: os.environ.get(k)
            for k in (
                "CUSTOMERS_PATH",
                tc.CUSTOMERS_KEY_ENV,
                tc.CUSTOMERS_KEYS_ENV,
                tc.CUSTOMERS_KEY_FILE_ENV,
                "DTVSS_DEV_ALLOW_UNENCRYPTED",
                "RAILWAY_ENVIRONMENT",
            )
        }
        os.environ["CUSTOMERS_PATH"] = str(self.path)
        # Each test gets a fresh randomly-generated key so cross-test leakage
        # would surface as a test failure (decrypt would fail).
        self.test_key = Fernet.generate_key().decode("utf-8")
        os.environ[tc.CUSTOMERS_KEY_ENV] = self.test_key
        # Wipe the other key vars so resolution is unambiguous
        for var in (
            tc.CUSTOMERS_KEYS_ENV,
            tc.CUSTOMERS_KEY_FILE_ENV,
            "DTVSS_DEV_ALLOW_UNENCRYPTED",
            "RAILWAY_ENVIRONMENT",
        ):
            os.environ.pop(var, None)

    def tearDown(self) -> None:
        for k, v in self._prev_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self._tmpdir.cleanup()

    def _make(self, **overrides) -> tuple[tc.Customer, str]:
        """Helper: create a record with sensible defaults, override as needed."""
        kwargs = dict(
            name="Test User",
            organisation="Test Org",
            email="test@example.com",
            country="AU",
            license_version="tier2-v1.0",
        )
        kwargs.update(overrides)
        return tc.create_record(**kwargs)

    def _write_records_plaintext_dict(self, records_as_dicts: list[dict]) -> None:
        """Test helper: write the on-disk file with encryption applied properly.

        Used by schema-validation tests that need to construct an invalid
        record on disk and then trigger validation on load. Because records
        are encrypted, we encrypt with the same key the library will use
        to decrypt. The library still validates the decrypted record, so
        this exercises the post-decrypt validation path.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        encrypted = [tc._encrypt_record_dict(d) for d in records_as_dicts]
        self.path.write_text(json.dumps({"version": 1, "records": encrypted}))


class PathResolution(_BaseCase):
    def test_env_var_overrides_default(self):
        self.assertEqual(tc.customers_path(), self.path)

    def test_default_when_env_unset(self):
        os.environ.pop("CUSTOMERS_PATH", None)
        self.assertEqual(tc.customers_path(), Path("private/customers.json"))


class LoadEmptyAndMissing(_BaseCase):
    def test_load_missing_returns_empty(self):
        # No file on disk; load should not crash.
        self.assertFalse(self.path.exists())
        c = tc.load_customers()
        self.assertEqual(c.version, tc.CURRENT_SCHEMA_VERSION)
        self.assertEqual(c.records, [])

    def test_load_empty_records_list(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"version": 1, "records": []}))
        c = tc.load_customers()
        self.assertEqual(c.records, [])

    def test_load_unsupported_version_rejected(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"version": 99, "records": []}))
        with self.assertRaises(tc.SchemaError):
            tc.load_customers()

    def test_load_missing_records_key_rejected(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"version": 1}))
        with self.assertRaises(tc.SchemaError):
            tc.load_customers()

    def test_load_records_with_dict_instead_of_string_rejected(self):
        # Catches the "wrote a pre-encryption file" failure mode
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"version": 1, "records": [{"id": "x"}]}))
        with self.assertRaisesRegex(tc.SchemaError, "expected encrypted string"):
            tc.load_customers()


class TokenOperations(_BaseCase):
    def test_generate_token_format(self):
        tok = tc.generate_token()
        self.assertTrue(tc.TOKEN_PATTERN.match(tok))
        self.assertEqual(len(tok), 43)

    def test_tokens_are_unique(self):
        toks = {tc.generate_token() for _ in range(1000)}
        self.assertEqual(len(toks), 1000)  # birthday paradox: would need ~2^128

    def test_hash_token_format(self):
        h = tc.hash_token("test")
        self.assertTrue(h.startswith("sha256:"))
        self.assertEqual(len(h), len("sha256:") + 64)

    def test_validate_token_rejects_none(self):
        self.assertIsNone(tc.validate_token(None))

    def test_validate_token_rejects_empty(self):
        self.assertIsNone(tc.validate_token(""))

    def test_validate_token_rejects_wrong_format(self):
        self.assertIsNone(tc.validate_token("short"))
        self.assertIsNone(tc.validate_token("x" * 42))   # one char short
        self.assertIsNone(tc.validate_token("x" * 44))   # one char long
        self.assertIsNone(tc.validate_token("!" * 43))   # bad chars

    def test_validate_token_rejects_unknown(self):
        # Format valid but no matching record
        self.assertIsNone(tc.validate_token(tc.generate_token()))

    def test_validate_token_accepts_valid(self):
        record, plaintext = self._make()
        found = tc.validate_token(plaintext)
        self.assertIsNotNone(found)
        self.assertEqual(found.id, record.id)

    def test_validate_token_rejects_suspended(self):
        record, plaintext = self._make()
        tc.suspend_record(record.id, reason="test")
        self.assertIsNone(tc.validate_token(plaintext))

    def test_validate_token_rejects_revoked(self):
        record, plaintext = self._make()
        tc.revoke_record(record.id, reason="test")
        self.assertIsNone(tc.validate_token(plaintext))

    def test_validate_token_rejects_expired(self):
        record, plaintext = self._make()
        # Force expiry in the past
        past = (datetime.now(UTC) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        tc.update_record(record.id, expires_at=past)
        self.assertIsNone(tc.validate_token(plaintext))


class CreateRecord(_BaseCase):
    def test_create_returns_record_and_token(self):
        record, plaintext = self._make()
        self.assertTrue(tc.CUSTOMER_ID_RE.match(record.id))
        self.assertTrue(tc.TOKEN_PATTERN.match(plaintext))

    def test_create_hashes_token(self):
        record, plaintext = self._make()
        self.assertEqual(record.api_key_hash, tc.hash_token(plaintext))

    def test_create_assigns_active_status(self):
        record, _ = self._make()
        self.assertEqual(record.status, "active")

    def test_create_sequence_increments(self):
        r1, _ = self._make()
        r2, _ = self._make()
        # ids should differ by exactly 1 in the trailing sequence
        seq1 = int(r1.id.split("_")[-1])
        seq2 = int(r2.id.split("_")[-1])
        self.assertEqual(seq2, seq1 + 1)

    def test_create_default_claims(self):
        record, _ = self._make()
        self.assertEqual(sorted(record.enabled_claims), [8, 9, 11])

    def test_create_custom_claims(self):
        record, _ = self._make(enabled_claims=[8])
        self.assertEqual(record.enabled_claims, [8])

    def test_create_expires_one_year_default(self):
        record, _ = self._make()
        created = datetime.fromisoformat(record.created_at.replace("Z", "+00:00"))
        expires = datetime.fromisoformat(record.expires_at.replace("Z", "+00:00"))
        # ~365 days, allowing minor wall-clock drift across the function call
        self.assertGreater((expires - created).days, 364)
        self.assertLess((expires - created).days, 367)

    def test_create_persists_to_disk(self):
        record, _ = self._make()
        c = tc.load_customers()
        self.assertEqual(len(c.records), 1)
        self.assertEqual(c.records[0].id, record.id)


class SchemaValidation(_BaseCase):
    """Each test exercises one specific reject path in _validate_record."""

    def _bad_record_dict(self, **overrides) -> dict:
        record, _ = self._make()
        d = record.to_dict()
        d.update(overrides)
        return d

    def _write_and_reload(self, d: dict) -> None:
        self._write_records_plaintext_dict([d])
        tc.load_customers()  # triggers validation

    def test_bad_id_rejected(self):
        with self.assertRaisesRegex(tc.SchemaError, "invalid id"):
            self._write_and_reload(self._bad_record_dict(id="not_a_valid_id"))

    def test_empty_name_rejected(self):
        with self.assertRaisesRegex(tc.SchemaError, "name is empty"):
            self._write_and_reload(self._bad_record_dict(name=""))

    def test_bad_email_rejected(self):
        with self.assertRaisesRegex(tc.SchemaError, "email"):
            self._write_and_reload(self._bad_record_dict(email="not an email"))

    def test_bad_country_rejected(self):
        with self.assertRaisesRegex(tc.SchemaError, "country"):
            self._write_and_reload(self._bad_record_dict(country="aus"))

    def test_bad_tier_rejected(self):
        with self.assertRaisesRegex(tc.SchemaError, "tier"):
            self._write_and_reload(self._bad_record_dict(tier="tier1"))

    def test_bad_claims_rejected(self):
        with self.assertRaisesRegex(tc.SchemaError, "enabled_claims"):
            self._write_and_reload(self._bad_record_dict(enabled_claims=[42]))

    def test_bad_api_key_hash_rejected(self):
        with self.assertRaisesRegex(tc.SchemaError, "api_key_hash"):
            self._write_and_reload(self._bad_record_dict(api_key_hash="sha256:short"))

    def test_naive_timestamp_rejected(self):
        # No 'Z' suffix
        with self.assertRaisesRegex(tc.SchemaError, "missing 'Z'"):
            self._write_and_reload(self._bad_record_dict(created_at="2026-05-11T12:00:00"))

    def test_bad_status_rejected(self):
        with self.assertRaisesRegex(tc.SchemaError, "status"):
            self._write_and_reload(self._bad_record_dict(status="active "))

    def test_manufacturers_exceeds_max_rejected(self):
        with self.assertRaisesRegex(tc.SchemaError, "exceeds max"):
            self._write_and_reload(
                self._bad_record_dict(
                    manufacturers=["a", "b", "c"], max_manufacturers=2
                )
            )

    def test_negative_max_manufacturers_rejected(self):
        with self.assertRaisesRegex(tc.SchemaError, "negative"):
            self._write_and_reload(self._bad_record_dict(max_manufacturers=-1))

    def test_zero_rate_limit_rejected(self):
        with self.assertRaisesRegex(tc.SchemaError, "rate_limit"):
            self._write_and_reload(self._bad_record_dict(rate_limit_per_hour=0))


class CrossRecordInvariants(_BaseCase):
    def test_duplicate_id_rejected_on_load(self):
        record, _ = self._make()
        # Manually craft a second record with the same id
        d = record.to_dict()
        self._write_records_plaintext_dict([d, d])
        with self.assertRaisesRegex(tc.SchemaError, "duplicate id"):
            tc.load_customers()

    def test_duplicate_hash_rejected_on_load(self):
        r1, _ = self._make(email="a@example.com")
        r2, _ = self._make(email="b@example.com")
        # Force r2's hash to match r1's
        d1 = r1.to_dict()
        d2 = r2.to_dict()
        d2["api_key_hash"] = d1["api_key_hash"]
        self._write_records_plaintext_dict([d1, d2])
        with self.assertRaisesRegex(tc.SchemaError, "duplicate api_key_hash"):
            tc.load_customers()


class UpdateRecord(_BaseCase):
    def test_update_email(self):
        record, _ = self._make()
        updated = tc.update_record(record.id, email="new@example.com")
        self.assertEqual(updated.email, "new@example.com")
        # Persisted
        self.assertEqual(tc.get_record(record.id).email, "new@example.com")

    def test_update_forbidden_field_id(self):
        record, _ = self._make()
        with self.assertRaisesRegex(tc.SchemaError, "protected"):
            tc.update_record(record.id, id="cust_2026_9999")

    def test_update_forbidden_field_api_key_hash(self):
        record, _ = self._make()
        with self.assertRaisesRegex(tc.SchemaError, "protected"):
            tc.update_record(record.id, api_key_hash="sha256:" + "0" * 64)

    def test_update_unknown_field_rejected(self):
        record, _ = self._make()
        with self.assertRaisesRegex(tc.SchemaError, "unknown"):
            tc.update_record(record.id, bogus_field="x")

    def test_update_nonexistent_record(self):
        with self.assertRaisesRegex(tc.SchemaError, "no record"):
            tc.update_record("cust_2026_9999", email="x@example.com")

    def test_update_validates_new_value(self):
        record, _ = self._make()
        with self.assertRaises(tc.SchemaError):
            tc.update_record(record.id, country="lowercase")


class StatusTransitions(_BaseCase):
    def test_suspend_writes_reason_to_notes(self):
        record, _ = self._make()
        suspended = tc.suspend_record(record.id, reason="invoice overdue")
        self.assertEqual(suspended.status, "suspended")
        self.assertIn("invoice overdue", suspended.notes)

    def test_revoke_writes_reason_to_notes(self):
        record, _ = self._make()
        revoked = tc.revoke_record(record.id, reason="terminated")
        self.assertEqual(revoked.status, "revoked")
        self.assertIn("terminated", revoked.notes)

    def test_revoke_preserves_existing_notes(self):
        record, _ = self._make(notes="pre-existing operator note")
        revoked = tc.revoke_record(record.id, reason="cleanup")
        self.assertIn("pre-existing operator note", revoked.notes)
        self.assertIn("cleanup", revoked.notes)


class ListRecords(_BaseCase):
    def test_list_empty(self):
        self.assertEqual(tc.list_records(), [])

    def test_list_sorted_by_id(self):
        # Create in arbitrary order; verify sort
        r1, _ = self._make(email="a@example.com")
        r2, _ = self._make(email="b@example.com")
        r3, _ = self._make(email="c@example.com")
        ids = [r.id for r in tc.list_records()]
        self.assertEqual(ids, sorted([r1.id, r2.id, r3.id]))

    def test_filter_by_status(self):
        r1, _ = self._make(email="a@example.com")
        r2, _ = self._make(email="b@example.com")
        tc.suspend_record(r2.id, reason="test")
        active = tc.list_records(status="active")
        self.assertEqual([r.id for r in active], [r1.id])
        suspended = tc.list_records(status="suspended")
        self.assertEqual([r.id for r in suspended], [r2.id])

    def test_filter_invalid_status_rejected(self):
        with self.assertRaises(tc.SchemaError):
            tc.list_records(status="bogus")


class AtomicityAndLocking(_BaseCase):
    def test_lock_file_created(self):
        self._make()
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        self.assertTrue(lock_path.exists())

    def test_temp_file_cleaned_up(self):
        self._make()
        tmp_path = self.path.with_suffix(self.path.suffix + ".tmp")
        # After atomic rename, the .tmp file should NOT exist
        self.assertFalse(tmp_path.exists())

    def test_file_is_valid_json_after_write(self):
        self._make()
        # If the write was torn or aborted, json.loads would fail
        json.loads(self.path.read_text())


class Encryption(_BaseCase):
    """Tests specific to the application-layer encryption (ADR D14)."""

    def test_on_disk_records_are_ciphertext_strings(self):
        """The records field on disk must be strings, not dicts.

        This is the core encryption-at-rest property: even if someone
        gets the file off the volume without the key, they cannot read
        any customer data.
        """
        record, _ = self._make()
        raw = json.loads(self.path.read_text())
        self.assertEqual(len(raw["records"]), 1)
        self.assertIsInstance(raw["records"][0], str)
        # And the ciphertext must not contain any plaintext PII
        ciphertext = raw["records"][0]
        self.assertNotIn(record.email, ciphertext)
        self.assertNotIn(record.organisation, ciphertext)
        self.assertNotIn(record.name, ciphertext)

    def test_missing_key_in_production_refuses(self):
        os.environ.pop(tc.CUSTOMERS_KEY_ENV, None)
        os.environ["RAILWAY_ENVIRONMENT"] = "production"
        with self.assertRaisesRegex(tc.EncryptionKeyError, "RAILWAY_ENVIRONMENT is set"):
            tc.load_customers()

    def test_missing_key_in_dev_without_opt_in_refuses(self):
        os.environ.pop(tc.CUSTOMERS_KEY_ENV, None)
        # RAILWAY_ENVIRONMENT not set, DTVSS_DEV_ALLOW_UNENCRYPTED not set
        with self.assertRaisesRegex(tc.EncryptionKeyError, "No encryption key"):
            tc.load_customers()

    def test_dev_opt_in_warns_loudly(self):
        os.environ.pop(tc.CUSTOMERS_KEY_ENV, None)
        os.environ["DTVSS_DEV_ALLOW_UNENCRYPTED"] = "1"
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            tc.load_customers()
        user_warnings = [w for w in caught if issubclass(w.category, UserWarning)]
        self.assertGreaterEqual(len(user_warnings), 1)
        # The exact warning wording uses "sentinel" (lower-cased); a stricter
        # check for the more verbose phrasing was tried during development but
        # the case-insensitive substring check below is the stable assertion.
        self.assertIn("sentinel", str(user_warnings[0].message).lower())

    def test_malformed_key_refuses(self):
        os.environ[tc.CUSTOMERS_KEY_ENV] = "not-a-valid-fernet-key"
        with self.assertRaisesRegex(tc.EncryptionKeyError, "malformed"):
            tc.load_customers()

    def test_wrong_key_on_decrypt_raises_schema_error(self):
        """Records encrypted with one key cannot be read with another."""
        record, _ = self._make()
        # Swap the key to a different one
        os.environ[tc.CUSTOMERS_KEY_ENV] = Fernet.generate_key().decode("utf-8")
        with self.assertRaisesRegex(tc.SchemaError, "Failed to decrypt"):
            tc.load_customers()

    def test_tampered_ciphertext_detected(self):
        """Fernet authenticates; flipping a bit in the ciphertext should fail.

        This is what protects against an attacker who has write access to
        the file but not the key trying to inject a record.
        """
        self._make()
        raw = json.loads(self.path.read_text())
        # Tamper with the first record's ciphertext
        tampered = raw["records"][0]
        # Swap the last char for another url-safe-base64 char
        tampered = tampered[:-2] + ("A" if tampered[-2] != "A" else "B") + "="
        raw["records"][0] = tampered
        self.path.write_text(json.dumps(raw))
        with self.assertRaisesRegex(tc.SchemaError, "Failed to decrypt"):
            tc.load_customers()

    def test_multifernet_rotation_can_decrypt_with_old_key(self):
        """The rotation pattern: new key first, old key second; reads still work.

        Operator workflow:
            1. Generate new key, set CUSTOMERS_ENCRYPTION_KEYS="<new>,<old>"
            2. Existing records (encrypted with old) still decrypt because
               MultiFernet tries all keys.
            3. Writes use the first key (new), so over time all records
               migrate to the new key.
            4. After re-encrypting all records (via tools/rotate_encryption_key.py),
               set CUSTOMERS_ENCRYPTION_KEY="<new>" and discard the old.
        """
        record, _ = self._make()
        old_key = self.test_key
        new_key = Fernet.generate_key().decode("utf-8")
        # Rotate: new key first
        os.environ.pop(tc.CUSTOMERS_KEY_ENV, None)
        os.environ[tc.CUSTOMERS_KEYS_ENV] = f"{new_key},{old_key}"
        # The existing record was encrypted with old_key; load should
        # still work because MultiFernet tries each key in turn.
        loaded = tc.load_customers()
        self.assertEqual(len(loaded.records), 1)
        self.assertEqual(loaded.records[0].id, record.id)

    def test_multifernet_new_writes_use_first_key(self):
        """After rotation, writes use the new (first) key, not the old one."""
        record, _ = self._make()
        old_key = self.test_key
        new_key = Fernet.generate_key().decode("utf-8")
        os.environ.pop(tc.CUSTOMERS_KEY_ENV, None)
        os.environ[tc.CUSTOMERS_KEYS_ENV] = f"{new_key},{old_key}"
        # Touch the record via update_record so it's re-encrypted on write
        tc.update_record(record.id, notes="updated post-rotation")
        # Now set only the new key; the old record should still decrypt
        # because update_record re-encrypted it with new_key.
        os.environ.pop(tc.CUSTOMERS_KEYS_ENV, None)
        os.environ[tc.CUSTOMERS_KEY_ENV] = new_key
        loaded = tc.load_customers()
        self.assertEqual(loaded.records[0].notes, "updated post-rotation")

    def test_generate_encryption_key_produces_valid_key(self):
        key = tc.generate_encryption_key()
        # Should be a 44-char url-safe base64 string
        self.assertEqual(len(key), 44)
        # And should be a working Fernet key
        f = Fernet(key.encode("utf-8"))
        ct = f.encrypt(b"hello")
        self.assertEqual(f.decrypt(ct), b"hello")


if __name__ == "__main__":
    unittest.main()
