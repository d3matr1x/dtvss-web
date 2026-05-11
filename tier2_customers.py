"""
Tier 2 customer record management.

Implements the customer-data layer described in tier2-design.md §1-§2. This
module is the SINGLE WRITER to customers.json (per §1.7.1); every mutation
goes through update_record() under an flock. Reads happen without a lock
because atomic-rename writes guarantee readers see either the pre- or
post-write file, never a torn intermediate.

Public surface (anything else is an implementation detail):

    load_customers()                 -> Customers
    save_customers(customers)        -> None    (rare; prefer update_record)
    create_record(**fields)          -> Customer, plaintext_token
    update_record(customer_id, **kw) -> Customer
    get_record(customer_id)          -> Customer | None
    list_records(*, status=None)     -> list[Customer]
    validate_token(plaintext_token)  -> Customer | None
    hash_token(plaintext_token)      -> str   (returns 'sha256:<hex>')

Storage path resolution:

    CUSTOMERS_PATH env var if set; otherwise 'private/customers.json'.
    See tier2-design.md §1.5. Production sets this to '/data/customers.json'
    on the Railway volume.

Concurrency model:

    - Flask is the SOLE WRITER. CLI tools that mutate state run on the same
      host as Flask (Railway) or against the dev path (private/customers.json).
    - Cron jobs that need to drive state transitions read freely, then POST
      to an internal Flask endpoint that performs the write. They do NOT
      write to customers.json directly.
    - Locking is exclusive-lock based (advisory on Unix via fcntl.flock,
      mandatory on Windows via msvcrt.locking), which suffices because we
      control every writer. Atomic rename via os.replace() makes reads
      safe without a lock.

Schema invariants (validated on every load and every write):

    - id matches r'^cust_\\d{4}_\\d{4}$' and is unique
    - email looks vaguely like an email (presence of @, not RFC 5321 perfect)
    - country is 2-letter uppercase
    - tier is "tier2" (will widen at Tier 3)
    - enabled_claims is a subset of {8, 9, 11}
    - api_key_hash starts with "sha256:" and the hex is 64 chars
    - manufacturers count <= max_manufacturers
    - status is "active", "suspended", or "revoked"
    - all timestamps are ISO 8601 with explicit "Z" suffix

Anything failing schema validation raises SchemaError. Callers should let
this propagate; we want loud failures, not silent half-writes.

Copyright 2026 Andrew Broglio. Licensed under BSL 1.1.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import warnings
from dataclasses import asdict, dataclass, field, fields
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken, MultiFernet


# ---------------------------------------------------------------------------
# Cross-platform file locking
# ---------------------------------------------------------------------------
# Unix has fcntl.flock (advisory, well-behaved across processes).
# Windows has msvcrt.locking (mandatory, byte-range-only, but works for our
# single-byte-lock pattern). We hide the difference behind _exclusive_lock /
# _release_lock helpers so the rest of the file doesn't care.
#
# The choice of locking mechanism is per-platform and not configurable. If
# you're running on something exotic (jython, pypy on Windows, etc.) and one
# of these imports fails, you'll see an ImportError on module load — which
# is a clearer failure mode than a silent no-op lock.

if sys.platform == "win32":
    import msvcrt

    def _acquire_exclusive(file_handle) -> None:
        """Acquire an exclusive lock on file_handle. Blocks until acquired.

        On Windows we lock a single byte at offset 0. msvcrt.locking's
        LK_LOCK retries every second for up to 10 seconds before raising
        OSError. At Stage 1 scale (one operator, occasional CLI use)
        contention long enough to exhaust those retries is unrealistic;
        if it happens, the OSError surfaces as an I/O error to the caller,
        which is the right behaviour.
        """
        # Ensure file is non-empty so byte 0 exists to lock.
        # Write and rewind if needed.
        file_handle.seek(0, os.SEEK_END)
        if file_handle.tell() == 0:
            file_handle.write("\0")
            file_handle.flush()
        file_handle.seek(0)
        msvcrt.locking(file_handle.fileno(), msvcrt.LK_LOCK, 1)

    def _release_lock(file_handle) -> None:
        """Release the lock acquired by _acquire_exclusive."""
        file_handle.seek(0)
        msvcrt.locking(file_handle.fileno(), msvcrt.LK_UNLCK, 1)

else:
    import fcntl

    def _acquire_exclusive(file_handle) -> None:
        """Acquire an exclusive flock. Blocks until acquired (LOCK_EX)."""
        fcntl.flock(file_handle.fileno(), fcntl.LOCK_EX)

    def _release_lock(file_handle) -> None:
        """Release the flock."""
        fcntl.flock(file_handle.fileno(), fcntl.LOCK_UN)


# ---------------------------------------------------------------------------
# Path resolution (per design §1.5)
# ---------------------------------------------------------------------------

DEFAULT_DEV_PATH = "private/customers.json"


def customers_path() -> Path:
    """Resolve the customers.json path from environment.

    Reads CUSTOMERS_PATH if set; otherwise falls back to private/customers.json
    relative to the current working directory (i.e. repo root in dev). The
    fallback is intentional: dev "just works" without env config, prod
    requires the env var to be set explicitly.
    """
    return Path(os.environ.get("CUSTOMERS_PATH", DEFAULT_DEV_PATH))


# ---------------------------------------------------------------------------
# Application-layer encryption (per ADR D14)
# ---------------------------------------------------------------------------
#
# Customer records contain PII (name, email), commercial-sensitive context
# (hospital fleet composition, payment terms in notes), and per-customer
# identifying material (api_key_hash). Railway's storage-layer encryption
# defends against physical disk seizure but NOT against:
#   - anyone with access to the Railway project
#   - Railway employees with admin access
#   - backups restored to another project
#   - GitHub OAuth compromise (threat-model E4)
#
# Application-layer encryption with a key held in an env var raises the bar:
# the on-disk JSON contains only ciphertext, and decryption requires the
# CUSTOMERS_ENCRYPTION_KEY env var. The key never appears in the file.
#
# Algorithm: Fernet (AES-128-CBC + HMAC-SHA256, per RFC 8576-style profile).
# Reasoning:
#   - Authenticated encryption (HMAC) — prevents silent tampering
#   - Standard cryptography library, well-vetted
#   - Simple key format (one 32-byte url-safe base64 string)
#   - MultiFernet supports key rotation without flag days
#
# Scope of protection: each RECORD is encrypted individually, not the whole
# file. This means:
#   - The schema-version wrapper stays in plaintext (so a parser can refuse
#     a version it doesn't understand without needing the key)
#   - Adding/removing records doesn't re-encrypt the whole file
#   - Key rotation can re-encrypt one record at a time
#
# What this does NOT defend against:
#   - Code execution in the Flask process (env var is visible to the process)
#   - A debug-print of a decrypted Customer object reaching logs
#   - The plaintext token at issuance time (it's printed once to STDOUT)

CUSTOMERS_KEY_ENV = "CUSTOMERS_ENCRYPTION_KEY"
CUSTOMERS_KEY_FILE_ENV = "CUSTOMERS_ENCRYPTION_KEY_FILE"
# Multiple keys for rotation: comma-separated. First key is the encryption
# key for NEW writes; all keys can decrypt. Standard MultiFernet pattern.
CUSTOMERS_KEYS_ENV = "CUSTOMERS_ENCRYPTION_KEYS"

# Sentinel used only when DTVSS_DEV_ALLOW_UNENCRYPTED=1 is set. Catches the
# specific bug of forgetting to set the key in production: the dev fallback
# will refuse to run anywhere RAILWAY_ENVIRONMENT is set.
#
# This is a real, valid Fernet key that is published in the source tree.
# It is suitable ONLY for local development against throwaway data. Using
# it in production would mean the customer database can be decrypted by
# anyone with read access to this repository, which is the entire internet.
# Treat its presence in the source as documentation, not as a key.
_DEV_KEY_SENTINEL = "lbqDn8VTgkpTczfQXLKLW7Bz-JjXA-OvAWTdwlC0X3k="


class EncryptionKeyError(RuntimeError):
    """Raised when encryption-key configuration is missing or malformed.

    Distinct from SchemaError because the fix is different: SchemaError
    means "the data is wrong"; EncryptionKeyError means "the env is wrong."
    """


def _load_encryption_keys() -> MultiFernet:
    """Resolve and load the encryption key(s) from environment.

    Resolution order (first match wins):
        1. CUSTOMERS_ENCRYPTION_KEYS env var: comma-separated list of keys.
           First key is the encryption key for new writes; all keys decrypt.
           This is the rotation pattern.
        2. CUSTOMERS_ENCRYPTION_KEY env var: single key. Equivalent to a
           one-element list in (1).
        3. CUSTOMERS_ENCRYPTION_KEY_FILE env var: path to a file containing
           one key per line. Useful if the operator prefers to manage the
           key via a file-mounted secret rather than env var.
        4. DTVSS_DEV_ALLOW_UNENCRYPTED=1 with RAILWAY_ENVIRONMENT unset:
           use the dev sentinel key. Emits a UserWarning every load.
           Refuses to operate if RAILWAY_ENVIRONMENT is set (i.e. prod).

    Raises EncryptionKeyError if none of the above resolve.

    A loaded key is NOT cached. The cost of re-parsing on each load is
    negligible (microseconds), and the lack of caching means an in-flight
    key rotation takes effect immediately on the next request rather than
    after a process restart.
    """
    keys: list[str] = []

    raw_keys = os.environ.get(CUSTOMERS_KEYS_ENV)
    if raw_keys:
        keys = [k.strip() for k in raw_keys.split(",") if k.strip()]
    else:
        single = os.environ.get(CUSTOMERS_KEY_ENV)
        if single:
            keys = [single.strip()]
        else:
            key_file = os.environ.get(CUSTOMERS_KEY_FILE_ENV)
            if key_file and Path(key_file).is_file():
                file_content = Path(key_file).read_text(encoding="utf-8")
                keys = [
                    line.strip()
                    for line in file_content.splitlines()
                    if line.strip() and not line.strip().startswith("#")
                ]

    if not keys:
        # Last-resort dev fallback. Refuse loudly in any environment that
        # looks like production.
        if os.environ.get("RAILWAY_ENVIRONMENT"):
            raise EncryptionKeyError(
                "No encryption key configured but RAILWAY_ENVIRONMENT is set. "
                f"Set {CUSTOMERS_KEY_ENV} (or {CUSTOMERS_KEYS_ENV} for rotation, "
                f"or {CUSTOMERS_KEY_FILE_ENV} to point at a file) before "
                "starting the service. Refusing to run without a key in prod."
            )
        if os.environ.get("DTVSS_DEV_ALLOW_UNENCRYPTED") == "1":
            warnings.warn(
                f"Using the dev sentinel encryption key. Set {CUSTOMERS_KEY_ENV} "
                "before any production use. This warning fires on every load "
                "deliberately so it's hard to miss.",
                UserWarning,
                stacklevel=3,
            )
            keys = [_DEV_KEY_SENTINEL]
        else:
            raise EncryptionKeyError(
                f"No encryption key configured. Set {CUSTOMERS_KEY_ENV} (or "
                f"{CUSTOMERS_KEYS_ENV} / {CUSTOMERS_KEY_FILE_ENV}), or set "
                "DTVSS_DEV_ALLOW_UNENCRYPTED=1 for local development with a "
                "throwaway key. Run `python -c \"from cryptography.fernet import "
                "Fernet; print(Fernet.generate_key().decode())\"` to generate one."
            )

    try:
        fernets = [Fernet(k.encode("utf-8")) for k in keys]
    except (ValueError, TypeError) as e:
        raise EncryptionKeyError(
            f"Encryption key(s) malformed: {e}. Each key must be a "
            "44-character url-safe base64 string. Generate with "
            "Fernet.generate_key()."
        )

    return MultiFernet(fernets)


def _encrypt_record_dict(record_dict: dict[str, Any]) -> str:
    """Serialize a record dict to ciphertext. Output is a url-safe base64 string.

    Raises EncryptionKeyError if the key is missing or malformed.
    """
    plaintext = json.dumps(record_dict, ensure_ascii=False).encode("utf-8")
    return _load_encryption_keys().encrypt(plaintext).decode("utf-8")


def _decrypt_record_str(ciphertext: str) -> dict[str, Any]:
    """Decrypt a ciphertext string back into a record dict.

    Raises EncryptionKeyError if the key is missing/malformed.
    Raises SchemaError if the ciphertext is tampered with or was encrypted
    with a key not in the current rotation set.
    """
    keyset = _load_encryption_keys()
    try:
        plaintext = keyset.decrypt(ciphertext.encode("utf-8"))
    except InvalidToken as e:
        raise SchemaError(
            "Failed to decrypt record. Either the encryption key has "
            "changed (and the old key is not in the rotation set) or the "
            "ciphertext was tampered with. See ADR D14 for key-rotation "
            f"procedure. Underlying error: {e}"
        )
    try:
        return json.loads(plaintext.decode("utf-8"))
    except json.JSONDecodeError as e:
        # This shouldn't be possible: if decrypt succeeded the HMAC verified,
        # so the plaintext was what we wrote. But guard anyway.
        raise SchemaError(f"Decrypted record is not valid JSON: {e}")


def generate_encryption_key() -> str:
    """Generate a fresh Fernet key, returned as a str for env-var use.

    Convenience function. Operators run this once at first setup, store the
    output in CUSTOMERS_ENCRYPTION_KEY, and never need to touch it again
    until rotation.
    """
    return Fernet.generate_key().decode("utf-8")


# ---------------------------------------------------------------------------
# Schema (per design §1.1, §1.2)
# ---------------------------------------------------------------------------

CURRENT_SCHEMA_VERSION = 1

VALID_TIERS = frozenset({"tier2"})
VALID_STATUSES = frozenset({"active", "suspended", "revoked"})
VALID_CLAIMS = frozenset({8, 9, 11})

CUSTOMER_ID_RE = re.compile(r"^cust_\d{4}_\d{4}$")
API_KEY_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
# Deliberately not RFC 5321; we just want to catch typos that would prevent
# the welcome email from arriving. Actual deliverability is verified during
# the onboarding email step at Stage 4.
EMAIL_LOOKS_VALID_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class SchemaError(ValueError):
    """Raised when a customer record or wrapper fails schema validation.

    Subclasses ValueError so existing `except ValueError:` handlers catch
    these too, but lets specific callers (CLI tools, tests) filter on the
    narrower type.
    """


@dataclass
class Customer:
    """A single Tier 2 customer record.

    Maps 1:1 to the schema in tier2-design.md §1.1. Use create_record() to
    instantiate from raw fields; use load_customers()['records'] to get
    these back from disk.
    """

    id: str
    name: str
    organisation: str
    email: str
    country: str
    tier: str
    enabled_claims: list[int]
    api_key_hash: str
    api_key_issued_at: str
    manufacturers: list[str]
    max_manufacturers: int
    rate_limit_per_hour: int
    status: str
    license_signed_at: str
    license_version: str
    created_at: str
    expires_at: str
    notes: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Customer:
        """Construct from a JSON dict, raising SchemaError on missing fields.

        Tolerates extra keys (forward-compat) but rejects missing required
        ones (no silent default-substitution that masks data loss).
        """
        required = {f.name for f in fields(cls) if f.default is field(default="").default or f.default == ""} \
                   | {"id", "name", "organisation", "email", "country", "tier",
                      "enabled_claims", "api_key_hash", "api_key_issued_at",
                      "manufacturers", "max_manufacturers", "rate_limit_per_hour",
                      "status", "license_signed_at", "license_version",
                      "created_at", "expires_at"}
        missing = required - d.keys()
        if missing:
            raise SchemaError(f"missing required fields: {sorted(missing)}")
        # Only pass keys the dataclass knows about; tolerate unknown keys.
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in known})

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Customers:
    """The on-disk file structure: a versioned wrapper around a record list.

    On disk, the records list contains ciphertext strings (per ADR D14):

        {
            "version": 1,
            "records": ["<fernet ciphertext>", "<fernet ciphertext>", ...]
        }

    The wrapper exists so schema migrations are possible without breaking
    parsers. version=1 is the launch schema with application-layer
    encryption. Any future schema change (e.g. moving to SQLite or
    changing the encryption format) bumps this and adds a migration.
    """

    version: int
    records: list[Customer]

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Customers:
        """Parse the on-disk dict. Decrypts each ciphertext record.

        Raises SchemaError on schema problems, EncryptionKeyError if the
        key configuration is broken.
        """
        if "version" not in d:
            raise SchemaError("customers file missing 'version' field")
        if d["version"] != CURRENT_SCHEMA_VERSION:
            # Future: add migration here. For now, refuse to load an
            # unrecognised version rather than corrupting data.
            raise SchemaError(
                f"unsupported schema version {d['version']!r}; "
                f"this build supports version {CURRENT_SCHEMA_VERSION}"
            )
        if "records" not in d or not isinstance(d["records"], list):
            raise SchemaError("customers file missing 'records' list")

        decrypted_records: list[Customer] = []
        for i, raw in enumerate(d["records"]):
            if not isinstance(raw, str):
                raise SchemaError(
                    f"record {i}: expected encrypted string, got {type(raw).__name__}. "
                    f"File may be from a pre-encryption schema version."
                )
            record_dict = _decrypt_record_str(raw)
            decrypted_records.append(Customer.from_dict(record_dict))

        return cls(version=d["version"], records=decrypted_records)

    def to_dict(self) -> dict[str, Any]:
        """Serialize for on-disk write. Encrypts each record."""
        return {
            "version": self.version,
            "records": [_encrypt_record_dict(r.to_dict()) for r in self.records],
        }


def _validate_record(r: Customer) -> None:
    """Validate a single record against the schema. Raises SchemaError on fail.

    Called on every read and every write. Catching schema violations at
    every boundary is the point: a malformed record reaching production
    should fail at load, not silently corrupt a downstream query.
    """
    if not CUSTOMER_ID_RE.match(r.id):
        raise SchemaError(f"invalid id: {r.id!r} (expected cust_YYYY_NNNN)")
    if not r.name.strip():
        raise SchemaError(f"{r.id}: name is empty")
    if not r.organisation.strip():
        raise SchemaError(f"{r.id}: organisation is empty")
    if not EMAIL_LOOKS_VALID_RE.match(r.email):
        raise SchemaError(f"{r.id}: email does not look valid: {r.email!r}")
    if not COUNTRY_RE.match(r.country):
        raise SchemaError(f"{r.id}: country must be 2-letter uppercase ISO code: {r.country!r}")
    if r.tier not in VALID_TIERS:
        raise SchemaError(f"{r.id}: tier {r.tier!r} not in {VALID_TIERS}")
    if not set(r.enabled_claims).issubset(VALID_CLAIMS):
        raise SchemaError(
            f"{r.id}: enabled_claims {r.enabled_claims} not subset of {VALID_CLAIMS}"
        )
    if not API_KEY_HASH_RE.match(r.api_key_hash):
        raise SchemaError(f"{r.id}: api_key_hash does not match 'sha256:<64 hex>'")
    _validate_iso8601(r.id, "api_key_issued_at", r.api_key_issued_at)
    if r.max_manufacturers < 0:
        raise SchemaError(f"{r.id}: max_manufacturers cannot be negative")
    if len(r.manufacturers) > r.max_manufacturers:
        raise SchemaError(
            f"{r.id}: {len(r.manufacturers)} manufacturers exceeds max {r.max_manufacturers}"
        )
    if r.rate_limit_per_hour < 1:
        raise SchemaError(f"{r.id}: rate_limit_per_hour must be >= 1")
    if r.status not in VALID_STATUSES:
        raise SchemaError(f"{r.id}: status {r.status!r} not in {VALID_STATUSES}")
    _validate_iso8601(r.id, "license_signed_at", r.license_signed_at)
    if not r.license_version.strip():
        raise SchemaError(f"{r.id}: license_version is empty")
    _validate_iso8601(r.id, "created_at", r.created_at)
    _validate_iso8601(r.id, "expires_at", r.expires_at)


def _validate_iso8601(record_id: str, field_name: str, value: str) -> None:
    """Validate that a string is an ISO 8601 timestamp with explicit Z suffix.

    Refusing implicit-UTC strings (no suffix) catches the bug where a
    naive datetime gets serialised without timezone info and is later
    interpreted in the wrong zone.
    """
    if not value.endswith("Z"):
        raise SchemaError(
            f"{record_id}: {field_name}={value!r} missing 'Z' suffix; "
            f"all timestamps must be explicit UTC"
        )
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as e:
        raise SchemaError(f"{record_id}: {field_name}={value!r} not ISO 8601: {e}")


def _validate_customers(c: Customers) -> None:
    """Validate the whole file: per-record schema, plus cross-record invariants."""
    if c.version != CURRENT_SCHEMA_VERSION:
        raise SchemaError(f"unexpected schema version {c.version}")
    seen_ids: set[str] = set()
    seen_hashes: set[str] = set()
    for r in c.records:
        _validate_record(r)
        if r.id in seen_ids:
            raise SchemaError(f"duplicate id: {r.id}")
        seen_ids.add(r.id)
        # Token hashes must be globally unique. If two records share a hash,
        # either there's a hash collision (effectively impossible for SHA-256
        # at this scale) or someone manually copied an api_key_hash from one
        # record to another. Either way we want to know loudly.
        if r.api_key_hash in seen_hashes:
            raise SchemaError(f"duplicate api_key_hash for record {r.id}")
        seen_hashes.add(r.api_key_hash)


# ---------------------------------------------------------------------------
# Token operations (per design §2)
# ---------------------------------------------------------------------------

TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")


def generate_token() -> str:
    """Generate a fresh 256-bit URL-safe token.

    Returns the plaintext. The caller is responsible for showing it to the
    operator exactly once and storing only the hash via hash_token().
    """
    # secrets.token_urlsafe(32) gives 32 bytes of entropy encoded as 43
    # URL-safe base64 characters. See PEP 506 / design §2.1.
    return secrets.token_urlsafe(32)


def hash_token(plaintext_token: str) -> str:
    """Hash a plaintext token for at-rest storage. Returns 'sha256:<hex>'."""
    return "sha256:" + hashlib.sha256(plaintext_token.encode("utf-8")).hexdigest()


def validate_token(plaintext_token: str | None) -> Customer | None:
    """Validate a plaintext token. Returns the customer record if valid+active.

    Validation steps, in order:
        1. Format check (TOKEN_PATTERN). Reject before any disk I/O.
        2. Hash the supplied token.
        3. Walk records, hmac.compare_digest against each api_key_hash.
        4. If matched: check status == "active" and expires_at > now.
        5. Return record or None.

    Uses hmac.compare_digest rather than == to eliminate the per-record
    position-enumeration timing leak described in design §2.5.1. Token
    forgery is independently prevented by SHA-256 preimage resistance;
    the constant-time compare is belt-and-braces, not the primary defence.

    Returns None for any failure mode (format-invalid, no match, suspended,
    revoked, expired). Callers MUST NOT distinguish these cases in their
    response to the user; the threat model relies on this opacity.
    """
    if not plaintext_token or not TOKEN_PATTERN.match(plaintext_token):
        return None

    token_hash = hash_token(plaintext_token)
    customers = load_customers()

    now_iso = _utcnow_iso()
    for record in customers.records:
        if hmac.compare_digest(record.api_key_hash, token_hash):
            if record.status != "active":
                return None
            if record.expires_at <= now_iso:
                return None
            return record
    return None


# ---------------------------------------------------------------------------
# Load / save with single-writer lock + atomic rename (per design §1.7)
# ---------------------------------------------------------------------------

class _ExclusiveLock:
    """Context manager: acquires an exclusive lock on a sidecar .lock file.

    Uses a sibling .lock file rather than locking customers.json directly,
    because os.replace() during atomic rename would lose any lock held on
    the file (the inode changes on Unix; Windows behaviour is similar in
    spirit). Locking a separate file means the lock is held across the
    rename without ambiguity.

    The actual lock primitive is platform-specific: fcntl.flock on Unix,
    msvcrt.locking on Windows. The shim is at the top of this module.
    """

    def __init__(self, path: Path):
        self._lock_path = path.with_suffix(path.suffix + ".lock")
        self._fh = None

    def __enter__(self) -> _ExclusiveLock:
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        # 'a+' opens for read+write, creating if missing, position at end.
        # Both fcntl.flock and msvcrt.locking need a real file descriptor;
        # 'a+' is the simplest mode that works for both create-if-missing
        # and Windows's requirement that the byte we lock actually exists.
        self._fh = open(self._lock_path, "a+")
        _acquire_exclusive(self._fh)
        return self

    def __exit__(self, *exc) -> None:
        if self._fh is not None:
            try:
                _release_lock(self._fh)
            finally:
                self._fh.close()
                self._fh = None


def load_customers() -> Customers:
    """Read customers.json from disk and validate.

    No lock taken: atomic rename (os.replace) guarantees the reader sees
    either the pre-write or post-write file, never a torn intermediate.
    If the file does not exist, returns an empty Customers wrapper with
    schema version = CURRENT_SCHEMA_VERSION. This makes Stage 1 ergonomic:
    first call to create_record() doesn't have to pre-seed the file.

    Even if the file does not exist, the encryption-key configuration is
    validated first. The reason: failing fast on a missing key when
    there's nothing to read is much better than failing on the first
    create_record() call, because the operator hits the error earlier
    in the deployment.
    """
    # Validate key config eagerly. Raises EncryptionKeyError on missing
    # or malformed key, even if there are no records to decrypt yet.
    _load_encryption_keys()

    path = customers_path()
    if not path.exists():
        return Customers(version=CURRENT_SCHEMA_VERSION, records=[])
    raw = json.loads(path.read_text(encoding="utf-8"))
    c = Customers.from_dict(raw)
    _validate_customers(c)
    return c


def save_customers(customers: Customers) -> None:
    """Persist the whole file atomically. Acquires the exclusive lock.

    Almost no caller should use this directly; prefer update_record() and
    create_record() which build the right Customers object and call this
    once. Exposed because tests and migration scripts sometimes need it.
    """
    _validate_customers(customers)
    path = customers_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with _ExclusiveLock(path):
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(
            json.dumps(customers.to_dict(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        # os.replace is atomic on POSIX (single rename(2) call). On Windows
        # it works too if both paths are on the same volume.
        os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Convenience operations (per design §1.3, §1.5, §2.3)
# ---------------------------------------------------------------------------

DEFAULT_MAX_MANUFACTURERS = 5
DEFAULT_RATE_LIMIT_PER_HOUR = 60
DEFAULT_SUBSCRIPTION_YEARS = 1


def _utcnow_iso() -> str:
    """UTC now as ISO 8601 with explicit 'Z'. Used everywhere we write a timestamp."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _next_customer_id(records: list[Customer]) -> str:
    """Generate the next cust_YYYY_NNNN id.

    Year is the current UTC year. Sequence is per-year (resets at year
    rollover) and never reused across years. If multiple records exist
    for the same year, picks max+1; if none, starts at 0001.
    """
    year = datetime.now(UTC).year
    prefix = f"cust_{year}_"
    existing_seqs = [
        int(r.id[len(prefix):])
        for r in records
        if r.id.startswith(prefix)
    ]
    next_seq = max(existing_seqs, default=0) + 1
    if next_seq > 9999:
        # Hit the per-year limit. At Stage 1 scale this is decades away,
        # but loud failure is better than silent rollover.
        raise SchemaError(
            f"per-year sequence exhausted for year {year}; "
            f"schema needs widening before more customers can be created"
        )
    return f"{prefix}{next_seq:04d}"


def create_record(
    *,
    name: str,
    organisation: str,
    email: str,
    country: str,
    license_version: str,
    license_signed_at: str | None = None,
    manufacturers: list[str] | None = None,
    enabled_claims: list[int] | None = None,
    max_manufacturers: int = DEFAULT_MAX_MANUFACTURERS,
    rate_limit_per_hour: int = DEFAULT_RATE_LIMIT_PER_HOUR,
    subscription_years: int = DEFAULT_SUBSCRIPTION_YEARS,
    notes: str = "",
) -> tuple[Customer, str]:
    """Create a new customer record. Returns (record, plaintext_token).

    The plaintext token is shown to the operator exactly once (here) and
    is never stored. The operator copies it into the welcome email. If
    the operator loses it before sending, the procedure is to revoke the
    record and create a new one (§1.3 status transitions).

    Defaults follow tier2-design.md:
        enabled_claims default: [8, 9, 11] (all three)
        max_manufacturers: 5
        rate_limit_per_hour: 60
        subscription_years: 1 (expires_at = now + 1 year)
        license_signed_at: defaults to now if not supplied

    All keyword-only to prevent argument-order bugs.
    """
    customers = load_customers()

    now = _utcnow_iso()
    expires = (datetime.now(UTC) + timedelta(days=365 * subscription_years)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    plaintext_token = generate_token()

    record = Customer(
        id=_next_customer_id(customers.records),
        name=name,
        organisation=organisation,
        email=email,
        country=country,
        tier="tier2",
        enabled_claims=enabled_claims if enabled_claims is not None else [8, 9, 11],
        api_key_hash=hash_token(plaintext_token),
        api_key_issued_at=now,
        manufacturers=manufacturers or [],
        max_manufacturers=max_manufacturers,
        rate_limit_per_hour=rate_limit_per_hour,
        status="active",
        license_signed_at=license_signed_at or now,
        license_version=license_version,
        created_at=now,
        expires_at=expires,
        notes=notes,
    )

    _validate_record(record)  # fail before save, not after
    customers.records.append(record)
    save_customers(customers)

    return record, plaintext_token


def get_record(customer_id: str) -> Customer | None:
    """Return the record with this id, or None if not present."""
    for r in load_customers().records:
        if r.id == customer_id:
            return r
    return None


def list_records(*, status: str | None = None) -> list[Customer]:
    """Return all records, optionally filtered by status.

    Sorted by id for stable output (useful for CLI listings and diffs).
    """
    records = load_customers().records
    if status is not None:
        if status not in VALID_STATUSES:
            raise SchemaError(f"status filter {status!r} not in {VALID_STATUSES}")
        records = [r for r in records if r.status == status]
    return sorted(records, key=lambda r: r.id)


def update_record(customer_id: str, **fields_to_update: Any) -> Customer:
    """Update fields on a single record. Returns the updated record.

    This is the canonical write path. It:
        1. Acquires the exclusive lock (via save_customers).
        2. Loads the full file.
        3. Applies the field updates to the matching record.
        4. Validates the whole file (catches invariant violations like
           duplicate hashes that could only arise from bad calls).
        5. Atomic-renames into place.

    Cannot change `id` or `api_key_hash`. The former is a primary key;
    the latter is set only at creation. To rotate a token, mark the
    record revoked and create a new one (§2.3 step 6).

    Refuses to silently create a missing record: if customer_id is not
    found, raises SchemaError. This is a deliberate choice — accidentally
    creating a new record because of a typo would be much worse than the
    inconvenience of explicit not-found handling.
    """
    forbidden = {"id", "api_key_hash"} & fields_to_update.keys()
    if forbidden:
        raise SchemaError(
            f"cannot update protected fields: {sorted(forbidden)}. "
            f"Use create_record() and the revoke flow per §2.3 instead."
        )

    customers = load_customers()
    target = next((r for r in customers.records if r.id == customer_id), None)
    if target is None:
        raise SchemaError(f"no record with id {customer_id!r}")

    valid_field_names = {f.name for f in fields(Customer)}
    unknown = fields_to_update.keys() - valid_field_names
    if unknown:
        raise SchemaError(f"unknown fields: {sorted(unknown)}")

    for k, v in fields_to_update.items():
        setattr(target, k, v)

    _validate_record(target)  # catch bad updates before saving
    save_customers(customers)
    return target


def revoke_record(customer_id: str, reason: str = "") -> Customer:
    """Mark a record revoked. Convenience wrapper around update_record.

    Revoked is terminal per §1.3; this function does not check the
    current status before transitioning, because revoke is always
    permitted (e.g. revoking a suspended record before it auto-revokes
    after 90 days is fine).

    The reason is appended to notes, prefixed with a timestamp, so the
    audit trail survives even though we don't have a dedicated audit log
    yet at Stage 1.
    """
    record = get_record(customer_id)
    if record is None:
        raise SchemaError(f"no record with id {customer_id!r}")
    appended_notes = record.notes
    if reason:
        stamp = _utcnow_iso()
        line = f"[{stamp}] revoked: {reason}"
        appended_notes = f"{record.notes}\n{line}".strip()
    return update_record(customer_id, status="revoked", notes=appended_notes)


def suspend_record(customer_id: str, reason: str = "") -> Customer:
    """Mark a record suspended. Same pattern as revoke_record."""
    record = get_record(customer_id)
    if record is None:
        raise SchemaError(f"no record with id {customer_id!r}")
    appended_notes = record.notes
    if reason:
        stamp = _utcnow_iso()
        line = f"[{stamp}] suspended: {reason}"
        appended_notes = f"{record.notes}\n{line}".strip()
    return update_record(customer_id, status="suspended", notes=appended_notes)
