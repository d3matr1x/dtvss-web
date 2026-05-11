#!/usr/bin/env python3
"""
Create a new Tier 2 customer record.

Usage:
    python tools/customer_create.py

Runs interactively, prompting for each field. The plaintext token is shown
to the operator EXACTLY ONCE at the end. Copy it into the welcome email
before closing the terminal; it cannot be recovered.

This tool is the sole entry point for customer creation. Do not edit
customers.json by hand — every write must go through the library's
update_record / create_record (per tier2-design.md §1.7.1).

Environment:
    CUSTOMERS_PATH (optional) — overrides the default path.
                                Defaults to private/customers.json.
                                In production, set to /data/customers.json.

Exit codes:
    0   Customer created successfully.
    1   Validation error (bad input from operator).
    2   I/O error (filesystem, permissions).
    3   Operator cancelled at the confirmation prompt.

Copyright 2026 Andrew Broglio. Licensed under BSL 1.1.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Make the tier2_customers module importable whether this is run from
# repo root (`python tools/customer_create.py`) or from inside tools/.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tier2_customers import (
    DEFAULT_MAX_MANUFACTURERS,
    DEFAULT_RATE_LIMIT_PER_HOUR,
    DEFAULT_SUBSCRIPTION_YEARS,
    EncryptionKeyError,
    SchemaError,
    VALID_CLAIMS,
    create_record,
    customers_path,
)


def _prompt(label: str, *, default: str | None = None, required: bool = True) -> str:
    """Read a line from stdin with optional default. Strips whitespace."""
    suffix = f" [{default}]" if default else ""
    while True:
        value = input(f"{label}{suffix}: ").strip()
        if not value:
            if default is not None:
                return default
            if not required:
                return ""
            print("  Required. Please enter a value.")
            continue
        return value


def _prompt_int(label: str, *, default: int) -> int:
    while True:
        raw = _prompt(label, default=str(default))
        try:
            return int(raw)
        except ValueError:
            print(f"  Not a number: {raw!r}. Try again.")


def _prompt_list(label: str, *, default: list[str] | None = None) -> list[str]:
    """Comma-separated list. Empty input -> default (or [] if no default)."""
    default_str = ",".join(default) if default else ""
    raw = _prompt(label, default=default_str, required=False)
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def _prompt_claims() -> list[int]:
    """Specifically for enabled_claims. Default: all three (8, 9, 11)."""
    while True:
        raw = _prompt(
            "Enabled claims (comma-separated, subset of 8,9,11)",
            default="8,9,11",
        )
        try:
            claims = [int(x.strip()) for x in raw.split(",") if x.strip()]
        except ValueError:
            print(f"  Not all integers: {raw!r}. Try again.")
            continue
        invalid = set(claims) - VALID_CLAIMS
        if invalid:
            print(f"  Invalid claim numbers: {sorted(invalid)}. Valid: {sorted(VALID_CLAIMS)}")
            continue
        return claims


def _confirm(label: str) -> bool:
    raw = _prompt(label, default="n", required=False).lower()
    return raw in ("y", "yes")


def main() -> int:
    print("=" * 60)
    print("DTVSS Tier 2 — Customer Record Creation")
    print(f"Storage path: {customers_path()}")
    print("=" * 60)
    print()

    # ---- Required identity fields ----
    try:
        name = _prompt("Primary contact name")
        organisation = _prompt("Organisation")
        email = _prompt("Primary contact email")
        country = _prompt("Country (2-letter ISO code, e.g. AU)").upper()

        # ---- Licence ----
        license_version = _prompt(
            "Licence version (e.g. tier2-v1.0)",
            default="tier2-v1.0",
        )
        license_signed_at = _prompt(
            "Licence signed at (ISO 8601, blank for now)",
            required=False,
        ) or None

        # ---- Tier 2 configuration ----
        manufacturers = _prompt_list(
            "Manufacturers (comma-separated slugs, blank for none)",
            default=[],
        )
        enabled_claims = _prompt_claims()
        max_manufacturers = _prompt_int(
            "Max manufacturers", default=DEFAULT_MAX_MANUFACTURERS
        )
        rate_limit = _prompt_int(
            "Rate limit per hour", default=DEFAULT_RATE_LIMIT_PER_HOUR
        )
        years = _prompt_int(
            "Subscription duration in years", default=DEFAULT_SUBSCRIPTION_YEARS
        )

        # ---- Optional notes ----
        notes = _prompt("Operator notes (not shown to customer)", required=False)

        # ---- Confirmation ----
        print()
        print("Review:")
        print(f"  Name:                 {name}")
        print(f"  Organisation:         {organisation}")
        print(f"  Email:                {email}")
        print(f"  Country:              {country}")
        print(f"  Licence:              {license_version} signed {license_signed_at or '(now)'}")
        print(f"  Manufacturers:        {manufacturers or '(none)'}")
        print(f"  Enabled claims:       {enabled_claims}")
        print(f"  Max manufacturers:    {max_manufacturers}")
        print(f"  Rate limit/hour:      {rate_limit}")
        print(f"  Subscription years:   {years}")
        if notes:
            print(f"  Notes:                {notes}")
        print()

        if not _confirm("Create this record? (y/N)"):
            print("Cancelled.")
            return 3

        # ---- Create ----
        record, plaintext_token = create_record(
            name=name,
            organisation=organisation,
            email=email,
            country=country,
            license_version=license_version,
            license_signed_at=license_signed_at,
            manufacturers=manufacturers,
            enabled_claims=enabled_claims,
            max_manufacturers=max_manufacturers,
            rate_limit_per_hour=rate_limit,
            subscription_years=years,
            notes=notes,
        )

    except SchemaError as e:
        print(f"\nValidation error: {e}", file=sys.stderr)
        return 1
    except EncryptionKeyError as e:
        print(f"\nEncryption key error: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"\nI/O error: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 3

    # ---- Output (one-time plaintext token) ----
    print()
    print("=" * 60)
    print(f"CREATED: {record.id}")
    print("=" * 60)
    print()
    print(f"Customer ID:    {record.id}")
    print(f"Created at:     {record.created_at}")
    print(f"Expires at:     {record.expires_at}")
    print(f"Status:         {record.status}")
    print()
    print("  Plaintext token (shown ONCE — copy this NOW into the welcome email):")
    print()
    print(f"    {plaintext_token}")
    print()
    print(f"  Feed URL: https://dtvss.io/rss/feed/{plaintext_token}.xml")
    print()
    print("This token is not stored anywhere. If you lose it before sending the")
    print("welcome email, you must revoke this record and create a new one.")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
