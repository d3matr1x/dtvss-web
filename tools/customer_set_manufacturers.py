"""
DTVSS Tier 2 — CLI tool to update a customer's selected manufacturers
=====================================================================

Usage:
    python tools/customer_set_manufacturers.py CUST_2026_0001 baxter,philips
    python tools/customer_set_manufacturers.py CUST_2026_0001 --list
    python tools/customer_set_manufacturers.py CUST_2026_0001 --clear

The list of valid manufacturer slugs is sourced from the live MDM index
(index_loader.get_manufacturer_dropdown). A slug is valid iff it has at
least one CVE indexed. Invalid slugs are rejected with a clear error.

Changes are atomic: the customers.json file is updated via the same
locking + atomic-rename path used by customer_create.py, so concurrent
operations (CLI tools + Flask workers reading the file) stay consistent.

Copyright 2026 Andrew Broglio. Licensed under BSL 1.1.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow tools/ to import top-level modules. Adjust to your project layout.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tier2_customers import (  # noqa: E402
    EncryptionKeyError,
    SchemaError,
    customers_path,
    load_customers,
    update_record,
)

# The authoritative source of valid manufacturer slugs is the current
# MDM index. A manufacturer is "valid" iff it has at least one CVE
# indexed (status=="has_cves"). This means the list grows over time
# as new advisories arrive — no need to maintain a separate allowlist.
from index_loader import get_manufacturer_dropdown  # noqa: E402


def _get_valid_manufacturers() -> set[str]:
    """Build the set of valid manufacturer slugs from the live MDM index.

    Each entry's display_name is normalised to lowercase to match the
    convention used in customer.manufacturers.
    """
    try:
        dropdown = get_manufacturer_dropdown()
    except Exception as e:  # noqa: BLE001
        print(f"Warning: could not read manufacturer index: {e}", file=sys.stderr)
        print("Accepting any manufacturer slug without validation.", file=sys.stderr)
        return set()  # Empty set means "skip validation"
    return {item["name"].lower() for item in dropdown if item.get("name")}


def _parse_manufacturers(raw: str) -> list[str]:
    """Parse 'baxter,philips,medtronic' into a clean list."""
    if not raw:
        return []
    return [m.strip().lower() for m in raw.split(",") if m.strip()]


def _validate_manufacturers(manufacturers: list[str]) -> tuple[list[str], list[str]]:
    """Split provided slugs into (valid, invalid) buckets.
    Uses the live MDM index as the authoritative allowlist. If the index
    is unreadable, accepts all slugs (with a warning printed elsewhere).
    """
    supported = _get_valid_manufacturers()
    if not supported:
        # Fallback: accept all (warning was already printed)
        return list(manufacturers), []
    valid: list[str] = []
    invalid: list[str] = []
    for m in manufacturers:
        if m in supported:
            valid.append(m)
        else:
            invalid.append(m)
    return valid, invalid


def _show_current(customer_id: str) -> int:
    """Print the customer's current manufacturer list and exit."""
    try:
        customers = load_customers()
    except EncryptionKeyError as e:
        print(f"Encryption key error: {e}", file=sys.stderr)
        return 2
    except SchemaError as e:
        print(f"Customers file is malformed: {e}", file=sys.stderr)
        return 2

    for record in customers.records:
        if record.id == customer_id:
            print(f"Customer: {record.id}")
            print(f"  Organisation: {record.organisation}")
            print(f"  Status: {record.status}")
            print(f"  Manufacturers ({len(record.manufacturers)}):")
            for m in record.manufacturers:
                print(f"    - {m}")
            return 0

    print(f"Customer {customer_id} not found.", file=sys.stderr)
    return 1


def _set_manufacturers(customer_id: str, new_manufacturers: list[str]) -> int:
    """Update the customer's manufacturer list. Returns exit code."""
    # Validate against the live MDM index
    valid, invalid = _validate_manufacturers(new_manufacturers)
    if invalid:
        print(
            f"Unknown manufacturer slugs: {', '.join(invalid)}",
            file=sys.stderr,
        )
        supported = sorted(_get_valid_manufacturers())
        if supported:
            print(
                f"Currently indexed ({len(supported)}): {', '.join(supported)}",
                file=sys.stderr,
            )
        return 1

    try:
        # Read current state for the change-log line
        customers = load_customers()
        prev: list[str] = []
        for record in customers.records:
            if record.id == customer_id:
                prev = list(record.manufacturers)
                break
        else:
            print(f"Customer {customer_id} not found.", file=sys.stderr)
            return 1

        # Apply the update via tier2_customers.update_record (does its own
        # validation, locking, and atomic save). Raises SchemaError if
        # the customer ID doesn't exist (deliberate; doesn't silently create).
        updated = update_record(customer_id, manufacturers=valid)

    except EncryptionKeyError as e:
        print(f"Encryption key error: {e}", file=sys.stderr)
        return 2
    except SchemaError as e:
        # Could be "no record with id ..." (not found) or a validation
        # violation (e.g. exceeded max_manufacturers).
        print(f"Update rejected: {e}", file=sys.stderr)
        return 1
    except Exception as e:  # noqa: BLE001
        print(f"Update failed: {type(e).__name__}: {e}", file=sys.stderr)
        return 3

    print("=" * 60)
    print(f"UPDATED: {customer_id}")
    print("=" * 60)
    print(f"Customer:       {updated.organisation}")
    print(f"Status:         {updated.status}")
    print(f"  Previous:     {prev or '(none)'}")
    print(f"  New:          {updated.manufacturers or '(none)'}")
    added = sorted(set(updated.manufacturers) - set(prev))
    removed = sorted(set(prev) - set(updated.manufacturers))
    if added:
        print(f"  + Added:      {', '.join(added)}")
    if removed:
        print(f"  - Removed:    {', '.join(removed)}")
    print(f"  Storage:      {customers_path()}")
    print()
    print("Customer's next RSS feed fetch will reflect the new manufacturer list.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Update a Tier 2 customer's selected manufacturers.",
    )
    parser.add_argument(
        "customer_id",
        help="The customer ID (e.g. cust_2026_0001).",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "manufacturers",
        nargs="?",
        help="Comma-separated manufacturer slugs (e.g. baxter,philips).",
    )
    group.add_argument(
        "--list",
        action="store_true",
        help="Show the customer's current manufacturer list and exit.",
    )
    group.add_argument(
        "--clear",
        action="store_true",
        help="Remove all manufacturers from this customer (subscription stays "
             "active but feed will be empty until manufacturers are re-added).",
    )

    args = parser.parse_args()

    if args.list:
        return _show_current(args.customer_id)
    if args.clear:
        return _set_manufacturers(args.customer_id, [])
    if not args.manufacturers:
        parser.error("Provide manufacturers, --list, or --clear")
    return _set_manufacturers(args.customer_id, _parse_manufacturers(args.manufacturers))


if __name__ == "__main__":
    sys.exit(main())
