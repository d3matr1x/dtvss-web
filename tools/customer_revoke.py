#!/usr/bin/env python3
"""
Revoke a Tier 2 customer record.

Usage:
    python tools/customer_revoke.py cust_2026_0001
    python tools/customer_revoke.py cust_2026_0001 --reason "subscription not renewed"
    python tools/customer_revoke.py cust_2026_0001 --suspend

Revoke is terminal (per design §1.3). Suspend is reversible. Pick the
right one: if the customer might pay you in the next 90 days, suspend;
if the relationship is over, revoke.

This tool refuses to run without an explicit reason in interactive use,
because "why did we revoke this" is the question you'll be asked when
investigating an incident three months later. The reason is appended to
the record's notes with a timestamp.

Exit codes:
    0   State transition applied successfully.
    1   Validation error or record not found.
    2   I/O error.
    3   Operator cancelled at the confirmation prompt.

Copyright 2026 Andrew Broglio. Licensed under BSL 1.1.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tier2_customers import (
    EncryptionKeyError,
    SchemaError,
    customers_path,
    get_record,
    revoke_record,
    suspend_record,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("customer_id", help="The customer id to act on (e.g. cust_2026_0001).")
    parser.add_argument(
        "--reason",
        default="",
        help="Reason for the action. Required interactively; appended to record notes.",
    )
    parser.add_argument(
        "--suspend",
        action="store_true",
        help="Suspend instead of revoke. Suspension is reversible; revocation is terminal.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Skip the interactive confirmation prompt. Use in scripts only.",
    )
    args = parser.parse_args()

    try:
        record = get_record(args.customer_id)
    except EncryptionKeyError as e:
        print(f"Encryption key error: {e}", file=sys.stderr)
        return 1
    except SchemaError as e:
        print(f"Validation error: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"I/O error: {e}", file=sys.stderr)
        return 2

    if record is None:
        print(f"No record with id {args.customer_id!r}.", file=sys.stderr)
        print(f"(Storage path: {customers_path()})", file=sys.stderr)
        return 1

    action = "suspend" if args.suspend else "revoke"
    reason = args.reason

    if not args.force:
        print(f"Storage path: {customers_path()}")
        print()
        print(f"Record:        {record.id}")
        print(f"Organisation:  {record.organisation}")
        print(f"Email:         {record.email}")
        print(f"Current status:{record.status}")
        print(f"Action:        {action}")
        print()
        if not reason:
            reason = input("Reason (required): ").strip()
            if not reason:
                print("Reason is required interactively. Cancelled.", file=sys.stderr)
                return 3
        confirm = input(f"Apply {action} to {record.id}? (y/N): ").strip().lower()
        if confirm not in ("y", "yes"):
            print("Cancelled.")
            return 3

    try:
        if args.suspend:
            updated = suspend_record(args.customer_id, reason=reason)
        else:
            updated = revoke_record(args.customer_id, reason=reason)
    except EncryptionKeyError as e:
        print(f"Encryption key error: {e}", file=sys.stderr)
        return 1
    except SchemaError as e:
        print(f"Validation error: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"I/O error: {e}", file=sys.stderr)
        return 2

    print(f"OK: {updated.id} -> {updated.status}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
