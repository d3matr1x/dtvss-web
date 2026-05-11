#!/usr/bin/env python3
"""
List Tier 2 customer records.

Usage:
    python tools/customer_list.py                    # all records
    python tools/customer_list.py --status active    # filter by status
    python tools/customer_list.py --status suspended
    python tools/customer_list.py --status revoked
    python tools/customer_list.py --json             # machine-readable

Output is tabular by default, JSON with --json. Both formats are stable
across runs (records sorted by id). No plaintext tokens are ever shown
because the system does not store them.

Copyright 2026 Andrew Broglio. Licensed under BSL 1.1.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tier2_customers import (
    EncryptionKeyError,
    SchemaError,
    VALID_STATUSES,
    customers_path,
    list_records,
)


def _format_table(records: list) -> str:
    if not records:
        return "(no records)"
    rows = [
        ("ID", "STATUS", "ORG", "EMAIL", "EXPIRES", "CLAIMS", "MFGS"),
    ]
    for r in records:
        rows.append(
            (
                r.id,
                r.status,
                _truncate(r.organisation, 25),
                _truncate(r.email, 30),
                r.expires_at[:10],  # date only
                ",".join(str(c) for c in r.enabled_claims),
                str(len(r.manufacturers)),
            )
        )
    widths = [max(len(row[col]) for row in rows) for col in range(len(rows[0]))]
    out = []
    for i, row in enumerate(rows):
        out.append("  ".join(cell.ljust(widths[col]) for col, cell in enumerate(row)))
        if i == 0:
            out.append("  ".join("-" * widths[col] for col in range(len(rows[0]))))
    return "\n".join(out)


def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--status",
        choices=sorted(VALID_STATUSES),
        help="Filter to records with this status only.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of a human-readable table.",
    )
    args = parser.parse_args()

    try:
        records = list_records(status=args.status)
    except EncryptionKeyError as e:
        print(f"Encryption key error: {e}", file=sys.stderr)
        return 1
    except SchemaError as e:
        print(f"Validation error: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"I/O error: {e}", file=sys.stderr)
        return 2

    if args.json:
        out = {
            "path": str(customers_path()),
            "count": len(records),
            "records": [r.to_dict() for r in records],
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print(f"# {customers_path()} — {len(records)} record(s)")
        print()
        print(_format_table(records))
    return 0


if __name__ == "__main__":
    sys.exit(main())
