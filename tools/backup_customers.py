#!/usr/bin/env python3
"""
Snapshot the customers.json file to a dated copy.

Usage:
    python tools/backup_customers.py

Runs nightly via cron (Railway scheduler or GitHub Actions). Belt-and-braces
companion to Railway's native scheduled volume backups (see design §1.6).
Produces a portable JSON file the operator can inspect, diff, and grep
without restoring a volume.

Path resolution:
    Source: customers_path() (CUSTOMERS_PATH env var or private/customers.json)
    Destination: <source-parent>/backups/customers-YYYYMMDD.json

If the source file does not exist, exits 0 (nothing to back up; not an error).
If the destination for today already exists, overwrites it. The day is the
unit of granularity by design — multiple writes during one day produce one
backup per day, the latest version of the file at the time of the snapshot.

Retention:
    This script does not delete old backups. Retention is the operator's
    responsibility (or a separate cleanup cron). At Stage 1 scale (a few
    KB per record) retention is effectively unbounded; revisit when the
    backup directory size becomes noticeable.

Exit codes:
    0   Backup written, or source did not exist.
    2   I/O error.

Copyright 2026 Andrew Broglio. Licensed under BSL 1.1.
"""
from __future__ import annotations

import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tier2_customers import customers_path


def main() -> int:
    src = customers_path()
    if not src.exists():
        print(f"No customers file at {src}; nothing to back up.")
        return 0

    backup_dir = src.parent / "backups"
    try:
        backup_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(f"Cannot create backup directory {backup_dir}: {e}", file=sys.stderr)
        return 2

    stamp = datetime.now(UTC).strftime("%Y%m%d")
    dst = backup_dir / f"customers-{stamp}.json"

    try:
        # shutil.copy2 preserves mtime, useful for diff-based change detection.
        # We do NOT acquire the customers lock: the source file is updated via
        # atomic rename, so any single read is consistent. A backup taken mid-
        # write captures either the pre-write or post-write state, never a
        # torn intermediate.
        shutil.copy2(src, dst)
    except OSError as e:
        print(f"Backup failed: {e}", file=sys.stderr)
        return 2

    print(f"Backed up {src} -> {dst}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
