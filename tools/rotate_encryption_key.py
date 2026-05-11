#!/usr/bin/env python3
"""
Rotate the customer-database encryption key.

Usage:
    # 1. Generate a new key
    python tools/rotate_encryption_key.py --generate

    # 2. Stage the rotation: read with both keys, write with the new one.
    #    Records remain decryptable by either key during this phase.
    python tools/rotate_encryption_key.py --rotate

    # 3. After --rotate succeeds, set CUSTOMERS_ENCRYPTION_KEY to the new
    #    key alone and remove CUSTOMERS_ENCRYPTION_KEYS. Restart the service.

Rotation pattern (per ADR D14):

    Before rotation:
        CUSTOMERS_ENCRYPTION_KEY=<old>

    Step 1 — start dual-key phase:
        Generate new key (--generate prints it). Save in operator's
        password manager AND set both env vars:
            CUSTOMERS_ENCRYPTION_KEYS=<new>,<old>
        Unset CUSTOMERS_ENCRYPTION_KEY. Restart the service.
        At this point: reads use either key, writes use the new key.
        Existing records are still encrypted with the old key (until touched).

    Step 2 — re-encrypt:
        Run --rotate. This loads every record under MultiFernet (which
        tries each key), and writes it back. Because the first key in the
        rotation set is the new one, the write produces ciphertext under
        the new key.

    Step 3 — retire the old key:
        Set CUSTOMERS_ENCRYPTION_KEY=<new>. Unset CUSTOMERS_ENCRYPTION_KEYS.
        Restart the service. The old key is now retired and can be removed
        from the operator's records (or kept in cold storage for compliance).

Safety properties:

    - Each step is independently revert-able. If step 2 fails halfway, the
      file is whatever state os.replace() last committed to disk; any
      records still encrypted with the old key remain decryptable in the
      next attempt because old is still in the keyset.
    - Step 1 → 2 → 3 ordering matters: skipping step 2 retires the old key
      while records are still encrypted with it, breaking decrypt. The
      tool refuses to run --rotate if CUSTOMERS_ENCRYPTION_KEYS is not set
      (single-key mode means there's nothing to rotate to).

Copyright 2026 Andrew Broglio. Licensed under BSL 1.1.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tier2_customers import (
    CUSTOMERS_KEYS_ENV,
    EncryptionKeyError,
    SchemaError,
    customers_path,
    generate_encryption_key,
    load_customers,
    save_customers,
)


def _cmd_generate() -> int:
    """Print a fresh Fernet key. Nothing else."""
    print(generate_encryption_key())
    print()
    print("Save this key in your password manager.", file=sys.stderr)
    print(f"To stage rotation, set: {CUSTOMERS_KEYS_ENV}=<new>,<old>", file=sys.stderr)
    print("(The new key MUST be first. Restart the service. Then run --rotate.)", file=sys.stderr)
    return 0


def _cmd_rotate() -> int:
    """Re-encrypt every record under the current key set.

    Requires CUSTOMERS_ENCRYPTION_KEYS to be set with the new key as the
    first element. Reads every record (decrypting under whichever key it
    was originally encrypted with), then writes them all back. Because
    save_customers uses MultiFernet with the new key first, the write
    produces new-key ciphertext for every record.
    """
    if not os.environ.get(CUSTOMERS_KEYS_ENV):
        print(
            f"Refusing to rotate: {CUSTOMERS_KEYS_ENV} is not set. "
            f"This tool re-encrypts under the first key in {CUSTOMERS_KEYS_ENV}; "
            "if you have only one key set, there is nothing to rotate to.",
            file=sys.stderr,
        )
        return 1

    path = customers_path()
    if not path.exists():
        print(f"No customers file at {path}; nothing to rotate.")
        return 0

    try:
        customers = load_customers()
    except EncryptionKeyError as e:
        print(f"Key configuration error: {e}", file=sys.stderr)
        return 1
    except SchemaError as e:
        print(f"Failed to read customers: {e}", file=sys.stderr)
        print(
            "If this says 'Failed to decrypt', the old key may not be in "
            "your CUSTOMERS_ENCRYPTION_KEYS list. Add it before rotating.",
            file=sys.stderr,
        )
        return 1

    n = len(customers.records)
    print(f"Re-encrypting {n} record(s) under the new key (first in {CUSTOMERS_KEYS_ENV})...")
    try:
        save_customers(customers)
    except (EncryptionKeyError, SchemaError) as e:
        print(f"Rotation failed: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"I/O error during rotation: {e}", file=sys.stderr)
        return 2

    print(f"OK. {n} record(s) re-encrypted.")
    print()
    print("Next step: once you've confirmed the service is healthy with the", file=sys.stderr)
    print("new ciphertext, switch from CUSTOMERS_ENCRYPTION_KEYS=<new>,<old>", file=sys.stderr)
    print("back to CUSTOMERS_ENCRYPTION_KEY=<new>. Old key can then be retired.", file=sys.stderr)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--generate", action="store_true", help="Print a fresh Fernet key.")
    group.add_argument("--rotate", action="store_true", help="Re-encrypt all records under the current key set.")
    args = parser.parse_args()

    if args.generate:
        return _cmd_generate()
    return _cmd_rotate()


if __name__ == "__main__":
    sys.exit(main())
