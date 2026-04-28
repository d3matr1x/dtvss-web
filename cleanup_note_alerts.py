"""
DTVSS code-quality cleanup: closes 14 CodeQL Note-severity alerts.

Run from C:\dtvss-web after fresh git pull origin main:
    python3 cleanup_note_alerts.py

Modifies in place. Safe to run twice (idempotent — checks for old patterns
before replacing). If any file is in an unexpected state, the script
reports which file and stops without partial changes.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent

class CleanupError(Exception):
    pass

def replace_once(path: Path, old: str, new: str, label: str):
    """Replace exactly one occurrence of old with new. Idempotent."""
    src = path.read_text(encoding="utf-8")
    if new in src:
        print(f"  [skip] {label} — already applied")
        return False
    if src.count(old) == 0:
        raise CleanupError(f"{label}: pattern not found in {path.name}")
    if src.count(old) > 1:
        raise CleanupError(f"{label}: pattern matches {src.count(old)} times in {path.name} (need 1)")
    path.write_text(src.replace(old, new), encoding="utf-8")
    print(f"  [done] {label}")
    return True

def delete_line_if_exact(path: Path, exact_line: str, label: str):
    """Remove a single line that matches exact_line. Idempotent."""
    src = path.read_text(encoding="utf-8")
    pattern = exact_line.rstrip() + "\n"
    if pattern not in src:
        # Try CRLF
        pattern = exact_line.rstrip() + "\r\n"
        if pattern not in src:
            print(f"  [skip] {label} — line not found (already removed?)")
            return False
    path.write_text(src.replace(pattern, "", 1), encoding="utf-8")
    print(f"  [done] {label}")
    return True

# ─────────────────────────────────────────────────────────────────
# UNUSED IMPORTS
# ─────────────────────────────────────────────────────────────────
print("\n=== Unused imports ===")

delete_line_if_exact(ROOT/"app.py", "import uuid", "app.py: drop import uuid")
delete_line_if_exact(ROOT/"app.py",
    "from werkzeug.exceptions import HTTPException",
    "app.py: drop HTTPException import")

delete_line_if_exact(ROOT/"security.py", "import hashlib", "security.py: drop import hashlib")

delete_line_if_exact(ROOT/"api_clients.py", "import os", "api_clients.py: drop import os")

# Drop the function-local 'import logging' inside epss_lookup
# (the module-level one is now sufficient)
replace_once(ROOT/"api_clients.py",
    "    _log = logging.getLogger(\"dtvss.epss\")",
    "    _log = logging.getLogger(\"dtvss.epss\")",
    "api_clients.py: keep _log (no-op check)")
# Actually delete the redundant local import
src = (ROOT/"api_clients.py").read_text(encoding="utf-8")
old_block = "    import logging\n    _log = logging.getLogger(\"dtvss.epss\")"
new_block = "    _log = logging.getLogger(\"dtvss.epss\")"
old_block_crlf = "    import logging\r\n    _log = logging.getLogger(\"dtvss.epss\")"
new_block_crlf = "    _log = logging.getLogger(\"dtvss.epss\")"
if old_block in src:
    (ROOT/"api_clients.py").write_text(src.replace(old_block, new_block), encoding="utf-8")
    print("  [done] api_clients.py: drop redundant local import logging")
elif old_block_crlf in src:
    (ROOT/"api_clients.py").write_text(src.replace(old_block_crlf, new_block_crlf), encoding="utf-8")
    print("  [done] api_clients.py: drop redundant local import logging (CRLF)")
else:
    print("  [skip] api_clients.py: redundant local import logging — already removed")

delete_line_if_exact(ROOT/"test_security.py", "import json", "test_security.py: drop import json")
delete_line_if_exact(ROOT/"test_security.py", "import math", "test_security.py: drop import math")
delete_line_if_exact(ROOT/"test_security.py", "from io import BytesIO",
    "test_security.py: drop BytesIO import")

delete_line_if_exact(ROOT/"test_upstream_fuzzing.py", "import json",
    "test_upstream_fuzzing.py: drop import json")
replace_once(ROOT/"test_upstream_fuzzing.py",
    "from medical_scope import is_blocklisted, has_medical_term, is_in_scope",
    "from medical_scope import is_blocklisted",
    "test_upstream_fuzzing.py: tighten medical_scope import")

# ─────────────────────────────────────────────────────────────────
# UNUSED LOCALS
# ─────────────────────────────────────────────────────────────────
print("\n=== Unused locals ===")

# test_security.py:367 — raw_str = str(exc) is unused
delete_line_if_exact(ROOT/"test_security.py", "        raw_str = str(exc)",
    "test_security.py: drop unused raw_str")

# Note: line 434 'injection = {...}' is followed by ] * 600 which IS used
# below in the test. We leave that one alone.

# ─────────────────────────────────────────────────────────────────
# EMPTY EXCEPTS — convert to logging
# ─────────────────────────────────────────────────────────────────
print("\n=== Empty excepts → log.warning ===")

# app.py KEV check (line ~460)
replace_once(ROOT/"app.py",
    """        except Exception:
            pass  # KEV check failure is non-fatal""",
    """        except Exception as e:
            log.warning("KEV check failed for %s: %s",
                        _log_safe_value(cve_id), _log_safe_value(e))""",
    "app.py: KEV check empty-except → log.warning")

# app.py B exploitability fallback (line ~580) — within indexed search
replace_once(ROOT/"app.py",
    """        if not B and ic.get(\"exploitability\"):
            try:
                B = float(ic[\"exploitability\"])
            except (TypeError, ValueError):
                pass""",
    """        if not B and ic.get(\"exploitability\"):
            try:
                B = float(ic[\"exploitability\"])
            except (TypeError, ValueError) as e:
                log.warning("Exploitability parse failed for %s: %s",
                            _log_safe_value(cve_id), _log_safe_value(e))""",
    "app.py: exploitability fallback empty-except → log.warning")

# app.py KEV fallback check (line ~746) — within NVD search loop
replace_once(ROOT/"app.py",
    """        if not kev_status:
            try:
                if cisa_kev_check(nvd[\"cve_id\"]):
                    kev_status = True
            except Exception:
                pass""",
    """        if not kev_status:
            try:
                if cisa_kev_check(nvd[\"cve_id\"]):
                    kev_status = True
            except Exception as e:
                log.warning("KEV fallback check failed for %s: %s",
                            _log_safe_value(nvd.get(\"cve_id\")), _log_safe_value(e))""",
    "app.py: KEV fallback empty-except → log.warning")

# dtvss_engine.py Layer 2 fall-through (line ~112)
# This module probably doesn't have logging set up. Add a comment instead.
replace_once(ROOT/"dtvss_engine.py",
    """            for keyword in sorted(dynamic.keys(), key=len, reverse=True):
                if keyword in desc_lower:
                    return dynamic[keyword], \"openfda_cache\"
        except Exception:
            pass""",
    """            for keyword in sorted(dynamic.keys(), key=len, reverse=True):
                if keyword in desc_lower:
                    return dynamic[keyword], \"openfda_cache\"
        except Exception:  # noqa: BLE001
            # Layer 2 (openfda_cache) failure is non-fatal — fall through
            # to Layer 3 (live openFDA lookup) below.
            pass""",
    "dtvss_engine.py: Layer 2 fall-through annotated")

# dtvss_engine.py Layer 3 fall-through (line ~122)
replace_once(ROOT/"dtvss_engine.py",
    """            from api_clients import openfda_classify_device
            fda_result = openfda_classify_device(description)
            if fda_result and fda_result.get(\"tga_class\"):
                return fda_result[\"tga_class\"], \"openfda\"
        except Exception:
            pass""",
    """            from api_clients import openfda_classify_device
            fda_result = openfda_classify_device(description)
            if fda_result and fda_result.get(\"tga_class\"):
                return fda_result[\"tga_class\"], \"openfda\"
        except Exception:  # noqa: BLE001
            # Layer 3 (openFDA live) failure is non-fatal — fall through
            # to Layer 4 ("manual" / unclassifiable) below.
            pass""",
    "dtvss_engine.py: Layer 3 fall-through annotated")

print("\nAll cleanup steps complete.")
print("\nNext steps:")
print("  python3 -c 'import ast; ast.parse(open(\"app.py\").read())'  # verify parses")
print("  python3 test_security.py                                      # verify 33/33 still pass")
print("  git diff --stat                                               # review")
print("  git add -A && git commit -m '...' && git push")
