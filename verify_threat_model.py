#!/usr/bin/env python3
"""
DTVSS Threat Model Verification Script
======================================

Checks every claim made in threat-model.md (v0.1) against the actual
repo state. Run this from the repo root (C:\\dtvss-web).

Usage:
    python verify_threat_model.py

Output: a table showing each claim, whether it was verified, and the
evidence found. Failed verifications are flagged so you know exactly
what to fix in the threat model before publishing.

Exit codes:
    0 = all automatic claims verified, manual claims documented
    1 = one or more automatic claims failed verification

This script ONLY READS files. It does not modify anything.
"""
import os
import re
import sys
from pathlib import Path

# Color codes for readable terminal output (Windows cmd supports these
# via VT processing on Win10+; falls back to plain text gracefully)
class C:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


def header(msg: str) -> None:
    print(f"\n{C.BOLD}{C.BLUE}=== {msg} ==={C.RESET}")


def status(label: str, result: bool, evidence: str, manual: bool = False) -> None:
    """Print a single check result."""
    if manual:
        marker = f"{C.YELLOW}MANUAL{C.RESET}"
    else:
        marker = f"{C.GREEN}PASS{C.RESET}" if result else f"{C.RED}FAIL{C.RESET}"
    print(f"  [{marker}] {label}")
    if evidence:
        print(f"          {C.BLUE}{evidence}{C.RESET}")


# Track failures so exit code is correct
failures = []
manual_required = []


def check_file_exists(path: str) -> bool:
    """Helper: does this file exist in the repo?"""
    return Path(path).is_file()


def grep_file(path: str, pattern: str) -> list[str]:
    """Helper: grep a file for pattern, return matching lines."""
    if not check_file_exists(path):
        return []
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        return [line.strip() for line in text.splitlines() if re.search(pattern, line)]
    except Exception as e:
        print(f"  Warning: couldn't read {path}: {e}")
        return []


# =============================================================================
# Verification checks
# =============================================================================

def check_security_py_claims() -> None:
    """Claims in the threat model about middleware in security.py."""
    header("security.py middleware claims")

    # CLAIM: ProxyFix middleware is in use
    matches = grep_file("security.py", r"ProxyFix|proxy_fix")
    ok = bool(matches)
    if not ok:
        failures.append("ProxyFix middleware claim")
    status(
        "ProxyFix middleware (XFF chain handling)",
        ok,
        f"Found {len(matches)} matching line(s)" if ok else "No ProxyFix references found"
    )

    # CLAIM: Per-request CSP nonce
    nonce_matches = grep_file("security.py", r"csp_nonce|CSP.*nonce")
    ok = bool(nonce_matches)
    if not ok:
        failures.append("Per-request CSP nonce claim")
    status(
        "Per-request CSP nonce generation",
        ok,
        f"Found {len(nonce_matches)} matching line(s)" if ok else "No CSP nonce references found"
    )

    # CLAIM: Content-type-aware CSP (added today)
    cta_matches = grep_file("security.py", r"is_html|response\.mimetype.*text/html")
    ok = bool(cta_matches)
    if not ok:
        failures.append("Content-type-aware CSP claim")
    status(
        "Content-type-aware CSP (HTML vs non-HTML branching)",
        ok,
        f"Found {len(cta_matches)} matching line(s)" if ok else "No content-type branching found"
    )

    # CLAIM: Cross-Origin-Resource-Policy header
    corp_matches = grep_file("security.py", r"Cross-Origin-Resource-Policy")
    ok = bool(corp_matches)
    if not ok:
        failures.append("CORP header claim")
    status(
        "Cross-Origin-Resource-Policy header set",
        ok,
        f"Found {len(corp_matches)} matching line(s)" if ok else "No CORP header found"
    )

    # CLAIM: HSTS conditional on HTTPS
    hsts_matches = grep_file("security.py", r"Strict-Transport-Security")
    ok = bool(hsts_matches)
    if not ok:
        failures.append("HSTS header claim")
    status(
        "Strict-Transport-Security header",
        ok,
        f"Found {len(hsts_matches)} matching line(s)" if ok else "No HSTS header found"
    )


def check_dependency_claims() -> None:
    """Claims about which Python packages are in use."""
    header("Python dependency claims")

    # CLAIM: Flask-Limiter is the rate-limiter
    req_files = ["requirements.txt", "requirements-lock.txt"]
    found_in = []
    for f in req_files:
        if grep_file(f, r"^[Ff]lask[-_][Ll]imiter|^[Ll]imits"):
            found_in.append(f)
    ok = bool(found_in)
    if not ok:
        # Maybe it's referenced in security.py instead
        py_match = grep_file("security.py", r"flask_limiter|Flask-Limiter|Limiter")
        if py_match:
            found_in.append("security.py (import)")
            ok = True
    if not ok:
        failures.append("Flask-Limiter claim")
    status(
        "Flask-Limiter (rate limiting)",
        ok,
        f"Found in: {', '.join(found_in)}" if ok else "Flask-Limiter not found in requirements or imports"
    )

    # CLAIM: gunicorn is the WSGI server (mentioned in threat model)
    found_in = []
    for f in req_files + ["Procfile", "railpack.json"]:
        if grep_file(f, r"gunicorn"):
            found_in.append(f)
    ok = bool(found_in)
    if not ok:
        failures.append("gunicorn WSGI claim")
    status(
        "gunicorn WSGI server",
        ok,
        f"Found in: {', '.join(found_in)}" if ok else "gunicorn not found in deployment files"
    )

    # CLAIM: Werkzeug (implied by Flask + ProxyFix)
    found = bool(grep_file("requirements-lock.txt", r"[Ww]erkzeug")) or \
            bool(grep_file("requirements.txt", r"[Ww]erkzeug")) or \
            bool(grep_file("security.py", r"werkzeug"))
    if not found:
        failures.append("Werkzeug claim")
    status(
        "Werkzeug (provides ProxyFix)",
        found,
        "Verified via imports or requirements" if found else "Werkzeug not found"
    )


def check_workflow_claims() -> None:
    """Claims about CI workflows."""
    header("GitHub Actions workflow claims")

    workflows = {
        "Calibration CI (asserts patent values)": ".github/workflows/calibration.yml",
        "Daily dependency-audit (pip-audit + Safety)": ".github/workflows/dependency-audit.yml",
        "Nightly ZAP baseline scan": ".github/workflows/zap-baseline.yml",
        "Dependency-review-action on PRs": ".github/workflows/dependency-review.yml",
        "CodeQL on every push": ".github/workflows/codeql.yml",
    }

    for label, path in workflows.items():
        ok = check_file_exists(path)
        if not ok:
            # CodeQL might be auto-configured, no file needed - flag manual instead
            if "CodeQL" in label:
                manual_required.append(f"{label} (auto-config, verify in GitHub Actions tab)")
                status(label, False, "Workflow file not found; if CodeQL is GitHub-managed default, mark MANUAL", manual=True)
                continue
            failures.append(label)
        status(label, ok, f"File exists at {path}" if ok else f"NOT FOUND: {path}")


def check_html_claims() -> None:
    """Claims about HTML page contents."""
    header("HTML page claims")

    # CLAIM: SRI on React + React-DOM in calculator.html
    integrity_lines = grep_file("static/calculator.html", r'integrity="sha384-')
    ok = len(integrity_lines) >= 2
    if not ok:
        failures.append("SRI on React/React-DOM claim")
    status(
        "SRI on React + React-DOM (2 integrity attrs in calculator.html)",
        ok,
        f"Found {len(integrity_lines)} integrity= attributes" if ok else "Fewer than 2 SRI hashes found"
    )

    # CLAIM: Turnstile script in index.html and calculator.html (intentional, no SRI)
    turnstile_idx = grep_file("static/index.html", r"challenges\.cloudflare\.com/turnstile")
    turnstile_calc = grep_file("static/calculator.html", r"challenges\.cloudflare\.com/turnstile")
    ok = bool(turnstile_idx) and bool(turnstile_calc)
    if not ok:
        failures.append("Turnstile presence claim")
    status(
        "Cloudflare Turnstile loaded on /index and /calculator",
        ok,
        "Found on both pages" if ok else f"index: {len(turnstile_idx)}, calculator: {len(turnstile_calc)}"
    )

    # CLAIM: No SRI on Turnstile (deliberate)
    turnstile_with_sri = grep_file("static/index.html", r"turnstile.*integrity") + \
                        grep_file("static/calculator.html", r"turnstile.*integrity")
    ok = not bool(turnstile_with_sri)
    if not ok:
        failures.append("Turnstile-without-SRI claim")
    status(
        "Turnstile script deliberately NOT SRI-pinned",
        ok,
        "Confirmed: no integrity attribute on turnstile script" if ok else "WARNING: SRI on turnstile would break it"
    )


def check_data_source_claims() -> None:
    """Claims about how MDM index is built."""
    header("Data source claims")

    # CLAIM: MDM index from CISA CSAF + ICSMA RSS + NVD
    found_sources = []
    for source_name, pattern in [
        ("CISA CSAF", r"csaf|cisa.*csaf"),
        ("ICSMA RSS", r"icsma|ics-cert\.us-cert"),
        ("NVD", r"nvd|nist\.gov"),
    ]:
        for f in ["build_index.py", "build_dataset.py", "api_clients.py"]:
            matches = grep_file(f, pattern)
            if matches:
                found_sources.append(f"{source_name} (in {f})")
                break

    ok = len(found_sources) >= 2
    if not ok:
        failures.append("Data source diversity claim")
    status(
        "MDM index aggregates CISA CSAF + ICSMA + NVD",
        ok,
        f"Confirmed sources: {', '.join(found_sources)}" if found_sources else "No data source code references found"
    )

    # CLAIM: MDM index file exists
    mdm_idx = check_file_exists("static/data/mdm_index.json") or check_file_exists("mdm_index.json")
    if not mdm_idx:
        failures.append("MDM index file claim")
    status(
        "MDM index file present in repo",
        mdm_idx,
        "Found mdm_index.json" if mdm_idx else "NOT FOUND"
    )


def check_manual_items() -> None:
    """Items that cannot be verified from code alone - manual checks required.

    Reads `.threat_model_manuals.json` for items previously verified
    against the relevant platform. The file is a list of objects:

        [
          {"label": "DNSSEC enabled for dtvss.io",
           "verified_on": "2026-05-09",
           "verified_by": "Andrew Broglio",
           "evidence": "Registrar dashboard screenshot in private/audit/"},
          ...
        ]

    A label present in the manifest with a `verified_on` date is reported
    as VERIFIED and counted toward an informational total, not toward
    `manual_required`. Items NOT in the manifest are reported as PENDING
    and counted toward `manual_required` (and surfaced in the summary).

    This means the script's summary line accurately reflects what is
    still outstanding, instead of always showing "11 manual items still
    need walking through" after every one has been confirmed.
    """
    header("Manual verification (platform-side)")

    # Canonical list of manual checks. Order is stable so the manifest
    # is diffable. To retire a check, remove it here AND from the manifest.
    manual_checks = [
        ("DNSSEC enabled for dtvss.io", "Your DNS provider's dashboard - look for 'DNSSEC' under domain settings"),
        ("CAA records configured", "DNS provider - look for 'CAA' record type"),
        ("GitHub 2FA enforced for the d3matr1x account", "GitHub.com -> Settings -> Password & authentication"),
        ("Branch protection on main", "GitHub repo -> Settings -> Branches -> Branch protection rules"),
        ("Required signed commits", "Same as above - 'Require signed commits' option"),
        ("GitHub secret scanning enabled", "GitHub repo -> Settings -> Code security -> Secret scanning"),
        ("Railway 2FA enabled", "Railway -> Account -> Security"),
        ("Cloudflare 2FA + hardware key", "Cloudflare -> Account -> Authentication"),
        ("Cloudflare 5 custom WAF rules active", "Cloudflare -> Security -> WAF -> Custom rules"),
        ("Domain registrar 2FA", "Your registrar's account settings"),
        ("Pre-commit hooks configured", "Check .git/hooks/ or pre-commit-config.yaml"),
    ]

    # Load the manifest if present. Tolerant of missing file (first run).
    manifest_path = Path(".threat_model_manuals.json")
    verified_by_label = {}
    stale_in_manifest = []
    if manifest_path.is_file():
        try:
            import json
            entries = json.loads(manifest_path.read_text(encoding="utf-8"))
            canonical_labels = {label for label, _ in manual_checks}
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                label = entry.get("label", "")
                if not label:
                    continue
                if label not in canonical_labels:
                    # Manifest references a label we no longer check.
                    # Surface it but don't fail the build.
                    stale_in_manifest.append(label)
                    continue
                verified_by_label[label] = entry
        except Exception as e:
            print(f"  {C.YELLOW}Warning:{C.RESET} could not parse {manifest_path}: {e}")
            print(f"  Treating all manual items as PENDING.")

    pending = 0
    verified = 0
    for label, where in manual_checks:
        entry = verified_by_label.get(label)
        if entry:
            verified += 1
            on = entry.get("verified_on", "date?")
            by = entry.get("verified_by", "")
            ev = entry.get("evidence", "")
            evidence = f"VERIFIED on {on}"
            if by:
                evidence += f" by {by}"
            if ev:
                evidence += f" ({ev})"
            # Re-use the manual marker style but with a verified evidence
            # string - same visual lane, different content.
            status(label, True, evidence, manual=True)
        else:
            pending += 1
            manual_required.append(label)
            status(label, False, f"PENDING. Verify at: {where}", manual=True)

    if stale_in_manifest:
        print()
        print(f"  {C.YELLOW}Note:{C.RESET} manifest contains {len(stale_in_manifest)} entries that")
        print(f"  no longer correspond to any current manual check:")
        for label in stale_in_manifest:
            print(f"    - {label}")
        print(f"  Prune these from .threat_model_manuals.json when convenient.")

    # Stash totals for the summary
    check_manual_items.totals = (verified, pending)


def main() -> int:
    """Run all checks and produce summary."""
    print(f"{C.BOLD}DTVSS Threat Model Verification{C.RESET}")
    print(f"Repo root: {os.getcwd()}")
    print()

    # Sanity check: are we in the repo?
    if not check_file_exists("security.py") and not check_file_exists("app.py"):
        print(f"{C.RED}ERROR: This doesn't look like the dtvss-web repo root.{C.RESET}")
        print(f"Run this from C:\\dtvss-web (or wherever security.py lives).")
        return 1

    check_security_py_claims()
    check_dependency_claims()
    check_workflow_claims()
    check_html_claims()
    check_data_source_claims()
    check_manual_items()

    # Summary
    header("Summary")
    if failures:
        print(f"  {C.RED}{len(failures)} automatic check(s) FAILED:{C.RESET}")
        for f in failures:
            print(f"    - {f}")
        print()
        print(f"  {C.RED}Action required:{C.RESET} Update threat-model.md to remove or correct these claims.")
    else:
        print(f"  {C.GREEN}All automatic checks PASSED.{C.RESET}")

    print()
    verified, pending = getattr(check_manual_items, "totals", (0, 0))
    if pending == 0:
        print(f"  {C.GREEN}All {verified} manual verification(s) recorded as VERIFIED{C.RESET}")
        print(f"  in .threat_model_manuals.json.")
    else:
        print(f"  {C.YELLOW}{pending} manual verification(s) PENDING:{C.RESET}")
        print(f"  Walk through each on the relevant platform, then record")
        print(f"  the result in .threat_model_manuals.json (see check_manual_items")
        print(f"  docstring for schema).")
        if verified:
            print(f"  ({verified} already recorded as verified.)")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
