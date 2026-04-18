"""
DTVSS temporal amplification constant (k) calibration.

Evaluates the four clinical criteria defined in the DTVSS provisional patent
paragraph [0025] across a sweep of candidate k values from 1 to 30, and reports
the lowest integer k for which all four criteria are satisfied.

The patent states:
  "k = 15 is the lowest value satisfying all four of the following clinical
   criteria... All k values below 15 fail criterion (i)."

This script is the executable record of that calibration. It reads a frozen
dataset snapshot (dataset.csv) produced by build_dataset.py and performs no
network I/O at runtime - the calibration must be reproducible, and live data
would cause k to drift as EPSS scores evolve.

DTVSS formula (non-KEV branch, patent [0018]):
    DTVSS(t) = min( (B/10) x (H/10) x (1 + k x L(t)) x 10, 10.0 )

Copyright 2026 Andrew Broglio. All rights reserved.
Patent Pending - IP Australia | Licensed under BSL 1.1
"""
from __future__ import annotations

import csv
import json
from pathlib import Path


# ---------------------------------------------------------------------------
# Scoring function
# ---------------------------------------------------------------------------
def dtvss_score(B: float, H: float, L: float, k: float) -> float:
    """DTVSS formula, non-KEV branch, capped at 10.0 (patent Equation 1)."""
    raw = (B / 10.0) * (H / 10.0) * (1.0 + k * L) * 10.0
    return min(raw, 10.0)


# ---------------------------------------------------------------------------
# Criteria from patent [0025]
# ---------------------------------------------------------------------------
def criterion_i(rows: list[dict], k: float) -> tuple[bool, float]:
    """
    (i) CVE-2017-12718 (B=2.20, L=0.2577, H=7.5) scores >= 8.0 Critical.
    Binding constraint. Patent: 'All k values below 15 fail criterion (i).'
    """
    row = next((r for r in rows if r["cve_id"] == "CVE-2017-12718"), None)
    if row is None:
        return (False, 0.0)
    score = dtvss_score(row["B"], row["H"], row["L"], k)
    return (score >= 8.0, score)


def criterion_ii(rows: list[dict], k: float) -> tuple[bool, float]:
    """
    (ii) All low-risk CVEs (B <= 1.5, L <= 0.002) score <= 5.5.
    Patent: 'the highest low-risk score in the dataset being 0.98'.
    Returns (pass, max_low_risk_score).
    """
    low_risk = [r for r in rows if r["B"] <= 1.5 and r["L"] <= 0.002]
    if not low_risk:
        return (True, 0.0)  # vacuously true if no low-risk CVEs present
    max_score = max(dtvss_score(r["B"], r["H"], r["L"], k) for r in low_risk)
    return (max_score <= 5.5, max_score)


def criterion_iii(rows: list[dict], k: float) -> tuple[bool, float]:
    """
    (iii) CVE-2020-11896 (B=3.90, L=0.4263, H=7.5) scores >= 8.0 Critical.
    Passes at lower k than criterion (i); not binding.
    """
    row = next((r for r in rows if r["cve_id"] == "CVE-2020-11896"), None)
    if row is None:
        return (False, 0.0)
    score = dtvss_score(row["B"], row["H"], row["L"], k)
    return (score >= 8.0, score)


def criterion_iv(rows: list[dict], k: float) -> tuple[bool, float]:
    """
    (iv) Score span across dataset >= 4.0 points.
    Patent observed span: 9.62 points.
    """
    scores = [dtvss_score(r["B"], r["H"], r["L"], k) for r in rows]
    if not scores:
        return (False, 0.0)
    span = max(scores) - min(scores)
    return (span >= 4.0, span)


def evaluate_all_criteria(rows: list[dict], k: float) -> dict:
    """Evaluate all four criteria at a given k. Returns full result dict."""
    i_pass, i_val = criterion_i(rows, k)
    ii_pass, ii_val = criterion_ii(rows, k)
    iii_pass, iii_val = criterion_iii(rows, k)
    iv_pass, iv_val = criterion_iv(rows, k)
    all_pass = i_pass and ii_pass and iii_pass and iv_pass
    return {
        "k": k,
        "i_pass": i_pass, "i_score": round(i_val, 3),
        "ii_pass": ii_pass, "ii_max_low_risk_score": round(ii_val, 3),
        "iii_pass": iii_pass, "iii_score": round(iii_val, 3),
        "iv_pass": iv_pass, "iv_span": round(iv_val, 3),
        "all_pass": all_pass,
    }


# ---------------------------------------------------------------------------
# Supplementary statistics (patent [0025])
# ---------------------------------------------------------------------------
def score_change_count(rows: list[dict], k: float) -> tuple[int, int]:
    """
    Patent [0025]: 'At k = 15, 95 of 96 CVEs change rank when L(t) is zeroed.'

    The patent's 'change rank' phrasing is a score-change metric: a CVE counts
    as changed when its score at k=k differs from its score with L forced to
    zero (the static baseline B*H/10).

    CVEs flagged as KEV-overridden are EXCLUDED from this metric by definition:
    under Equation 1 the KEV branch pins their score to 10.0 regardless of k
    or L, so they cannot 'change' when L is varied. In the filing-time 96-CVE
    dataset, exactly one CVE is KEV-overridden (CVE-2020-11899, Treck Ripple20,
    listed in the CISA KEV catalog since 2022-03-03). Excluding it leaves 95
    non-KEV CVEs, all 95 of which change score when L is zeroed. Expressed
    against the 96-CVE denominator this is 95 of 96.

    Returns (changed_count, non_kev_denominator).
    """
    non_kev = [r for r in rows if not r.get("kev_override", False)]
    changed = 0
    for r in non_kev:
        live = dtvss_score(r["B"], r["H"], r["L"], k)
        zero_L = dtvss_score(r["B"], r["H"], 0.0, k)
        if abs(live - zero_L) > 0.0001:
            changed += 1
    return (changed, len(non_kev))


def tier_crossing_count(rows: list[dict], k: float) -> int:
    """
    Patent: 'At k = 15, ... 34 CVEs cross risk tiers due to L(t), compared to
    zero tier crossings under the prior additive formula.'

    Returns the number of non-KEV CVEs whose risk tier differs when scored
    with live L(t) versus with L(t) forced to zero. KEV-overridden CVEs are
    excluded because their score is pinned to 10.0 Critical regardless of L.
    """
    def tier(score: float) -> str:
        if score < 3.0:
            return "Low"
        if score < 6.0:
            return "Medium"
        if score < 8.0:
            return "High"
        return "Critical"

    non_kev = [r for r in rows if not r.get("kev_override", False)]
    crossings = 0
    for r in non_kev:
        live = dtvss_score(r["B"], r["H"], r["L"], k)
        zero = dtvss_score(r["B"], r["H"], 0.0, k)
        if tier(live) != tier(zero):
            crossings += 1
    return crossings


# ---------------------------------------------------------------------------
# Main sweep
# ---------------------------------------------------------------------------
DATASET_PATH = Path(__file__).parent / "dataset.csv"
RESULTS_PATH = Path(__file__).parent / "results.json"


def load_dataset() -> list[dict]:
    """Load the frozen dataset CSV. Exits cleanly with a message if missing."""
    if not DATASET_PATH.exists():
        print(f"ERROR: {DATASET_PATH} not found.")
        print("Run build_dataset.py first to produce it.")
        raise SystemExit(1)

    rows = []
    with open(DATASET_PATH) as f:
        reader = csv.DictReader(f)
        for row in reader:
            kev_str = (row.get("kev_override") or "").strip().lower()
            rows.append({
                "cve_id": row["cve_id"],
                "vendor": row["vendor"],
                "B": float(row["B"]),
                "H": float(row["H"]),
                "L": float(row["epss"]),
                "class": row["class"],
                "kev_override": kev_str == "true",
                "source": row["source"],
            })
    return rows


def main():
    print("DTVSS temporal amplification constant (k) calibration")
    print("=" * 60)
    rows = load_dataset()

    # Dataset summary
    n = len(rows)
    iib = sum(1 for r in rows if r["class"] == "IIb")
    iii = sum(1 for r in rows if r["class"] == "III")
    missing_epss = sum(1 for r in rows if r["L"] == 0.0 and r["cve_id"] not in ("CVE-2017-12718", "CVE-2020-11896"))
    print(f"Dataset: {n} CVEs ({iib} Class IIb, {iii} Class III)")
    if missing_epss:
        print(f"WARNING: {missing_epss} CVEs have EPSS=0.0 - either genuinely zero")
        print(f"         or EPSS fetch failed when dataset.csv was built.")
        print(f"         Re-run build_dataset.py with network access if unsure.")
    print()

    # Sweep
    print("Sweeping k from 1 to 30...")
    sweep = []
    for k in range(1, 31):
        result = evaluate_all_criteria(rows, k)
        sweep.append(result)

    lowest_satisfying_k = next((r["k"] for r in sweep if r["all_pass"]), None)

    # Boundary table (show k=13..17 in detail so the transition is visible)
    print()
    print("Boundary table around the criterion (i) transition:")
    print()
    print(f"  {'k':>3} | {'(i)':^18} | {'(ii)':^18} | {'(iii)':^18} | {'(iv)':^18} | all")
    print(f"  {'-'*3}-+-{'-'*18}-+-{'-'*18}-+-{'-'*18}-+-{'-'*18}-+-----")
    for r in sweep:
        if 10 <= r["k"] <= 20:
            ci = f"{'PASS' if r['i_pass'] else 'FAIL'} s={r['i_score']:.2f}"
            cii = f"{'PASS' if r['ii_pass'] else 'FAIL'} m={r['ii_max_low_risk_score']:.2f}"
            ciii = f"{'PASS' if r['iii_pass'] else 'FAIL'} s={r['iii_score']:.2f}"
            civ = f"{'PASS' if r['iv_pass'] else 'FAIL'} sp={r['iv_span']:.2f}"
            allm = "PASS" if r["all_pass"] else "----"
            print(f"  {r['k']:>3} | {ci:^18} | {cii:^18} | {ciii:^18} | {civ:^18} | {allm}")

    print()
    if lowest_satisfying_k is not None:
        print(f"Lowest integer k satisfying all four criteria: k = {lowest_satisfying_k}")
    else:
        print("NO k in [1, 30] satisfies all four criteria.")
        print("This indicates the dataset does not reproduce the patent's conditions.")
        print("Most likely causes:")
        print("  - EPSS values in dataset.csv are all 0.0 (network failure during build)")
        print("  - Dataset composition differs materially from the patent's 96-CVE set")
        raise SystemExit(2)

    # Supplementary statistics at the chosen k
    print()
    kev_count = sum(1 for r in rows if r["kev_override"])
    sc_changed, sc_total = score_change_count(rows, lowest_satisfying_k)
    tc = tier_crossing_count(rows, lowest_satisfying_k)
    print(f"Supplementary statistics at k = {lowest_satisfying_k}:")
    print(f"  KEV-overridden CVEs (excluded from below metrics): {kev_count}")
    print(f"  Non-KEV CVEs whose score changes when L(t) zeroed: {sc_changed} / {sc_total}")
    print(f"    (expressed against full dataset: {sc_changed} of {n})")
    print(f"  Non-KEV CVEs crossing risk tiers due to L(t):      {tc}")
    print(f"  Patent claim at k=15, 96-CVE filing dataset:       95 of 96 score changes, 34 tier crossings")

    # Write full results.json
    with open(RESULTS_PATH, "w") as f:
        json.dump({
            "lowest_satisfying_k": lowest_satisfying_k,
            "dataset_size": n,
            "class_iib_count": iib,
            "class_iii_count": iii,
            "kev_overridden_count": kev_count,
            "non_kev_count": sc_total,
            "score_changes_non_kev": sc_changed,
            "tier_crossings_non_kev": tc,
            "sweep": sweep,
        }, f, indent=2)
    print()
    print(f"Full sweep written to {RESULTS_PATH}")


if __name__ == "__main__":
    main()
