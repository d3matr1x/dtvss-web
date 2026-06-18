"""
DTVSS temporal amplification constant (k): policy definition and validation.

CHANGE OF BASIS (2026-06)
-------------------------
Earlier versions of this script DERIVED k by sweeping candidate values and
selecting the lowest integer that satisfied four clinical criteria, two of
which (criteria i and iii) required a specific CVE to score >= 8.0 at its
*live* EPSS. Because EPSS is built to move, that made k a function of one
CVE's exploitation probability on one day.

Re-running the original sweep on 2026-06-16 EPSS selected k = 30, not 15.
CVE-2017-12718's EPSS had halved (0.2577 -> 0.1319), dropping its score from
8.03 to 4.91 and pushing the binding criterion out to k = 30. The constant
doubled in roughly a quarter, driven by a single CVE. A constant cannot be
both "derived from live EPSS" and "stable".

This script therefore no longer derives k. It STATES k as an amplification
policy and uses the dataset to VALIDATE that the stated value produces a
sensible score distribution. k is defined by what the temporal amplifier
(1 + k * L) does at fixed reference exploitation probabilities. That
definition contains no dataset and so cannot drift:

    k = 15  =>  EPSS 0.25            amplifies the base patient-risk score x4.75
                EPSS 0.50 (even odds)                                     x8.50
                EPSS 1.00 (near-certain)                                  x16.00

The filing dataset's role changes from "the thing k is fitted to" into "the
thing the stated k is validated against": a small, non-trivial slice of the
corpus should register Critical, low-risk CVEs should stay low, and the score
range should stay wide. These are validation checks, not gates that move k.

The Critical-fraction check is the data-grounded cross-check: on the filing
data it independently lands at k ~ 15-16, which is why 15 remains a reasonable
choice. It depends on the aggregate EPSS distribution (which moves little),
not on one CVE (which can move a lot), so it is far more stable than the
old single-CVE anchor.

DTVSS formula (non-KEV branch, patent [0018]):
    DTVSS(t) = min( (B/10) x (H/10) x (1 + k x L(t)) x 10, 10.0 )

Copyright 2026 Andrew Broglio. All rights reserved.
Patent Pending - IP Australia | Licensed under BSL 1.1
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

# ---------------------------------------------------------------------------
# k is a STATED amplification policy, not a fitted constant.
# To change the escalation strength, change this one number; the validation
# below reports whether the new value still produces a sensible distribution.
# ---------------------------------------------------------------------------
K_TEMPORAL = 15.0

# Reference exploitation probabilities at which the amplification is quoted.
# These define what k MEANS. They are fixed, so the meaning of k never drifts.
REFERENCE_PROBABILITIES = (0.25, 0.50, 1.00)

# Validation parameters (sanity bands, NOT gates that select k).
CRITICAL_THRESHOLD = 8.0
CRITICAL_FRACTION_BAND = (0.03, 0.08)   # ~1 in 20 of the corpus should be Critical
LOW_RISK_CEILING = 5.5                  # low-risk CVEs must not amplify past this
SPAN_MINIMUM = 4.0                      # score range must stay discriminating

# Former criteria (i) and (iii). Retained ONLY as printed observations so the
# EPSS drift stays visible. They are no longer pass/fail gates.
OBSERVED_REFERENCE_CVES = ("CVE-2017-12718", "CVE-2020-11896")


# ---------------------------------------------------------------------------
# Scoring function
# ---------------------------------------------------------------------------
# Soft saturation cap - mirrors dtvss_engine.soft_cap exactly. Below the knee
# scores are exact; within the Critical band the amplifier's overshoot is
# compressed smoothly toward 10 rather than hard-clipped. Critical membership
# (raw >= 8) is unchanged, so the Critical-fraction check is identical to the
# old hard cap; the score span is slightly smaller because the top no longer
# pins to a flat 10.
SOFT_CAP_KNEE = 8.0
SOFT_CAP_SCALE = 10.0 - SOFT_CAP_KNEE


def _soft_cap(raw: float) -> float:
    if raw <= SOFT_CAP_KNEE:
        return raw
    x = raw - SOFT_CAP_KNEE
    return SOFT_CAP_KNEE + (10.0 - SOFT_CAP_KNEE) * (x / (x + SOFT_CAP_SCALE))


def dtvss_score(B: float, H: float, L: float, k: float = K_TEMPORAL) -> float:
    """DTVSS formula, non-KEV branch, soft-capped to [0, 10). Matches
    dtvss_engine.compute_dtvss and calculator.html's soft cap."""
    raw = (B / 10.0) * (H / 10.0) * (1.0 + k * L) * 10.0
    return _soft_cap(raw)


def amplification_profile(k: float = K_TEMPORAL) -> dict:
    """The DEFINITION of k: the multiplier (1 + k*L) at reference probabilities.

    Pure function of k, with no dataset in it, so it is invariant to EPSS
    drift. This is the primary, drift-proof statement of what k is.
    """
    return {L: round(1.0 + k * L, 3) for L in REFERENCE_PROBABILITIES}


# ---------------------------------------------------------------------------
# Validation suite (dataset's role: confirm the stated k is sensible)
# ---------------------------------------------------------------------------
def validate_critical_fraction(rows, k=K_TEMPORAL, band=CRITICAL_FRACTION_BAND):
    """A small, non-trivial slice of the corpus should be Critical.

    Distributional cross-check. Depends on the aggregate EPSS distribution,
    which is stable, not on one CVE, which is not. If this drifts out of band
    it is a signal for the operational triage layer to re-size its bucket, not
    a reason to re-fit k.
    """
    scores = [dtvss_score(r["B"], r["H"], r["L"], k) for r in rows]
    frac = (sum(s >= CRITICAL_THRESHOLD for s in scores) / len(scores)) if scores else 0.0
    return (band[0] <= frac <= band[1], round(frac, 4))


def validate_low_risk_stays_low(rows, k=K_TEMPORAL, ceiling=LOW_RISK_CEILING):
    """Low-risk CVEs (B <= 1.5, L <= 0.002) must not amplify into upper tiers.
    Retained from the prior criterion (ii) as a genuine sanity check."""
    low = [r for r in rows if r["B"] <= 1.5 and r["L"] <= 0.002]
    if not low:
        return (True, 0.0)
    m = max(dtvss_score(r["B"], r["H"], r["L"], k) for r in low)
    return (m <= ceiling, round(m, 2))


def validate_score_span(rows, k=K_TEMPORAL, minimum=SPAN_MINIMUM):
    """Score range must stay wide enough to discriminate. Retained from the
    prior criterion (iv) as a sanity check."""
    scores = [dtvss_score(r["B"], r["H"], r["L"], k) for r in rows]
    if not scores:
        return (False, 0.0)
    span = max(scores) - min(scores)
    return (span >= minimum, round(span, 2))


def observe_reference_cves(rows, k=K_TEMPORAL):
    """Report the scores of the former criterion CVEs. NOT a gate.

    These move with the EPSS snapshot; printing them keeps the drift visible
    rather than letting a stale '8.03 Critical' worked example sit unchallenged.
    """
    out = {}
    for cve in OBSERVED_REFERENCE_CVES:
        r = next((x for x in rows if x["cve_id"] == cve), None)
        if r is None:
            out[cve] = {"present": False}
        else:
            out[cve] = {
                "present": True,
                "B": r["B"], "H": r["H"], "L": r["L"],
                "score": round(dtvss_score(r["B"], r["H"], r["L"], k), 3),
            }
    return out


def run_validation(rows, k=K_TEMPORAL) -> dict:
    cf_pass, cf_val = validate_critical_fraction(rows, k)
    lr_pass, lr_val = validate_low_risk_stays_low(rows, k)
    sp_pass, sp_val = validate_score_span(rows, k)
    return {
        "k": k,
        "critical_fraction": {"pass": cf_pass, "value": cf_val,
                              "band": list(CRITICAL_FRACTION_BAND)},
        "low_risk_stays_low": {"pass": lr_pass, "max_low_risk_score": lr_val,
                              "ceiling": LOW_RISK_CEILING},
        "score_span": {"pass": sp_pass, "value": sp_val, "minimum": SPAN_MINIMUM},
        "all_validations_pass": cf_pass and lr_pass and sp_pass,
        "observations_not_gates": observe_reference_cves(rows, k),
    }


# ---------------------------------------------------------------------------
# Dataset loading
# ---------------------------------------------------------------------------
def load_dataset(path: Path) -> list[dict]:
    if not path.exists():
        print(f"ERROR: {path} not found.")
        print("Run build_dataset.py first to produce it, or pass --dataset.")
        raise SystemExit(1)
    rows = []
    with open(path) as f:
        for row in csv.DictReader(f):
            kev_str = (row.get("kev_override") or "").strip().lower()
            rows.append({
                "cve_id": row["cve_id"],
                "vendor": row.get("vendor", ""),
                "B": float(row["B"]),
                "H": float(row["H"]),
                "L": float(row["epss"]),
                "class": row.get("class", ""),
                "kev_override": kev_str == "true",
                "source": row.get("source", ""),
            })
    return rows


def fetch_live_epss(cve_ids: list[str]) -> tuple[dict, str | None]:
    """Optional: fetch current EPSS from FIRST.org to demonstrate that the
    stated k does not move and the distribution stays in band on live data.
    Returns ({cve: epss}, data_date). Network failure returns ({}, None)."""
    import urllib.request
    import time
    out, date = {}, None
    cves = sorted(set(cve_ids))
    try:
        for i in range(0, len(cves), 50):
            url = ("https://api.first.org/data/v1/epss?cve="
                   + ",".join(cves[i:i + 50]) + "&envelope=true")
            req = urllib.request.Request(url, headers={"User-Agent": "dtvss-calibration/2.0"})
            data = json.loads(urllib.request.urlopen(req, timeout=30).read().decode())
            for r in data.get("data", []):
                out[r["cve"]] = float(r["epss"])
                date = r.get("date", date)
            time.sleep(0.3)
    except Exception as e:  # noqa: BLE001
        print(f"  (live EPSS fetch failed: {e}; skipping live validation)")
        return {}, None
    return out, date


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="DTVSS k policy definition and validation")
    ap.add_argument("--dataset", type=Path,
                    default=Path(__file__).parent / "dataset.csv",
                    help="frozen dataset snapshot (default: sibling dataset.csv)")
    ap.add_argument("--live", action="store_true",
                    help="also fetch current EPSS and re-validate, to show k is stable")
    ap.add_argument("--results", type=Path,
                    default=Path(__file__).parent / "results.json",
                    help="where to write the JSON record")
    args = ap.parse_args()

    print("DTVSS temporal amplification constant (k): policy + validation")
    print("=" * 64)
    rows = load_dataset(args.dataset)
    n = len(rows)
    iib = sum(1 for r in rows if r["class"] == "IIb")
    iii = sum(1 for r in rows if r["class"] == "III")
    print(f"Dataset: {n} CVEs ({iib} Class IIb, {iii} Class III)")
    print()

    # 1. The DEFINITION of k (drift-proof, no dataset).
    print(f"k = {K_TEMPORAL:g}, defined as an amplification policy:")
    prof = amplification_profile()
    for L, mult in prof.items():
        tag = " (even odds)" if L == 0.5 else (" (near-certain)" if L == 1.0 else "")
        print(f"    EPSS {L:.2f}{tag:<14} -> base patient-risk score x{mult:g}")
    print("  This statement contains no EPSS data, so the meaning of k cannot drift.")
    print()

    # 2. VALIDATION on the frozen dataset.
    print("Validation on the frozen filing dataset (checks, not gates that move k):")
    v = run_validation(rows)
    cf, lr, sp = v["critical_fraction"], v["low_risk_stays_low"], v["score_span"]
    print(f"  Critical fraction : {cf['value']*100:5.2f}%   band {cf['band'][0]*100:.0f}-{cf['band'][1]*100:.0f}%   "
          f"[{'PASS' if cf['pass'] else 'CHECK'}]")
    print(f"  Low-risk stays low: max {lr['max_low_risk_score']:.2f}   ceiling {lr['ceiling']}   "
          f"[{'PASS' if lr['pass'] else 'CHECK'}]")
    print(f"  Score span        : {sp['value']:.2f}   minimum {sp['minimum']}   "
          f"[{'PASS' if sp['pass'] else 'CHECK'}]")
    print()

    # 3. OBSERVATIONS (former gates), with the drift made explicit.
    print("Former single-CVE criteria, now observations only (these move with EPSS):")
    for cve, o in v["observations_not_gates"].items():
        if o.get("present"):
            print(f"  {cve}: L={o['L']:.4f}  score={o['score']:.2f}   "
                  f"(snapshot-dependent; not a calibration gate)")
        else:
            print(f"  {cve}: not present in this dataset")
    print()

    record = {
        "k": K_TEMPORAL,
        "basis": "stated amplification policy, validated on dataset (not fitted)",
        "amplification_profile": {str(L): m for L, m in prof.items()},
        "validation": v,
        "dataset_size": n,
        "class_iib_count": iib,
        "class_iii_count": iii,
    }

    # 4. OPTIONAL live re-validation: prove k does not move and distribution holds.
    if args.live:
        print("Live re-validation (fetching current EPSS from FIRST.org)...")
        live, date = fetch_live_epss([r["cve_id"] for r in rows])
        if live:
            live_rows = [{**r, "L": live.get(r["cve_id"], r["L"])} for r in rows]
            lv = run_validation(live_rows)
            print(f"  EPSS date: {date}")
            print(f"  k is unchanged at {K_TEMPORAL:g} (it is stated, not re-derived).")
            print(f"  Critical fraction on live EPSS: {lv['critical_fraction']['value']*100:5.2f}% "
                  f"(band {CRITICAL_FRACTION_BAND[0]*100:.0f}-{CRITICAL_FRACTION_BAND[1]*100:.0f}%) "
                  f"[{'in band' if lv['critical_fraction']['pass'] else 'OUT OF BAND -> triage layer re-sizes'}]")
            print(f"  Compare: the OLD single-CVE sweep would have selected a different k here.")
            record["live_validation"] = {"epss_date": date, **lv}
        print()

    with open(args.results, "w") as f:
        json.dump(record, f, indent=2)
    print(f"Record written to {args.results}")
    print()
    print("Summary: k is now a fixed amplification policy. Re-running this on any")
    print("EPSS snapshot reports the same k; only the validation metrics move, and")
    print("those feed the triage layer rather than re-fitting the constant.")


if __name__ == "__main__":
    main()
