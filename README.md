# DTVSS Calibration Package

[![Calibration](https://github.com/d3matr1x/dtvss-web/actions/workflows/calibration.yml/badge.svg)](https://github.com/d3matr1x/dtvss-web/actions/workflows/calibration.yml)

Reproducible record of the temporal amplification constant **k = 15** used in the
DTVSS scoring formula. k = 15 is a **stated amplification policy**: at even-odds
exploitation likelihood (EPSS = 0.5) a vulnerability's base patient-risk score is
amplified 8.5-fold, and at near-certain exploitation 16-fold. It is set as an
explicit risk-appetite policy, not fitted to the data. This package states k and
uses the frozen 96-CVE filing dataset to validate that the policy produces a
sensible distribution. Every figure in the validation record below reproduces
exactly against the committed dataset.

> **Note on framing.** k was originally described (provisional patent specification,
> [0023] and [0025]) as "the lowest integer satisfying four clinical criteria." Those
> criteria anchor to where individual CVEs cross the Critical threshold, which
> ties the constant to specific EPSS readings — and EPSS is re-estimated
> continuously. DTVSS therefore states k as an explicit amplification policy and
> uses the dataset to validate it, rather than solving for a value that depends
> on any single CVE's current EPSS.

## What the calibration checks

k = 15 is the policy. Its profile, the multiplier `1 + k·L` applies to the base
patient-risk score:

- EPSS 0.25 → ×4.75
- EPSS 0.50 (even odds) → ×8.5
- EPSS 1.00 (near-certain) → ×16

Running `calibrate_k.py` against `dataset.csv` (96 CVEs, 87 Class IIb + 9 Class III)
validates three properties of the resulting distribution:

| Check                              | Criterion   | Value           | Result |
| ---------------------------------- | ----------- | --------------- | ------ |
| Share of CVEs reaching Critical    | 3–8% band   | 5.21% (5 of 96) | passes |
| Highest score in the low-risk subset | ≤ 5.5     | 0.98            | passes |
| Score span across the dataset      | ≥ 4.0       | 9.44            | passes |

These confirm that the stated k produces a sensible distribution — a small,
stable share reaching Critical, low-exploitability findings staying low, and the
scale spreading across its range. They **validate** k = 15; they do not derive it.

Two CVEs that the earlier formulation used as anchors are still recorded, now as
**observations rather than gates**, because their scores move with EPSS:

| Observation (one EPSS snapshot)                | Inputs                     | Score |
| ---------------------------------------------- | -------------------------- | ----- |
| CVE-2017-12718 (ICU Medical Plum 360, Class IIb) | B=2.20, L=0.2577, H=7.5   | 8.03  |
| CVE-2020-11896 (Treck Ripple20, Class IIb)     | B=3.90, L=0.4263, H=7.5    | 9.74  |

Both are time-relative: L is one day's EPSS reading and the score moves with it.

## The amplifier and the soft cap

The DTVSS score multiplies a vulnerability's base patient-risk score
(`B/10 × H/10 × 10`) by the temporal factor `(1 + k·L(t))`, where L(t) is the daily
EPSS probability of exploitation. With k = 15 the multiplier runs from ×1 at
L = 0 to ×16 at L = 1.0.

Because the multiplier can drive the product past 10, scores are shaped at the top
of the range rather than hard-clipped: scores below 8.0 are exact, and above 8.0
the overshoot is compressed asymptotically toward 10 without ever reaching it
(knee at 8.0). This preserves the difference between a serious and an extreme
finding, and keeps Critical membership identical to a hard clip (raw ≥ 8 ⟺
score ≥ 8). An exact 10.0 is reserved for one case: a CVE in the CISA KEV catalog,
which is forced to 10.0 regardless of k.

The same soft cap is used in `dtvss_engine.py`, `calculator.html`, and
`calibrate_k.py`, so the validation reflects production scoring. The score span is
**9.44** under the soft cap, slightly below the 9.62 a hard clip produces, because
the top no longer pins to a flat 10.

## Files

| File                              | Purpose                                                         |
| --------------------------------- | --------------------------------------------------------------- |
| `source_96cve_filing.csv`         | The frozen 96-CVE export that backs the published figures. Exported from the DTVSS application on 2026-04-09 with EPSS snapshot from 2026-04-08. Source of truth; treat as immutable. |
| `build_dataset.py`                | Reshapes `source_96cve_filing.csv` into the calibration schema and writes `dataset.csv`. Optionally rebuilds from the live ICSMA index with `--from-index`. |
| `dataset.csv`                     | The working calibration dataset in the schema `calibrate_k.py` expects (96 rows, canonical). Regenerated from the source file by `build_dataset.py`. |
| `calibrate_k.py`                  | States k = 15 as an amplification policy and validates it against `dataset.csv` (distribution checks). Standard library only; `--live` fetches current EPSS to confirm the policy still validates. |
| `results.json`                    | Calibration record written by `calibrate_k.py`: the stated k, the amplification profile, and the validation figures. Re-run to refresh. |
| `dataset_live_index_362cve.csv`   | Larger dataset built via `build_dataset.py --from-index` (362 CVEs: 323 Class IIb + 39 Class III). A bigger sample for re-validating the distribution. The committed copy carries an EPSS = 0.0 placeholder from a sandboxed build; `--from-index` with network access populates it. |
| `results_live_index_362cve.json`  | Calibration output against the 362-CVE dataset. Supplementary; regenerate via `--from-index`. |
| `README.md`                       | This file.                                                       |

### Schema note: `L` vs `epss_pct` in `source_96cve_filing.csv`

The source CSV contains two related EPSS columns for the same CVE on the
same snapshot date:

- **`L`** — the EPSS *score* in `[0.0, 1.0]`. This is the probability used as
  the L(t) variable in the DTVSS scoring formula (specification [0021]). The
  calibration code reads this column.
- **`epss_pct`** — the EPSS *percentile* in `[0.0, 1.0]`. This is where the
  CVE ranks among all CVEs by predicted exploitation probability on the
  snapshot date. **It is not used in scoring** and is included only for
  human inspection.

A reader diffing the two columns by name will see different numbers for
the same CVE on the same date and conclude there is a contradiction.
There is not — they are different quantities. Anyone using
`source_96cve_filing.csv` for analysis should treat `L` as authoritative
for any DTVSS scoring claim and `epss_pct` as an informational ranking
column only. The schema produced by `build_dataset.py` (`dataset.csv`)
emits only the score, under the column name `epss`, to remove this
ambiguity from the calibration path.

## How to reproduce

### Run the canonical validation (fast, offline)

```bash
cd calibration
python3 calibrate_k.py
```

Reads `dataset.csv`, runs in under a second, and prints the stated k and the
validation result (`k = 15` as a stated amplification policy, with the three
distribution checks passing).

### Rebuild `dataset.csv` from the frozen source (offline, idempotent)

```bash
cd calibration
python3 build_dataset.py
```

Reshapes `source_96cve_filing.csv` into the calibration schema. No network,
no API calls.

### Re-validate against the current live ICSMA index (requires network)

```bash
cd calibration
python3 build_dataset.py --from-index
python3 calibrate_k.py
```

Rebuilds `dataset.csv` from `../static/data/mdm_index.json`, fetches live EPSS
from `api.first.org`, and runs the validation against that larger dataset.
Expected runtime ~2 minutes dominated by EPSS API calls. k is **stated**, so it
does not re-derive; what this checks is whether the distribution stays sensible
(the Critical share in band) as live EPSS evolves. Out-of-band is a signal for an
operational triage layer to resize its Critical bucket, not a reason to change k.

Running `--from-index` overwrites the canonical `dataset.csv`; re-run
`python3 build_dataset.py` afterward to restore the canonical 96-CVE dataset.

## How the policy is validated

`calibrate_k.py` applies the stated policy (k = 15, soft cap) to every CVE in
`dataset.csv` and checks three properties of the resulting distribution.

**(1) A small, stable share reaches Critical.** Target band 3–8%. Observed 5.21%
(5 of 96). This keeps the Critical tier meaningful — neither empty nor flooded.

**(2) Low-exploitability findings stay low.** Every CVE with B ≤ 1.5 and
L ≤ 0.002 scores ≤ 5.5. Highest observed: 0.98.

**(3) The scale discriminates.** Score span across the dataset ≥ 4.0. Observed
9.44.

These are checks on the stated policy, not a derivation of it. The value of k is
a risk-appetite choice; the dataset confirms that choice is not absurd.

### Why k is stated, not solved for

An amplification constant should not move when one CVE's exploitation probability
is revised, and EPSS values are revised constantly. Anchoring the constant to
where a single named CVE crosses the Critical threshold makes it sensitive to that
CVE's daily EPSS score. Stating k as a policy removes that sensitivity: the
meaning of k is fixed, and the dataset validates it rather than determining it.

## How B and H are assigned

**B** (CVSS exploitability sub-score, range [0, 10]):

Computed from each CVE's CVSS v3.x vector per FIRST.org CVSS v3.1
specification (section 7.1):

    B = 8.22 x AV x AC x PR x UI

where PR is scope-dependent (separate tables for Scope:Unchanged vs
Scope:Changed). The B values in `source_96cve_filing.csv` are these
pre-computed values, authoritative for the calibration figures.

**H** (patient harm weighting factor, range [0, 10]):

Per the specification [0022]:

- Class I devices: H = 2.0
- Class IIa devices: H = 5.0
- Class IIb devices (pumps, ventilators, monitors, CGMs): **H = 7.5**
- Class III devices (implantable cardiac): **H = 10.0**

Only IIb and III appear in the calibration dataset. The filing-time export
has H assigned per CVE; the `--from-index` rebuild path assigns H by vendor
and description keyword (Abbott / Zoll / Boston Scientific / Biotronik /
St. Jude -> III; Medtronic cardiac keywords -> III, else IIb; other in-scope
vendors -> IIb).

## KEV handling

Per the scoring formula, CVEs listed in the CISA Known Exploited Vulnerabilities
catalog have their score forced to 10.0 regardless of B, L, and H. This is
implemented in the scoring path, not in this calibration script, which evaluates
the non-KEV multiplicative branch. A KEV-overridden score is L-independent by
construction: it is 10.0 whether L is live or zero.

The filing dataset contains exactly one KEV-listed CVE (CVE-2020-11899, Treck
Ripple20, in CISA KEV since 2022-03-03). It is the single exact 10.0 in the set;
the soft cap holds every other score below 10.

## Note on "11 Class III CVEs"

The specification [0025] describes "11 Class III implantable cardiac device CVEs from
Zoll Medical and Abbott." The filing-time dataset contains 9 Class III CVEs
(6 Zoll + 3 Abbott). This is a minor arithmetic slip in the specification text; the
calibration itself was correctly performed against the 9 CVEs actually in
the dataset. Does not affect any check.

## What this package does not do

- **Does not re-fit k.** k = 15 is a stated policy; `calibrate_k.py` validates
  it, it does not search for it.

- **Mirrors, but does not change, production scoring.** `calibrate_k.py` uses the
  same formula and soft cap as `dtvss_engine.py` so the validation reflects what
  the live engine produces. Engine behaviour is set there, not here.

- **Does not subsample or re-weight the dataset.** The 96 CVEs in the source
  export are used verbatim.

## Copyright

Copyright 2026 Andrew Broglio. All rights reserved.
Patent Pending - IP Australia.
Licensed under BSL 1.1. See repository LICENSE.
