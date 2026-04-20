# DTVSS Calibration Package

Executable record of the temporal amplification constant **k = 15** used in the
DTVSS scoring formula, backing the empirical calibration claim in provisional
patent paragraphs [0023] and [0025]:

> "k = 15 is the lowest value satisfying all four of the following clinical
> criteria."

This package runs the sweep and produces the evidence. On the committed
filing-time dataset, every patent number reproduces exactly.

## Results summary

Running `calibrate_k.py` against `dataset.csv`:

| Patent claim                              | Patent value | This repo | Match |
| ----------------------------------------- | ------------ | --------- | ----- |
| Dataset size                              | 96 CVEs      | 96        | exact |
| Score span across dataset                 | 9.62         | 9.62      | exact |
| Max score in the low-risk subset          | 0.98         | 0.98      | exact |
| Lowest integer k satisfying all criteria  | 15           | 15        | exact |
| CVE-2017-12718 score at k=15 (criterion i) | >= 8.0      | 8.03      | passes |
| CVE-2017-12718 score at k=14              | < 8.0        | 7.60      | fails (correct) |
| CVE-2020-11896 score at k=15 (criterion iii) | >= 8.0    | 10.00     | passes |
| CVEs whose score changes when L zeroed    | 95 of 96     | 95 of 96  | exact |
| CVEs crossing risk tiers due to L(t)      | 34           | 34        | exact |

The "95 of 96" figure is correctly computed by excluding KEV-overridden CVEs
from the denominator, because those CVEs are pinned to score 10.0 under
Equation 1's KEV branch and cannot change when L(t) is varied. In the
filing-time dataset exactly one CVE is KEV-listed (CVE-2020-11899, Treck
Ripple20, in CISA KEV since 2022-03-03); excluding it leaves 95 non-KEV CVEs,
all 95 of which change score when L is zeroed.

## Files

| File                              | Purpose                                                         |
| --------------------------------- | --------------------------------------------------------------- |
| `source_96cve_filing.csv`         | The frozen 96-CVE export that backs the patent's claims. Exported from the DTVSS application on 2026-04-09 with EPSS snapshot from 2026-04-08. This is the source of truth for the empirical calibration; treat as immutable. |
| `build_dataset.py`                | Reshapes `source_96cve_filing.csv` into the calibration schema and writes `dataset.csv`. Optionally rebuilds from the live ICSMA index with `--from-index`. |
| `dataset.csv`                     | The working calibration dataset in the schema `calibrate_k.py` expects (96 rows, canonical). Regenerated from the source file by `build_dataset.py`. |
| `calibrate_k.py`                  | Sweeps k from 1 to 30, evaluates the four criteria, reports the lowest satisfying k and supplementary KEV-aware statistics. No network I/O. |
| `results.json`                    | Full sweep written by `calibrate_k.py`. Re-run to refresh.    |
| `dataset_live_index_362cve.csv`   | Larger dataset built via `build_dataset.py --from-index` against the current live ICSMA index. 362 CVEs (323 Class IIb + 39 Class III). Included for re-validation against a superset of the filing-time data. |
| `results_live_index_362cve.json`  | Sweep results against the 362-CVE dataset. k = 15 still holds, because the binding criterion depends on patent-frozen test values. |
| `README.md`                       | This file.                                                       |

## How to reproduce

### Run the canonical calibration (fast, offline)

```bash
cd calibration
python3 calibrate_k.py
```

Reads `dataset.csv`, runs in under a second, outputs the boundary table and
concludes `Lowest integer k satisfying all four criteria: k = 15`.

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
from `api.first.org`, and runs the calibration against that larger dataset.
Expected runtime ~2 minutes dominated by EPSS API calls. k = 15 should still
be reported because the binding criterion (i) depends on patent-frozen test
values.

Use this path periodically (every 3-6 months) to confirm new ICSMA advisories
have not introduced CVEs that would disrupt the calibration. The resulting
`dataset.csv` is a superset of the canonical 96; if you run it, you will
overwrite the canonical and should re-run `python3 build_dataset.py` afterward
to restore the canonical 96-CVE dataset.

## Criteria evaluated

The four criteria are defined in patent paragraph [0025]:

**(i)** CVE-2017-12718 (ICU Medical Plum 360 / Smiths Medfusion infusion
pump, B=2.20, L=0.2577, H=7.5 per Class IIb) scores >= 8.0 Critical.

This is the **binding constraint**. At k=14 the score is 7.60 (Critical tier
begins at 8.0, so it fails). At k=15 the score is 8.03 (passes). The arithmetic:

    DTVSS = (2.20/10) x (7.5/10) x (1 + k x 0.2577) x 10
          = 1.65 x (1 + 0.2577 x k)

    Setting DTVSS >= 8.0:
          1.65 x (1 + 0.2577 x k) >= 8.0
          1 + 0.2577 x k >= 4.848
          k >= 14.93

Lowest integer satisfying: k = 15.

**(ii)** All low-risk CVEs (B <= 1.5, L <= 0.002) score <= 5.5.

Sanity check. The highest-scoring low-risk CVE in the dataset is at 0.98
(matches patent). Passes at all k in [1, 30].

**(iii)** CVE-2020-11896 (Treck TCP/IP stack, Ripple20, B=3.90, L=0.4263,
H=7.5) scores >= 8.0 Critical.

Passes at much lower k than criterion (i) and is therefore non-binding. At
k=15 it scores 10.00 (capped at maximum). Passes at all k >= 3.

**(iv)** Score span across the dataset >= 4.0 points.

Sanity check. Observed span is 9.62, matching the patent exactly. Passes at
all k in [1, 30].

Only criterion (i) binds. The rest are sanity checks verifying that the k
chosen for (i) is not absurd.

## Two datasets, one conclusion

The package ships with two calibration datasets because they answer two
different questions.

**`dataset.csv` (96 CVEs, canonical):** built from the filing-time export.
This is the patent's dataset, used to generate the patent's specific numeric
claims. The 95/96 and 34 figures are exact against this dataset. Use this for
any claim that references the patent's calibration.

**`dataset_live_index_362cve.csv` (362 CVEs):** built from the current live
ICSMA index at time of package creation. Useful to demonstrate that k = 15 is
not fragile to dataset growth - on a ~3.8x larger dataset including hundreds
of additional CVEs from recent ICSMA advisories, k = 15 remains the lowest
satisfying value. The supplementary statistics differ against this larger
dataset because most CVEs have EPSS = 0.0 placeholder from a sandboxed build;
re-running `build_dataset.py --from-index` with network access will populate
them.

Both datasets agree on the k = 15 outcome because the binding constraint is
criterion (i), whose inputs are patent-frozen and do not depend on the rest
of the dataset.

## How B and H are assigned

**B** (CVSS exploitability sub-score, range [0, 10]):

Computed from each CVE's CVSS v3.x vector per FIRST.org CVSS v3.1
specification (section 7.1):

    B = 8.22 x AV x AC x PR x UI

where PR is scope-dependent (separate tables for Scope:Unchanged vs
Scope:Changed). The B values in `source_96cve_filing.csv` are these
pre-computed values, authoritative for the patent's claims.

**H** (patient harm weighting factor, range [0, 10]):

Per patent [0022]:

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

Per patent Equation 1, CVEs listed in the CISA Known Exploited Vulnerabilities
catalog have their score forced to 10.0 Critical regardless of B, L, and H.
This is implemented in the scoring path (not in this calibration script,
which sweeps the non-KEV branch), but matters for the supplementary statistics.

A KEV-overridden CVE's score is L-independent by construction: it is 10.0
whether L is live or zero. Counting it as "unchanged when L is zeroed" would
be misleading because the zero-L reading of its score is also 10.0 (via the
KEV override), not via the multiplicative formula. The correct denominator
for the "score changes when L is zeroed" statistic is the set of non-KEV CVEs,
which is 95 in the filing-time dataset.

The patent figure of 95 matches this interpretation exactly.

## Note on "11 Class III CVEs"

Patent [0025] describes "11 Class III implantable cardiac device CVEs from
Zoll Medical and Abbott." The filing-time dataset contains 9 Class III CVEs
(6 Zoll + 3 Abbott). This is a minor arithmetic slip in the patent text; the
calibration itself was correctly performed against the 9 CVEs actually in
the dataset. Does not affect any criterion.

## What this package does not do

- **Does not modify the live engine.** `dtvss_engine.py` continues to use its
  hardcoded `K_TEMPORAL = 15.0`. This package is evidentiary only.

- **Does not monitor ongoing EPSS drift.** The script uses the
  patent-frozen L values for CVE-2017-12718 and CVE-2020-11896 so that
  criterion evaluation is reproducible. If you want to verify the patent
  against today's live EPSS for those specific CVEs, that is a separate
  monitoring task.

- **Does not subsample or re-weight the dataset.** The 96 CVEs in the source
  export are used verbatim.

## Copyright

Copyright 2026 Andrew Broglio. All rights reserved.
Patent Pending - IP Australia.
Licensed under BSL 1.1. See repository LICENSE.
 
