"""
Build the frozen calibration dataset for DTVSS.

PRIMARY PATH (default): load from the filing-time 96-CVE export
  The DTVSS provisional patent was filed against a frozen 96-CVE calibration
  dataset, exported from the DTVSS application on 2026-04-09 and checked into
  the repo as `source_96cve_filing.csv`. That file IS the source of truth for
  the patent's empirical claims. This script copies its rows into the
  calibration schema and writes `dataset.csv`.

ALTERNATIVE: rebuild from the current live ICSMA index (--from-index)
  Produces a larger dataset drawn from the current state of CISA ICSMA.
  Useful for re-validating that k = 15 still holds against more recent
  advisories. The result is NOT the patent's 96-CVE set and numerical
  statistics will differ.

Usage:
    python3 build_dataset.py                  # rebuild from 96-CVE filing export
    python3 build_dataset.py --from-index     # rebuild from current live index

Copyright 2026 Andrew Broglio. All rights reserved.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path


HERE = Path(__file__).parent
SOURCE_96_CVE_PATH = HERE / "source_96cve_filing.csv"
OUTPUT_PATH = HERE / "dataset.csv"

DATASET_FIELDS = [
    "cve_id", "vendor", "vendor_display", "description",
    "cvss_vector", "B", "H", "class", "published", "epss",
    "kev_override", "source",
]


# ---------------------------------------------------------------------------
# PRIMARY: load from the filing-time 96-CVE export
# ---------------------------------------------------------------------------
def build_from_filing_export() -> list[dict]:
    """Reshape source_96cve_filing.csv into the calibration schema."""
    if not SOURCE_96_CVE_PATH.exists():
        print(f"ERROR: {SOURCE_96_CVE_PATH} not found.")
        print("The filing-time 96-CVE export must be committed to the repo")
        print("at calibration/source_96cve_filing.csv.")
        raise SystemExit(1)

    rows_in = list(csv.DictReader(open(SOURCE_96_CVE_PATH)))
    rows_out = []
    for r in rows_in:
        kev = (r.get("kev_override") or "").strip().lower() == "true"
        rows_out.append({
            "cve_id": r["cve_id"],
            "vendor": r["mdm_name"].lower(),
            "vendor_display": r["mdm_name"],
            "description": (r.get("description") or "")[:200],
            "cvss_vector": "",  # not preserved in the export; B is authoritative
            "B": r["B"],
            "H": r["H"],
            "class": r["tga_class"],
            "published": (r.get("published") or "")[:10],
            "epss": r["L"],
            "kev_override": "true" if kev else "false",
            "source": f"filing-time calibration dataset (epss_date={r.get('epss_date', '')})",
        })

    print(f"Loaded {len(rows_out)} CVEs from filing-time export "
          f"({SOURCE_96_CVE_PATH.name}).")
    kev_count = sum(1 for r in rows_out if r["kev_override"] == "true")
    print(f"  KEV-overridden CVEs: {kev_count}")
    return rows_out


# ---------------------------------------------------------------------------
# ALTERNATIVE: rebuild from live ICSMA index + live EPSS
# ---------------------------------------------------------------------------

# CVSS v3.x exploitability sub-score weights per FIRST.org v3.1 spec
AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC_WEIGHTS = {"L": 0.77, "H": 0.44}
UI_WEIGHTS = {"N": 0.85, "R": 0.62}
PR_WEIGHTS_SCOPE_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_WEIGHTS_SCOPE_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}


def parse_cvss_vector(vec: str) -> dict[str, str] | None:
    if not vec:
        return None
    body = vec
    for prefix in ("CVSS:3.0/", "CVSS:3.1/", "CVSS:4.0/"):
        if body.startswith(prefix):
            body = body[len(prefix):]
            break
    try:
        metrics = {}
        for token in body.split("/"):
            if ":" in token:
                k, v = token.split(":", 1)
                metrics[k] = v
        for required in ("AV", "AC", "PR", "UI", "S"):
            if required not in metrics:
                return None
        return metrics
    except Exception:
        return None


def compute_exploitability_subscore(vec: str) -> float | None:
    """Return B = 8.22 x AV x AC x PR x UI per FIRST.org CVSS v3.1 spec."""
    m = parse_cvss_vector(vec)
    if m is None:
        return None
    try:
        av = AV_WEIGHTS[m["AV"]]
        ac = AC_WEIGHTS[m["AC"]]
        ui = UI_WEIGHTS[m["UI"]]
        pr_table = PR_WEIGHTS_SCOPE_UNCHANGED if m["S"] == "U" else PR_WEIGHTS_SCOPE_CHANGED
        pr = pr_table[m["PR"]]
        return round(8.22 * av * ac * pr * ui, 3)
    except KeyError:
        return None


CLASS_III_CARDIAC_VENDORS = {
    "zoll", "zoll medical", "abbott", "st. jude medical",
    "boston scientific", "biotronik",
}

MEDTRONIC_CLASS_III_KEYWORDS = (
    "pacemaker", "icd", "crt", "implantable cardioverter",
    "defibrillator", "carelink", "conexus",
)

OUT_OF_SCOPE_VENDORS = {
    "alivecor", "ossur", "illumina", "oxford nanopore technologies",
    "mirion medical", "santesoft", "microdicom", "pixmeo", "medixant",
    "softneta", "infinitt healthcare", "lifepoint informatics",
    "change healthcare", "carestream", "varex imaging", "beaconmedaes",
    "swisslog healthcare", "panoramic corporation", "vertikal systems",
    "capsule technologies", "qualcomm life", "johnson & johnson",
    "innokas", "stryker", "bpl medical technologies", "fujifilm",
    "qardio", "dario health", "i-sens inc", "vyaire medical",
    "bmc medical", "natus medical", "contec health",
}


def assign_h_live(vendor_key: str, cve_id: str, description: str) -> tuple[float, str]:
    v = vendor_key.lower()
    desc = (description or "").lower()
    if v in OUT_OF_SCOPE_VENDORS:
        return (0.0, "EXCLUDE")
    if v in CLASS_III_CARDIAC_VENDORS:
        return (10.0, "III")
    if v == "medtronic":
        if any(kw in desc for kw in MEDTRONIC_CLASS_III_KEYWORDS):
            return (10.0, "III")
        return (7.5, "IIb")
    return (7.5, "IIb")


# Patent-frozen test cases - override whatever is in live data
PATENT_TEST_CASES = {
    "CVE-2017-12718": {
        "B": 2.20, "L": 0.2577, "H": 7.5, "class": "IIb",
        "vendor": "icu medical",
        "description": "Buffer overflow (Smiths Medical Medfusion 4000 / ICU Medical Plum 360)",
        "note": "Patent criterion (i) binding constraint",
    },
    "CVE-2020-11896": {
        "B": 3.90, "L": 0.4263, "H": 7.5, "class": "IIb",
        "vendor": "treck",
        "description": "Treck TCP/IP stack heap overflow (Ripple20, ICSMA-20-168-01)",
        "note": "Patent criterion (iii) binding constraint",
    },
}


EPSS_API_URL = "https://api.first.org/data/v1/epss"


def fetch_epss_batch(cve_ids: list[str]) -> dict[str, float]:
    if not cve_ids:
        return {}
    params = urllib.parse.urlencode({"cve": ",".join(cve_ids)})
    url = f"{EPSS_API_URL}?{params}"
    req = urllib.request.Request(url, headers={"User-Agent": "DTVSS-calibration/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        out = {}
        for row in data.get("data", []):
            cve = row.get("cve")
            epss = row.get("epss")
            if cve and epss is not None:
                out[cve] = float(epss)
        return out
    except Exception as e:
        print(f"  WARN: EPSS batch fetch failed: {e}", file=sys.stderr)
        return {}


def fetch_all_epss(cve_ids: list[str]) -> dict[str, float]:
    result = {}
    unique = list(dict.fromkeys(cve_ids))
    batch_size = 100
    total_batches = (len(unique) + batch_size - 1) // batch_size
    for i in range(0, len(unique), batch_size):
        batch = unique[i:i + batch_size]
        batch_num = i // batch_size + 1
        print(f"  EPSS batch {batch_num}/{total_batches} ({len(batch)} CVEs)...")
        result.update(fetch_epss_batch(batch))
        time.sleep(1.0)
    return result


def build_from_live_index() -> list[dict]:
    """Rebuild from the current mdm_index.json + live EPSS fetch."""
    index_path_env = os.environ.get("DTVSS_INDEX_PATH")
    if index_path_env:
        index_path = Path(index_path_env)
    else:
        index_path = HERE.parent / "static" / "data" / "mdm_index.json"

    print(f"Loading index from {index_path}...")
    with open(index_path) as f:
        index = json.load(f)

    rows = []
    excluded = 0
    excluded_by_vendor: dict[str, int] = {}
    no_vector = 0

    for vkey, mfr in index.get("manufacturers", {}).items():
        for cve in mfr.get("cves", []):
            cve_id = cve.get("cve_id", "")
            vector = cve.get("cvss_vector", "")
            description = cve.get("description", "")

            if cve_id in PATENT_TEST_CASES:
                continue

            B = compute_exploitability_subscore(vector)
            if B is None:
                no_vector += 1
                continue

            H, class_label = assign_h_live(vkey, cve_id, description)
            if class_label == "EXCLUDE":
                excluded += 1
                excluded_by_vendor[vkey] = excluded_by_vendor.get(vkey, 0) + 1
                continue

            rows.append({
                "cve_id": cve_id,
                "vendor": vkey,
                "vendor_display": mfr.get("display_name", vkey),
                "description": description[:200],
                "cvss_vector": vector,
                "B": B,
                "H": H,
                "class": class_label,
                "published": cve.get("published", ""),
                "epss": None,
                "kev_override": "false",  # Live rebuild path does not currently check KEV;
                                          # re-validation is primarily against patent-frozen
                                          # test cases which handle their own KEV status.
                "source": "ICSMA index (live rebuild)",
            })

    print(f"  Parsed {len(rows)} in-scope CVEs.")
    print(f"  Excluded {excluded} out-of-scope CVEs.")
    print(f"  Skipped {no_vector} CVEs with unparseable CVSS vectors.")

    cve_ids = [r["cve_id"] for r in rows]
    print(f"Fetching EPSS for {len(cve_ids)} CVEs...")
    epss_map = fetch_all_epss(cve_ids)
    for r in rows:
        r["epss"] = epss_map.get(r["cve_id"], 0.0)

    # Append patent-frozen test cases
    for cve_id, tc in PATENT_TEST_CASES.items():
        rows.append({
            "cve_id": cve_id,
            "vendor": tc["vendor"],
            "vendor_display": tc["vendor"],
            "description": tc["description"],
            "cvss_vector": "",
            "B": tc["B"],
            "H": tc["H"],
            "class": tc["class"],
            "published": "",
            "epss": tc["L"],
            "kev_override": "false",  # Neither patent-frozen test case is KEV-listed
            "source": f"patent [0025] frozen value - {tc['note']}",
        })

    return rows


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Build DTVSS calibration dataset.csv")
    parser.add_argument(
        "--from-index", action="store_true",
        help="Rebuild from current live ICSMA index instead of the 96-CVE filing export.",
    )
    args = parser.parse_args()

    if args.from_index:
        rows = build_from_live_index()
    else:
        rows = build_from_filing_export()

    iib = sum(1 for r in rows if r["class"] == "IIb")
    iii = sum(1 for r in rows if r["class"] == "III")
    print()
    print(f"Final dataset composition:")
    print(f"  Class IIb (H=7.5):  {iib}")
    print(f"  Class III (H=10.0): {iii}")
    print(f"  Total:              {len(rows)}")

    with open(OUTPUT_PATH, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=DATASET_FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print()
    print(f"Wrote {OUTPUT_PATH} ({len(rows)} rows).")


if __name__ == "__main__":
    main()
