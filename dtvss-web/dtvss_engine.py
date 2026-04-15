# DTVSS — Dynamic Temporal Vulnerability Scoring System
# Copyright © 2026 Andrew Broglio. All rights reserved.
# Patent Pending — IP Australia
# Licensed under BSL 1.1 — Commercial licence required for production use.

"""
DTVSS Scoring Engine
====================
DTVSS(t) = (B/10 × H/10 × (1 + 15 × L(t))) × 10
Output capped at 10.0. KEV override forces 10.0 post-scoring.
"""

K_TEMPORAL = 15.0

TGA_CLASSES = {
    "IIb": {"H": 7.5, "label": "Class IIb", "desc": "Moderate-high risk",
            "examples": "Infusion pumps, insulin pumps, ventilators, patient monitors, CGMs",
            "jurisdictions": {"TGA / Medsafe (AU·NZ)": "IIb", "EU MDR": "IIb", "MHRA (UK)": "IIb", "FDA (US)": "II"}},
    "III": {"H": 10.0, "label": "Class III", "desc": "Highest risk",
            "examples": "Pacemakers, implantable defibrillators, CRT devices",
            "jurisdictions": {"TGA / Medsafe (AU·NZ)": "III", "EU MDR": "III", "MHRA (UK)": "III", "FDA (US)": "III"}},
}

THRESHOLDS = [
    (3.0, "Low", "Standard patch cycle. Monitor L(t) for changes."),
    (6.0, "Medium", "Remediation within 30 days."),
    (8.0, "High", "Remediation within 7 days. Escalate to clinical risk team."),
    (10.1, "Critical", "Immediate action. Isolate device. Treat as incident response."),
]

# Device keyword → TGA class mapping for auto-classification
DEVICE_KEYWORDS = {
    # Infusion pumps — IIb
    "baxter": "IIb", "sigma spectrum": "IIb", "colleague": "IIb",
    "icu medical": "IIb", "plum 360": "IIb", "plum a+": "IIb",
    "hospira": "IIb", "lifecare": "IIb",
    "smiths medical": "IIb", "medfusion": "IIb", "cadd": "IIb",
    "bd alaris": "IIb", "alaris": "IIb", "carefusion": "IIb",
    "b. braun": "IIb", "b braun": "IIb", "infusomat": "IIb", "perfusor": "IIb",
    "fresenius": "IIb", "ivenix": "IIb", "agilia": "IIb",
    "moog": "IIb", "curlin": "IIb",
    "eitan": "IIb", "mindray": "IIb", "benefusion": "IIb",
    "treck": "IIb", "ripple20": "IIb",
    "infusion pump": "IIb",
    # Insulin pumps — IIb
    "medtronic minimed": "IIb", "minimed": "IIb", "paradigm": "IIb", "carelink": "IIb",
    "insulet": "IIb", "omnipod": "IIb",
    "tandem": "IIb", "t:slim": "IIb",
    "roche accu-chek": "IIb", "accu-chek": "IIb",
    "ypsomed": "IIb", "ypsopump": "IIb",
    "dana": "IIb", "diabecare": "IIb",
    "animas": "IIb",
    "insulin pump": "IIb",
    # Ventilators — IIb
    "philips respironics": "IIb", "respironics": "IIb",
    "hamilton medical": "IIb", "hamilton ventilator": "IIb",
    "drager": "IIb", "dräger": "IIb", "evita": "IIb",
    "puritan bennett": "IIb",
    "resmed": "IIb",
    "getinge": "IIb", "servo": "IIb",
    "ventilator": "IIb",
    # Patient monitors — IIb
    "philips intellivue": "IIb", "intellivue": "IIb",
    "ge healthcare monitor": "IIb", "carescape": "IIb",
    "nihon kohden": "IIb",
    "spacelabs": "IIb",
    "patient monitor": "IIb",
    # CGMs — IIb
    "freestyle libre": "IIb", "dexcom": "IIb", "guardian": "IIb",
    # Implantable cardiac — III
    "pacemaker": "III", "icd": "III", "defibrillator": "III",
    "medtronic pacemaker": "III", "medtronic icd": "III", "medtronic crt": "III",
    "abbott pacemaker": "III", "abbott defibrillator": "III",
    "boston scientific": "III",
    "biotronik": "III",
    "zoll": "III",
    "implantable": "III",
}


def classify_device(description: str, use_openfda: bool = True) -> tuple[str | None, str]:
    """
    Auto-classify device from CVE description or device name.
    Cascade: keyword match → openFDA API → None (user selects manually).
    Returns (tga_class, source) where source is 'keyword', 'openfda', or 'manual'.
    """
    desc_lower = description.lower()
    # Layer 1: keyword match (fast, no API call)
    for keyword in sorted(DEVICE_KEYWORDS.keys(), key=len, reverse=True):
        if keyword in desc_lower:
            return DEVICE_KEYWORDS[keyword], "keyword"

    # Layer 2: openFDA API (server-side, hidden from user)
    if use_openfda:
        try:
            from api_clients import openfda_classify_device
            fda_result = openfda_classify_device(description)
            if fda_result and fda_result.get("tga_class"):
                return fda_result["tga_class"], "openfda"
        except Exception:
            pass  # openFDA failure is non-fatal

    # Layer 3: unclassifiable — caller should prompt user
    return None, "manual"


def compute_dtvss(B: float, L: float, H: float, kev: bool = False) -> dict:
    """
    DTVSS(t) = (B/10 × H/10 × (1 + 15 × L(t))) × 10
    KEV override forces 10.0 Critical.
    """
    B = max(0.0, min(10.0, B))
    L = max(0.0, min(1.0, L))
    H = max(0.0, min(10.0, H))

    if kev:
        return {
            "B": round(B, 3), "L": round(L, 4), "H": round(H, 1),
            "raw": None, "score": 10.0, "risk_level": "Critical",
            "guidance": "KEV OVERRIDE: Confirmed active exploitation. Immediate action. Isolate device.",
            "kev_override": True,
            "static_baseline": round(B * H / 10, 2),
        }

    raw = (B / 10.0) * (H / 10.0) * (1.0 + K_TEMPORAL * L) * 10.0
    score = round(min(raw, 10.0), 2)
    static_baseline = round(B * H / 10, 2)

    risk_level = guidance = ""
    for threshold, level, msg in THRESHOLDS:
        if score < threshold:
            risk_level, guidance = level, msg
            break

    return {
        "B": round(B, 3), "L": round(L, 4), "H": round(H, 1),
        "raw": round(raw, 4), "score": score,
        "risk_level": risk_level, "guidance": guidance,
        "kev_override": False,
        "static_baseline": static_baseline,
    }
