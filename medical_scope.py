"""
DTVSS Medical Device Scope Filter
==================================
Keeps non-medical CVEs out of search results and scoring.

The previous filter used substring matching on "infusion pump" etc., which
matched PHP-Fusion, Wonderware InFusion SCADA, WordPress Infusionsoft, and
other products with "infusion" in their name. This module replaces that with
word-boundary regex matching and an explicit non-medical blocklist.

DEFENSE LAYERS (applied in order):
  1. BLOCKLIST — reject CVEs mentioning known non-medical products
  2. ICS-MEDICAL ALLOW — CVEs with ICSMA advisory URLs always pass
  3. MEDICAL TERMS ALLOW — word-boundary match on medical vocabulary
  4. CLASSIFICATION GUARD — refuse to default to IIb; reject unclassifiable

Copyright 2026 Andrew Broglio. All rights reserved.
"""

import re

# -----------------------------------------------------------------------------
# Layer 1: BLOCKLIST — definitely not medical
# -----------------------------------------------------------------------------
# Products and vendors whose CVEs have historically contaminated search
# results. Each term here will cause the CVE to be rejected regardless of
# whether it also matches any medical term.
#
# Word-boundary matched so "infusion" (medical) still passes while
# "php-fusion" (CMS) is caught.

NON_MEDICAL_BLOCKLIST = [
    # Content management systems
    r"\bphp[- ]?fusion\b",
    r"\bwordpress\b",
    r"\bjoomla\b",
    r"\bdrupal\b",
    r"\bmagento\b",
    r"\btypo3\b",
    r"\bmybb\b",
    r"\bvbulletin\b",
    r"\bphpbb\b",
    r"\bghost\b",            # Ghost blogging platform
    r"\bmyfusion\b",
    r"\bzpanel\b",
    r"\bcpanel\b",
    r"\bplesk\b",
    r"\bdirectadmin\b",

    # SaaS / business software with "fusion" or "infusion" in the name
    r"\binfusionsoft\b",     # Keap/Infusionsoft marketing automation
    r"\bgravity\s*forms\b",  # WordPress plugin

    # Industrial control systems that aren't medical
    # (Wonderware / Invensys / Foxboro are ICS/SCADA, not ICSMA)
    r"\bwonderware\b",
    r"\binvensys\b",
    r"\bfoxboro\b",
    r"\barchestra\b",
    r"\binfusion\s+(ce|fe|scada)\b",  # "InFusion CE/FE/SCADA"
    r"\bintouch\b",           # Wonderware InTouch
    r"\bschneider\s+electric\b",
    r"\brockwell\s+automation\b",
    r"\bsiemens\s+simatic\b",  # Siemens SCADA (not Siemens Healthineers)
    r"\bge\s+proficy\b",

    # Other confusables seen in the wild
    r"\bconfusion\b",         # Sometimes appears in descriptions
    r"\bfusion\s+middleware\b",  # Oracle Fusion Middleware
    r"\boracle\s+fusion\b",
]

# Pre-compile for performance. re.IGNORECASE so case doesn't matter.
_BLOCKLIST_PATTERNS = [re.compile(p, re.IGNORECASE) for p in NON_MEDICAL_BLOCKLIST]


# -----------------------------------------------------------------------------
# Layer 3: MEDICAL TERMS ALLOW — word-boundary matching
# -----------------------------------------------------------------------------
# Unlike the previous substring-based filter, these use word boundaries so
# "infusion pump" in a description passes, but "infusion" inside "php-fusion"
# or "Infusionsoft" does not.
#
# Grouped by category for maintainability.

MEDICAL_TERMS = [
    # Infusion / drug delivery
    r"\binfusion\s+pump\b",
    r"\bsyringe\s+pump\b",
    r"\binsulin\s+pump\b",
    r"\bdrug\s+delivery\b",
    r"\bmedfusion\b",          # Smiths Medical Medfusion
    r"\bmedtronic\s+minimed\b",
    r"\bhospira\b",
    r"\bbaxter\s+sigma\b",
    r"\bb\.?\s*braun\b",
    r"\bicu\s+medical\b",
    r"\balaris\b",             # BD Alaris
    r"\bcarefusion\b",
    r"\bsmiths\s+medical\b",
    r"\bomnipod\b",            # Insulet
    r"\bt:slim\b",             # Tandem
    r"\bcurlin\b",
    r"\blifecare\s+pca\b",     # Hospira LifeCare PCA

    # Cardiac implantables
    r"\bpacemaker\b",
    r"\bimplantable\s+cardioverter\b",
    r"\bdefibrillator\b",
    r"\bcrt[- ]?d?\b",         # Cardiac resynchronization therapy
    r"\bcarelink\b",
    r"\bconexus\b",
    r"\bboston\s+scientific\b",
    r"\bbiotronik\b",
    r"\babbott\s+pacemaker\b",
    r"\bst\.?\s*jude\s+medical\b",
    r"\bzoll\b",

    # Ventilators / respiratory
    r"\bventilator\b",
    r"\bcpap\b",
    r"\bbipap\b",
    r"\brespironics\b",
    r"\bhamilton\s+medical\b",
    r"\bdr[aä]ger\b",
    r"\bevita\b",
    r"\bpuritan\s+bennett\b",
    r"\bservo\s+ventilator\b",

    # Patient monitoring / CGM
    r"\bpatient\s+monitor\b",
    r"\bintellivue\b",
    r"\bcarescape\b",
    r"\bnihon\s+kohden\b",
    r"\bspacelabs\b",
    r"\bpulse\s+oximeter\b",
    r"\bcontinuous\s+glucose\b",
    r"\bglucose\s+monitor\b",
    r"\bdexcom\b",
    r"\bfreestyle\s+libre\b",
    r"\bguardian\s+connect\b",

    # Imaging / PACS (medical imaging, not generic "imaging")
    r"\bmedical\s+imaging\b",
    r"\bpacs\s+(?:server|system|workstation)\b",
    r"\bdicom\b",
    r"\bct\s+scanner\b",
    r"\bmri\s+(?:scanner|system)\b",
    r"\bultrasound\s+(?:system|machine)\b",
    r"\bx[- ]?ray\s+(?:system|machine)\b",

    # Other medical device categories
    r"\bmedical\s+device\b",
    r"\bmedical\s+advisory\b",
    r"\bicsma\b",
    r"\bics[- ]?cert\s+medical\b",
    r"\bhealthcare\s+(?:device|system|equipment)\b",
    r"\bclinical\s+(?:device|system|network)\b",
    r"\bhl7\b",
    r"\bfhir\b",
    r"\bdialysis\b",
    r"\banesthesia\b",
    r"\bendoscop(?:e|ic|y)\b",
    r"\belectrocardiograph\b",
    r"\bblood\s+gas\s+analy[sz]er\b",
    r"\binfusomat\b",          # B. Braun
    r"\bperfusor\b",           # B. Braun
    r"\bbenefusion\b",         # Mindray
    r"\bypsopump\b",           # Ypsomed
    r"\btelemetry\s+(?:unit|system).*hospital\b",
]

_MEDICAL_PATTERNS = [re.compile(p, re.IGNORECASE) for p in MEDICAL_TERMS]


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------

def is_blocklisted(description: str) -> tuple[bool, str]:
    """
    Return (True, matched_pattern) if description matches the non-medical
    blocklist. Used as a hard reject — these CVEs never get scored as medical.
    """
    if not description:
        return (False, "")
    for pat in _BLOCKLIST_PATTERNS:
        m = pat.search(description)
        if m:
            return (True, m.group(0))
    return (False, "")


def has_medical_term(description: str) -> tuple[bool, str]:
    """
    Return (True, matched_term) if description contains a medical-device term
    with proper word boundaries.
    """
    if not description:
        return (False, "")
    for pat in _MEDICAL_PATTERNS:
        m = pat.search(description)
        if m:
            return (True, m.group(0))
    return (False, "")


def is_in_scope(
    description: str,
    ics_advisory: bool = False,
    ics_urls: list | None = None,
) -> tuple[bool, str]:
    """
    Decide whether a CVE is within DTVSS's medical-device scope.
    
    Returns (in_scope, reason). Reason is a short human-readable string
    explaining why the decision was made, for logging / UI display.

    Decision tree:
      1. If blocklisted (PHP-Fusion, Wonderware, WordPress etc.) -> OUT
      2. If ICSMA advisory present in NVD references              -> IN
      3. If description has a medical-device term                 -> IN
      4. Otherwise                                                -> OUT
    
    This is conservative by default — "uncertain" is treated as out of scope.
    Better to miss a niche medical CVE than to score a CMS bug as Critical.
    """
    # Layer 1 — hard reject
    blocked, match = is_blocklisted(description or "")
    if blocked:
        return (False, f"non-medical product detected: {match}")
    
    # Layer 2 — ICSMA advisory is authoritative "in scope" signal
    if ics_advisory:
        return (True, "ICSMA advisory referenced")
    
    if ics_urls:
        for url in ics_urls:
            u = url.lower()
            if "/icsma-" in u or "ics-medical-advisories" in u:
                return (True, "ICSMA advisory in references")
    
    # Layer 3 — medical terminology
    medical, term = has_medical_term(description or "")
    if medical:
        return (True, f"medical term matched: {term}")
    
    # Layer 4 — default deny
    return (False, "no medical-device indicators found")


def filter_scored_results(
    results: list[dict],
    include_explanation: bool = False,
) -> tuple[list[dict], dict]:
    """
    Filter a list of scored CVE results down to in-scope medical ones.
    
    Returns (kept, stats) where stats counts what was filtered and why.
    Useful for logging / debugging the filter's behaviour.
    """
    kept = []
    stats = {
        "total": len(results),
        "kept": 0,
        "rejected_blocklist": 0,
        "rejected_no_signal": 0,
        "admitted_icsma": 0,
        "admitted_medical_term": 0,
    }
    
    for r in results:
        desc = r.get("description", "")
        ics_flag = bool(r.get("ics_advisory", False))
        ics_urls = r.get("ics_urls", []) or []
        
        in_scope, reason = is_in_scope(desc, ics_flag, ics_urls)
        
        if in_scope:
            stats["kept"] += 1
            if "ICSMA" in reason:
                stats["admitted_icsma"] += 1
            else:
                stats["admitted_medical_term"] += 1
            if include_explanation:
                r["_scope_reason"] = reason
            kept.append(r)
        else:
            if "non-medical product" in reason:
                stats["rejected_blocklist"] += 1
            else:
                stats["rejected_no_signal"] += 1
    
    return (kept, stats)
