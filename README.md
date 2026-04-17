# DTVSS - Dynamic Temporal Vulnerability Scoring System

**Patent Pending - IP Australia**
**Copyright 2026 Andrew Broglio. All rights reserved.**
**Licensed under BSL 1.1**

## Formula

```
DTVSS(t) = (B/10 x H/10 x (1 + 15 x L(t))) x 10
```

- **B** - CVSS exploitability sub-score (8.22 x AV x AC x PR x UI per FIRST.org CVSS v3.1 spec)
- **L(t)** - Exploit likelihood (EPSS API from FIRST.org, updated daily)
- **H** - Patient harm modifier (TGA / Medsafe / EU MDR / MHRA / FDA classification)
- **k = 15** - Empirically calibrated against 96 real medical device CVEs
- **KEV override** - Score forced to 10.0 Critical when CVE in CISA KEV catalog

## Data Pipeline

**CVE Discovery** - CISA ICS Medical Advisories (ICSMA) only. Zero false positives.
- CISA CSAF JSON (cisagov/CSAF on GitHub) - full historical archive
- ICSMA RSS feed - hourly ingestion of new advisories

**Scoring** - Live per-CVE scoring with multi-source fallback:
- NVD API v2 -> MITRE CVE.org -> CISA Vulnrichment (for B value)
- EPSS API (for L(t) value)
- CISA KEV Catalog (for KEV override)
- TGA / EU MDR / MHRA / FDA device classification (for H value)

NVD is used for CVSS enrichment only, not CVE discovery.

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/lookup?cve=CVE-2017-12725` | GET | Single CVE lookup, auto-scored |
| `/api/search?q=Medtronic` | GET | Manufacturer search from ICSMA index |
| `/api/score` | POST | Manual scoring `{B, L, H, kev}` |
| `/api/device-classes` | GET | Available classes with H values |
| `/api/manufacturers` | GET | Dropdown list from ICSMA index |

Optional query parameter `tga_class=IIb` or `tga_class=III` overrides auto-detection.

## Deploy to Railway

1. Push this repo to GitHub
2. Go to [railway.app](https://railway.app) - New Project - Deploy from GitHub
3. Add environment variable: `NVD_API_KEY` (free from https://nvd.nist.gov/developers/request-an-api-key)
4. Railway auto-detects Python, installs requirements, runs gunicorn

The `mdm_index.json` ships with the repo (built by GitHub Actions daily).

## Build the Index Locally

```bash
pip install -r requirements.txt
export NVD_API_KEY=your-key-here
python build_index.py
```

This fetches all ICSMA CSAF JSON files from GitHub, supplements with RSS,
and enriches missing CVSS scores from NVD. Takes 2-5 minutes.

## Run Locally

```bash
pip install -r requirements.txt
export NVD_API_KEY=your-key-here
python app.py
# Open http://localhost:5000
```

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `NVD_API_KEY` | No | NVD API key. Without: 5 req/30s. With: 50 req/30s |
| `PORT` | No | Railway sets automatically. Default: 5000 |

## Update Schedule

- **Hourly** - ICSMA RSS check + NVD CVSS enrichment (runtime background thread)
- **Daily** - Full rebuild via GitHub Actions at 03:00 UTC (CSAF + RSS + NVD enrichment)

## Licence

Licensed under the Business Source License 1.1 (BSL 1.1).

- **Non-commercial use**: permitted (research, education, evaluation)
- **Commercial use**: requires a separate commercial licence
- **Change date**: 4 years from first public release
- **Change licence**: Apache License 2.0

Contact for commercial licensing enquiries.
