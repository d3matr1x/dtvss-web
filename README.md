# DTVSS - Dynamic Temporal Vulnerability Scoring System

**Patent Pending - IP Australia**
**© 2026 Andrew Broglio. All rights reserved.**
**Licensed under BSL 1.1**

## Formula

```
DTVSS(t) = (B/10 × H/10 × (1 + 15 × L(t))) × 10
```

- **B** - CVSS exploitability sub-score (NVD API v2)
- **L(t)** - Exploit likelihood (EPSS API, updated daily)
- **H** - Patient harm modifier (TGA/Medsafe/EU MDR/MHRA/FDA classification)
- **k = 15** - Empirically calibrated against 96 real medical device CVEs
- **KEV override** - Score forced to 10.0 Critical when CVE in CISA KEV catalog

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/lookup?cve=CVE-2017-12725` | GET | Single CVE lookup, auto-scored |
| `/api/search?q=Medfusion` | GET | Device name search, all results scored |
| `/api/score` | POST | Manual scoring `{B, L, H, kev}` |
| `/api/device-classes` | GET | Available classes with H values |

Optional query parameter `tga_class=IIb` or `tga_class=III` overrides auto-detection.

## Deploy to Railway

1. Push this repo to GitHub
2. Go to [railway.app](https://railway.app) → New Project → Deploy from GitHub
3. Add environment variable: `NVD_API_KEY` (free from https://nvd.nist.gov/developers/request-an-api-key)
4. Railway auto-detects Python, installs requirements, runs Procfile

## Run Locally

```bash
pip install -r requirements.txt
export NVD_API_KEY=your-key-here   # optional but recommended
python app.py
# Open http://localhost:5000
```

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `NVD_API_KEY` | No | NVD API key. Without: 5 req/30s. With: 50 req/30s |
| `PORT` | No | Railway sets automatically. Default: 5000 |

## Licence

Licensed under the Business Source License 1.1 (BSL 1.1).

- **Non-commercial use**: permitted (research, education, evaluation)
- **Commercial use**: requires a separate commercial licence
- **Change date**: 4 years from first public release
- **Change licence**: Apache License 2.0

Contact for commercial licensing enquiries.
