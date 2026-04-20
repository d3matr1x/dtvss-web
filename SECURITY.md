# Security Policy

The Dynamic Temporal Vulnerability Scoring System (DTVSS) is a security tool
itself, so we take vulnerability reports seriously. Thank you for taking the
time to disclose responsibly.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report privately through GitHub Security Advisories:

1. Go to the **Security** tab of this repository.
2. Click **Report a vulnerability**.
3. Fill in the form. Only repository maintainers will see it.

This creates a private advisory thread where we can coordinate triage,
fix, and disclosure with you directly.

If you cannot use GitHub Security Advisories for any reason, the
machine-readable contact in [`/.well-known/security.txt`](https://dtvss.io/.well-known/security.txt)
is the authoritative fallback.

## What to include

A useful report usually contains:

- A clear description of the issue and the security impact.
- Steps to reproduce, ideally with a minimal proof of concept.
- The affected commit, deployed URL, or version.
- Your name or handle if you want to be credited in the acknowledgements.

You do not need a working exploit — a credible explanation of impact is enough
to start triage.

## Scope

In scope:

- The DTVSS web application at `https://dtvss.io` and any subdomains we
  operate.
- The source code in this repository, including the Flask application
  (`app.py`), the security-hardening module (`security.py`), the scoring
  engine (`dtvss_engine.py`), the API clients (`api_clients.py`), the
  index loader (`index_loader.py`), and the build scripts.
- The deployment configuration (`railway.toml`, `Procfile`,
  `requirements.txt`).

Out of scope:

- Vulnerabilities in upstream data sources we consume but do not control:
  the National Vulnerability Database (NVD), the Exploit Prediction Scoring
  System (EPSS / FIRST.org), the CISA Known Exploited Vulnerabilities (KEV)
  catalogue, and the CISA CSAF / ICSMA feeds. Report those to the relevant
  upstream provider.
- Vulnerabilities in third-party Python packages listed in
  `requirements.txt`. Report those to the package maintainers; we will
  pick up the fix once it is released.
- Findings that depend solely on missing best-practice headers without a
  demonstrable impact (we already apply a hardened header set via
  `security.py`).
- Rate-limit bypasses that only achieve what an authenticated user could
  already do.
- Denial of service via volumetric traffic — the application runs behind
  Railway's edge and rate limiting; please do not stress-test the
  production deployment.
- Social engineering of project maintainers.

## Safe harbour

We will not pursue legal action against researchers who:

- Make a good-faith effort to avoid privacy violations, data destruction,
  service degradation, or disruption to other users.
- Test only against accounts and data they own, or against scoped test
  accounts we provide on request.
- Report the issue to us privately and give us a reasonable opportunity to
  fix it before public disclosure.
- Do not exploit the issue beyond the minimum needed to demonstrate it.

If in doubt about whether an action is in scope, ask first via a private
advisory.

## Coordinated disclosure timeline

We aim for the following timeline. We will tell you if a fix needs longer
and why.

- **Acknowledgement**: within 5 business days of receiving the report.
- **Triage and severity assessment**: within 10 business days.
- **Fix or mitigation**: within 90 days for high and critical issues,
  longer for lower-severity issues that require a coordinated upstream
  release.
- **Public disclosure**: by mutual agreement, typically when a fix has
  shipped and users have had time to update.

If we go quiet for more than 14 days without explanation, you are free to
escalate by re-pinging the advisory or, as a last resort, disclosing
publicly with reasonable notice.

## Acknowledgements

Researchers who report valid issues and want public credit are listed in
the closed advisories on the Security tab.

---

Copyright © 2026 Andrew Broglio. Patent Pending — IP Australia.
Licensed under BSL 1.1.
