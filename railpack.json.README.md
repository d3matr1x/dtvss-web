# `railpack.json` — what this file does

## Why this file exists

This file tells Railway's Railpack builder to pin Python to version 3.12
for the production build. Railpack's auto-detection would otherwise pick
the latest available Python (3.13+), which doesn't match the Python
version `requirements-lock.txt` was generated against.

## Why it's so minimal

We tried to override Railpack's install step to enforce
`pip install --require-hashes -r requirements-lock.txt` at deploy time,
but ran into cascading Railpack bugs:

1. Railpack silently dropped shell commands with `&&` separators
2. Creating a venv at `/app/.venv` manually conflicted with Railpack's
   runtime-image copy step
3. Not creating a venv caused the deploy step to fail looking for one
4. Python 3.13 vs 3.12 wheel hash mismatches when lockfile was
   generated against 3.12

Rather than fighting Railpack further, we accepted a compromise:
**Railpack uses its default `pip install -r requirements.txt` flow**,
which works reliably. Hash verification is still enforced in two places:

1. **CI (`.github/workflows/security.yml`)** — every PR must pass
   `pip install --require-hashes -r requirements-lock.txt` before it
   can be merged. If a dep drift appears, the PR is blocked.

2. **`requirements-lock.txt`** is still committed to the repo. If you
   ever deploy via Docker, Render, Fly, or anywhere else with a
   well-behaved pip install pipeline, you get hash verification back.

## What this costs

For production deploys to Railway specifically:
- No protection against a compromised PyPI mirror serving tampered
  wheels during the build
- No protection against a PyPI account takeover that publishes a
  malicious version of a pinned package

For a tool with no user data, no auth, no PHI, and version-pinned deps
(so CVE scanners still catch known bad versions), this is a defensible
tradeoff.

## When you bump a dependency

```bash
# 1. Edit requirements.txt with the new pin
$EDITOR requirements.txt

# 2. Regenerate the lockfile so CI still passes
pip install pip-tools
pip-compile --generate-hashes -o requirements-lock.txt requirements.txt

# 3. Commit both files together
git add requirements.txt requirements-lock.txt
git commit -m "Bump <pkg> to <ver>"
```

## Getting hash verification back

If Railway fixes Railpack's custom-install quirks (or you switch
builders), the path to full hash verification is:

1. Replace this file with a version that has custom install commands
2. Test on a branch first, not main
3. Roll forward if the build succeeds, revert if not
