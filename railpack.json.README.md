# `railpack.json` — what this file does

Per Fix #7b in `PATCHES_v2.md` (post-Nixpacks migration).

## Why this file exists

Railpack's default Python provider runs `pip install -r requirements.txt`,
which does **not** verify package hashes. We need
`pip install --require-hashes -r requirements-lock.txt` to fail-closed
against tampered packages or a MITM'd PyPI mirror.

Overriding the install step via `railpack.json` is the supported,
git-tracked way to do this. The alternative —
`RAILPACK_INSTALL_COMMAND` env var — lives in the Railway dashboard
and isn't visible from the repo.

## Why `railpack.json` has no comments

JSON doesn't support comments natively. Railpack's schema declares
`"additionalProperties": false` at the root, so any custom keys
(like `_comment`) will fail schema validation and break the build.
This README is the comment.

## Why we still keep `requirements.txt`

Railpack's Python provider auto-detects `requirements.txt` to:

1. Pick the Python version (via Mise, Railpack's tool installer)
2. Identify which language/framework providers to enable

We let that detection happen, and override only the install command
itself so hashes are enforced on the actual package install.

## When you bump a dependency

```bash
# 1. Edit requirements.txt with the new pin
$EDITOR requirements.txt

# 2. Regenerate the lockfile
pip install pip-tools  # one-time, in your dev env
pip-compile --generate-hashes -o requirements-lock.txt requirements.txt

# 3. Commit both files together
git add requirements.txt requirements-lock.txt
git commit -m "Bump <pkg> to <ver>"

# 4. (Optional but recommended) Re-audit
pip-audit -r requirements.txt
```

## When the build fails with a hash mismatch

**STOP.** That mismatch is the security control firing — investigate
before regenerating the lockfile. A tampered package on PyPI or a
hijacked mirror is exactly the case this is designed to catch.

Steps:

1. Check what package failed and what hash was expected vs received
2. Compare against a known-good build (CI run from the previous deploy)
3. Cross-check the package's hash on PyPI's web UI from a separate
   network path
4. If everything looks legitimate (e.g., you forgot to regenerate the
   lockfile after bumping a version), regenerate per the section above
5. If anything looks off, report to the Python Packaging Working
   Group's security contact and to PyPI security

## Migration notes

Railway's previous builder, Nixpacks, used `[build.nixpacksConfig.phases.install]`
in `railway.toml` to override the install command. Railpack does NOT
honour that block — the equivalent moved to `railpack.json`. This is
why the old `[build.nixpacksConfig.*]` entry was removed from
`railway.toml` in the same patch.

If you ever need to switch back to Nixpacks (don't — it's deprecated),
you would need to:

1. Set `builder = "NIXPACKS"` in `railway.toml`
2. Move the install commands from this file back into `[build.nixpacksConfig.phases.install].cmds`
3. Delete `railpack.json` (or it'll be ignored, but cleaner to remove)
