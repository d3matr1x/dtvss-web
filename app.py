"""
=============================================================================
PATCH FOR app.py — security.txt routes
=============================================================================
Add the following routes to app.py.

WHERE TO ADD: directly after the existing /sitemap.xml route (around line
180-185 in the current app.py) and BEFORE the catch-all /<path:filename>
route. The catch-all uses STATIC_ASSET_PREFIXES and would 404 anything
under /.well-known/, so the dedicated routes must come first.

WHY NOT JUST WHITELIST .well-known/ IN STATIC_ASSET_PREFIXES?
The catch-all route was deliberately constrained per finding MED-04 of the
pentest. Adding a new prefix widens the attack surface; an explicit, named
route per file is consistent with the existing pattern (see how robots.txt
and sitemap.xml are handled).
=============================================================================
"""

from flask import redirect


# -----------------------------------------------------------------------------
# Security disclosure (RFC 9116)
# -----------------------------------------------------------------------------
# Served from /.well-known/security.txt as the canonical location. The
# legacy /security.txt path 301s to the canonical URL so older scanners
# still find it. The human-readable policy lives at /security-policy and
# is referenced by the `Policy:` field inside security.txt.

@app.route("/.well-known/security.txt")
def security_txt():
    """
    RFC 9116 security.txt. The file lives at
    static/.well-known/security.txt in the repo so it's served verbatim.

    Content-Type must be text/plain per RFC 9116 §3. UTF-8 is the
    canonical encoding.
    """
    return send_from_directory(
        "static/.well-known",
        "security.txt",
        mimetype="text/plain; charset=utf-8",
    )


@app.route("/security.txt")
def security_txt_legacy():
    """
    Legacy location — redirect to the canonical /.well-known/ path.
    RFC 9116 §3 prefers /.well-known/ but allows /security.txt as a
    fallback for environments where /.well-known/ is unreachable.
    301 (permanent) is appropriate because the canonical location will
    not change.
    """
    return redirect("/.well-known/security.txt", code=301)


@app.route("/security-policy")
def security_policy():
    """
    Human-readable vulnerability disclosure policy linked from the
    `Policy:` field inside security.txt.
    """
    return send_from_directory("static", "security-policy.html")
