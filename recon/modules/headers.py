"""Security-header and cookie-flag checks. Pure-Python (requests), no Docker.

Parsing/analysis lives in `analyze()` which takes plain data (a headers dict)
so it can be unit-tested without any network access. Finding text is authored in
English; Turkish comes from recon/i18n.py keyed by rule_id/msg_key.
"""
from __future__ import annotations

from ..findings import Finding
from ..scope import Scope, ScopeViolation, scoped_get

NAME = "headers"
NEEDS_DOCKER = False

# header -> (rule slug, severity, english why)
EXPECTED = {
    "Strict-Transport-Security": ("missing-hsts", "medium",
        "No HSTS: protocol-downgrade / MITM risk"),
    "Content-Security-Policy": ("missing-csp", "medium",
        "No CSP: wider XSS impact"),
    "X-Content-Type-Options": ("missing-nosniff", "low",
        "No nosniff: MIME sniffing risk"),
    "X-Frame-Options": ("missing-xfo", "low",
        "Missing: clickjacking risk (if no CSP frame-ancestors)"),
    "Referrer-Policy": ("missing-referrer-policy", "info",
        "Missing: referrer information leak"),
    "Permissions-Policy": ("missing-permissions-policy", "info",
        "Missing: browser features not restricted"),
}


def analyze(headers: dict, status: int, url: str) -> list[Finding]:
    """Pure analysis of a response's headers. Pass the raw header dict."""
    present = {k.lower(): v for k, v in headers.items()}
    findings: list[Finding] = []

    for header, (slug, sev, why) in EXPECTED.items():
        if header.lower() not in present:
            findings.append(Finding(
                NAME, f"Missing security header: {header}", sev, why,
                evidence=f"GET {url} -> {status}",
                recommendation=f"Add the {header} response header.",
                rule_id=f"{NAME}.{slug}",
            ))

    for h in ("Server", "X-Powered-By", "X-AspNet-Version"):
        if h.lower() in present:
            val = present[h.lower()]
            findings.append(Finding(
                NAME, f"Technology disclosure: {h}", "info",
                f"{h}: {val}",
                recommendation=f"Remove/generalize the {h} header.",
                rule_id=f"{NAME}.tech-disclosure-{h.lower()}",
                msg_key=f"{NAME}.tech-disclosure",
                params={"header": h, "value": val},
            ))

    set_cookie = present.get("set-cookie", "")
    if set_cookie:
        low = set_cookie.lower()
        missing = [flag for flag, key in
                   (("Secure", "secure"), ("HttpOnly", "httponly"),
                    ("SameSite", "samesite")) if key not in low]
        if missing:
            findings.append(Finding(
                NAME, "Missing cookie flag", "low",
                "Missing: " + ", ".join(missing),
                evidence="Set-Cookie header missing a flag",
                recommendation="Set Secure + HttpOnly + SameSite on session cookies.",
                rule_id=f"{NAME}.cookie-flags",
                params={"missing": ", ".join(missing)},
            ))
    return findings


def run(target: str, ctx: dict) -> list[Finding]:
    scope = ctx.get("scope") or Scope.allow_all()
    try:
        r = scoped_get(target, scope, timeout=ctx.get("http_timeout", 15))
    except ScopeViolation as e:
        return [Finding(NAME, "Out-of-scope redirect blocked", "info",
                        f"A redirect pointed outside the allowed scope: {e}",
                        rule_id=f"{NAME}.scope-blocked",
                        params={"host": str(e)})]
    except Exception as e:
        return [Finding(NAME, "HTTP request failed", "info",
                        f"Could not fetch {target}: {e}",
                        rule_id=f"{NAME}.request-failed",
                        params={"target": target, "error": str(e)})]
    return analyze(dict(r.headers), r.status_code, r.url)
