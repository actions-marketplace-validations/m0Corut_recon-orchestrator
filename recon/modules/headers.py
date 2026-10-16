"""Security-header, CSP/HSTS quality and cookie checks. Pure-Python, no Docker.

All analysis lives in pure functions (`analyze`, `analyze_csp`, `analyze_hsts`,
`analyze_cookies`) that take plain data, so they unit-test without the network.
Presence checks tell you a header is missing; the quality checks tell you a
header is present but weak (a `default-src *` CSP, a short HSTS, a `SameSite=None`
cookie without `Secure`). Finding text is English; Turkish comes from i18n keyed
by rule_id/msg_key.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

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

HSTS_MIN_MAX_AGE = 15552000      # 180 days
SESSION_COOKIE_HINTS = (
    "sess", "sid", "token", "auth", "jwt", "phpsessid", "jsessionid",
    "connect.sid", "wordpress_logged_in", "asp.net_sessionid", "csrftoken",
)


# ---- CSP ----------------------------------------------------------------------

def parse_csp(policy_text: str) -> dict[str, list[str]]:
    """Pure: 'a b; c d' -> {'a': ['b'], 'c': ['d']}. Directive names lowercased."""
    out: dict[str, list[str]] = {}
    for part in policy_text.split(";"):
        tokens = part.split()
        if not tokens:
            continue
        out[tokens[0].lower()] = tokens[1:]
    return out


def _effective(directives: dict[str, list[str]], name: str) -> list[str] | None:
    if name in directives:
        return directives[name]
    if "default-src" in directives:
        return directives["default-src"]
    return None


def _has_nonce_or_hash(sources: list[str]) -> bool:
    return any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
              for s in sources)


def _is_wildcard_source(s: str) -> bool:
    s = s.strip().strip("'")
    return s in ("*", "http:", "https:", "data:") or s.startswith("*.") or "://*" in s


def analyze_csp(policy_text: str, report_only: bool, url: str) -> list[Finding]:
    """Pure: quality findings for a present CSP header value."""
    def f(slug, sev, detail, token=""):
        return Finding(NAME, f"CSP weakness: {slug}", sev, detail,
                       evidence=f"{slug}: {token}" if token else slug,
                       recommendation="Tighten the Content-Security-Policy.",
                       rule_id=f"{NAME}.{slug}", params={"token": token})

    directives = parse_csp(policy_text)
    if not directives:
        return [f("csp-unparseable", "info", "CSP header could not be parsed.")]
    out: list[Finding] = []
    script = _effective(directives, "script-src") or []
    if "'unsafe-inline'" in script and not _has_nonce_or_hash(script) \
            and "'strict-dynamic'" not in script:
        out.append(f("csp-unsafe-inline", "medium",
                     "script-src allows 'unsafe-inline' with no nonce/hash.",
                     "'unsafe-inline'"))
    if "'unsafe-eval'" in script:
        out.append(f("csp-unsafe-eval", "low", "script-src allows 'unsafe-eval'.",
                     "'unsafe-eval'"))
    for d in ("script-src", "object-src", "default-src"):
        srcs = directives.get(d, [])
        wild = next((s for s in srcs if _is_wildcard_source(s)), None)
        if wild:
            out.append(f("csp-wildcard-source", "medium",
                         f"{d} contains a wildcard/broad source.", f"{d} {wild}"))
            break
    if "object-src" not in directives and "default-src" not in directives:
        out.append(f("csp-missing-object-src", "low",
                     "No object-src and no default-src to restrict plugins."))
    if "base-uri" not in directives:
        out.append(f("csp-missing-base-uri", "low", "No base-uri directive."))
    if _has_nonce_or_hash(script) and "'strict-dynamic'" not in script:
        out.append(f("csp-nonce-without-strict-dynamic", "info",
                     "Nonce/hash without 'strict-dynamic' (allow-list bypass class)."))
    if report_only:
        out.append(f("csp-report-only", "low",
                     "CSP is Report-Only; it is not enforced."))
    return out


# ---- HSTS ---------------------------------------------------------------------

def analyze_hsts(value: str, url: str, over_http: bool = False) -> list[Finding]:
    out: list[Finding] = []
    low = value.lower()
    m = re.search(r"max-age\s*=\s*(\d+)", low)
    max_age = int(m.group(1)) if m else 0
    if over_http:
        out.append(Finding(NAME, "HSTS served over HTTP", "info",
                           "HSTS on a plain-HTTP response is ignored by browsers.",
                           evidence=value, rule_id=f"{NAME}.hsts-over-http"))
    if max_age < HSTS_MIN_MAX_AGE:
        out.append(Finding(NAME, "HSTS max-age is short", "low",
                           f"max-age={max_age} (< {HSTS_MIN_MAX_AGE}, ~180d).",
                           evidence=value, recommendation="Use max-age >= 15552000.",
                           rule_id=f"{NAME}.hsts-short-max-age",
                           params={"max_age": max_age}))
    if "includesubdomains" not in low:
        out.append(Finding(NAME, "HSTS without includeSubDomains", "info",
                           "Subdomains are not covered by HSTS.",
                           evidence=value, rule_id=f"{NAME}.hsts-no-subdomains"))
    return out


# ---- cookies ------------------------------------------------------------------

def _parse_cookie(set_cookie: str) -> tuple[str, dict[str, str]]:
    parts = [p.strip() for p in set_cookie.split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts and "=" in parts[0] else parts[0]
    attrs: dict[str, str] = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip()
    return name, attrs


def _is_session_cookie(name: str) -> bool:
    low = name.lower()
    return any(h in low for h in SESSION_COOKIE_HINTS)


def analyze_cookies(set_cookie_values: list[str], scheme: str,
                    host: str) -> list[Finding]:
    out: list[Finding] = []
    for raw in set_cookie_values:
        name, attrs = _parse_cookie(raw)
        if not name:
            continue
        session = _is_session_cookie(name)
        missing = [flag for flag, key in
                   (("Secure", "secure"), ("HttpOnly", "httponly"),
                    ("SameSite", "samesite")) if key not in attrs]
        if missing:
            out.append(Finding(
                NAME, f"Missing cookie flag: {name}", "low",
                "Missing: " + ", ".join(missing),
                evidence=name, recommendation="Set Secure + HttpOnly + SameSite.",
                rule_id=f"{NAME}.cookie-flags", params={"missing": ", ".join(missing),
                                                        "cookie": name}))
        if attrs.get("samesite", "").lower() == "none" and "secure" not in attrs:
            out.append(Finding(
                NAME, f"Cookie SameSite=None without Secure: {name}", "medium",
                "SameSite=None requires Secure; browsers reject it otherwise and "
                "it is sent cross-site.",
                evidence=name, recommendation="Add Secure to SameSite=None cookies.",
                rule_id=f"{NAME}.cookie-samesite-none-insecure", params={"cookie": name}))
        if session and scheme == "http":
            out.append(Finding(
                NAME, f"Session cookie set over HTTP: {name}", "medium",
                "A session cookie was set on a plain-HTTP response.",
                evidence=name, recommendation="Serve the login over HTTPS only.",
                rule_id=f"{NAME}.cookie-session-over-http", params={"cookie": name}))
        dom = attrs.get("domain", "").lstrip(".").lower()
        if dom and host and host.endswith("." + dom) and dom != host:
            out.append(Finding(
                NAME, f"Cookie scoped to a broad domain: {name}", "low",
                f"Domain={dom} covers sibling subdomains of {host}.",
                evidence=name, recommendation="Scope cookies to the exact host.",
                rule_id=f"{NAME}.cookie-broad-domain", params={"cookie": name,
                                                              "domain": dom}))
        if session and not name.startswith(("__Host-", "__Secure-")):
            out.append(Finding(
                NAME, f"Session cookie without __Host-/__Secure- prefix: {name}", "info",
                "Prefix hardens the cookie against fixation/overwrite.",
                evidence=name, rule_id=f"{NAME}.cookie-no-host-prefix",
                params={"cookie": name}))
    return out


# ---- orchestration ------------------------------------------------------------

def analyze(headers: dict, status: int, url: str,
            set_cookie_values: list[str] | None = None) -> list[Finding]:
    """Pure analysis of a response's headers plus its separate Set-Cookie list."""
    present = {k.lower(): v for k, v in headers.items()}
    findings: list[Finding] = []

    csp_val = present.get("content-security-policy")
    cspro_val = present.get("content-security-policy-report-only")
    # Only an ENFORCED frame-ancestors actually blocks framing. A Report-Only CSP
    # merely reports violations (it never blocks), so its frame-ancestors must NOT
    # suppress the missing-X-Frame-Options finding — doing so would hide a real
    # clickjacking exposure.
    has_frame_ancestors = bool(csp_val and "frame-ancestors" in csp_val.lower())

    for header, (slug, sev, why) in EXPECTED.items():
        hl = header.lower()
        if hl in present:
            continue
        # Report-Only present instead of enforced CSP: report that, not "missing"
        if hl == "content-security-policy" and cspro_val:
            continue
        # frame-ancestors covers clickjacking; don't also demand XFO
        if slug == "missing-xfo" and has_frame_ancestors:
            continue
        findings.append(Finding(
            NAME, f"Missing security header: {header}", sev, why,
            evidence=f"GET {url} -> {status}",
            recommendation=f"Add the {header} response header.",
            rule_id=f"{NAME}.{slug}"))

    if csp_val:
        findings += analyze_csp(csp_val, report_only=False, url=url)
    elif cspro_val:
        findings += analyze_csp(cspro_val, report_only=True, url=url)

    scheme = urlparse(url).scheme or "https"
    if "strict-transport-security" in present:
        findings += analyze_hsts(present["strict-transport-security"], url,
                                 over_http=(scheme == "http"))

    for h in ("Server", "X-Powered-By", "X-AspNet-Version"):
        if h.lower() in present:
            val = present[h.lower()]
            findings.append(Finding(
                NAME, f"Technology disclosure: {h}", "info", f"{h}: {val}",
                recommendation=f"Remove/generalize the {h} header.",
                rule_id=f"{NAME}.tech-disclosure-{h.lower()}",
                msg_key=f"{NAME}.tech-disclosure", params={"header": h, "value": val}))

    host = (urlparse(url).hostname or "").lower()
    cookies = set_cookie_values
    if cookies is None:                       # fallback: folded header (tests / old callers)
        cookies = [present["set-cookie"]] if "set-cookie" in present else []
    findings += analyze_cookies(cookies, scheme, host)
    return findings


def _set_cookie_list(resp) -> list[str]:
    """Separate Set-Cookie values (requests folds them into one header)."""
    raw = getattr(resp, "raw", None)
    hdrs = getattr(raw, "headers", None)
    if hdrs is not None and hasattr(hdrs, "getlist"):
        values = hdrs.getlist("Set-Cookie")
        if values:
            return list(values)
    one = resp.headers.get("Set-Cookie")
    return [one] if one else []


def run(target: str, ctx: dict) -> list[Finding]:
    scope = ctx.get("scope") or Scope.allow_all()
    try:
        r = scoped_get(target, scope, timeout=ctx.get("http_timeout", 15),
                       limiter=ctx.get("limiter"))
    except ScopeViolation as e:
        return [Finding(NAME, "Out-of-scope redirect blocked", "info",
                        f"A redirect pointed outside the allowed scope: {e}",
                        rule_id=f"{NAME}.scope-blocked", params={"host": str(e)})]
    except Exception as e:
        return [Finding(NAME, "HTTP request failed", "info",
                        f"Could not fetch {target}: {e}",
                        rule_id=f"{NAME}.request-failed",
                        params={"target": target, "error": str(e)})]
    return analyze(dict(r.headers), r.status_code, r.url, _set_cookie_list(r))
