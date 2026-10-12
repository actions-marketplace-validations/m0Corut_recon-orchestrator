"""CMS detection and WordPress-specific exposure checks (read-only).

Fingerprints the CMS from the home page and headers, then — for WordPress, the
most common one — probes a short list of well-known paths that routinely leak
information or widen the attack surface: the REST user list (user enumeration),
an exposed debug log (can leak secrets), xmlrpc.php (brute-force / amplification),
and the version from readme/meta (ties the install to known CVEs).

Read-only: GET/HEAD only, through scoped_get and the shared rate limit. Parsing
is split into pure functions so it is unit-tested without the network. Opt-in
(``-m cms``); not in the default set.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from ..findings import Finding
from ..scope import Scope, ScopeViolation, scoped_get

NAME = "cms"
NEEDS_DOCKER = False

_GENERATOR = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I)
_WP_VER = re.compile(r"wordpress\s*([0-9.]+)", re.I)

# WordPress paths to probe -> handler. Each handler is pure: (status, body) -> Finding|None
# Two forms of the REST users route: pretty permalinks vs the default plain ones.
WP_USER_ROUTES = ("wp-json/wp/v2/users", "?rest_route=/wp/v2/users")
WP_PATHS = (*WP_USER_ROUTES, "wp-content/debug.log", "xmlrpc.php", "readme.html")


def detect_cms(html: str, headers: dict) -> tuple[str, str] | None:
    """Pure: identify the CMS and version from a home-page response.

    Returns (cms, version) or None. Version is "" when unknown.
    """
    hdr = {k.lower(): v for k, v in (headers or {}).items()}
    gen_match = _GENERATOR.search(html or "")
    generator = gen_match.group(1) if gen_match else ""
    blob = " ".join([generator, hdr.get("x-powered-by", ""), hdr.get("x-generator", ""),
                     hdr.get("link", "")]).lower()
    body = (html or "").lower()

    if "wordpress" in blob or "/wp-content/" in body or "/wp-json/" in body \
            or "wp-json" in hdr.get("link", "").lower():
        m = _WP_VER.search(generator) or _WP_VER.search(body)
        return "WordPress", (m.group(1) if m else "")
    if "joomla" in blob or "/media/jui/" in body:
        m = re.search(r"joomla!?\s*([0-9.]+)", generator, re.I)
        return "Joomla", (m.group(1) if m else "")
    if "drupal" in blob or "sites/all/" in body or "drupal-settings-json" in body:
        m = re.search(r"drupal\s*([0-9.]+)", generator, re.I)
        return "Drupal", (m.group(1) if m else "")
    return None


def analyze_home(target: str, cms: str, version: str) -> Finding:
    detail = f"{cms} detected" + (f" (version {version})" if version else
                                  " (version not disclosed)")
    return Finding(
        NAME, f"CMS detected: {cms}", "info", detail,
        evidence=f"{cms} {version}".strip(),
        recommendation="Keep the CMS and its plugins updated; hide the version.",
        rule_id=f"{NAME}.detected", msg_key=f"{NAME}.detected",
        params={"cms": cms, "version": version or "?"})


def _looks_like_body(status: int, body: str, needles: tuple[str, ...]) -> bool:
    return status == 200 and any(n in (body or "").lower() for n in needles)


def analyze_wordpress(probe: dict[str, tuple[int, str]]) -> list[Finding]:
    """Pure: findings from probed WordPress paths. probe: path -> (status, body)."""
    out: list[Finding] = []
    user_route = next(
        (r for r in WP_USER_ROUTES
         if probe.get(r, (0, ""))[0] == 200
         and ('"slug"' in probe[r][1] or '"name"' in probe[r][1])), None)
    if user_route:
        out.append(Finding(
            NAME, "WordPress user enumeration via REST API", "medium",
            "The REST users endpoint lists usernames, which helps "
            "credential attacks.",
            evidence=f"GET /{user_route} -> 200 with user list",
            recommendation="Restrict the users REST route or require authentication.",
            rule_id=f"{NAME}.wp-user-enum"))
    st, body = probe.get("wp-content/debug.log", (0, ""))
    if st == 200 and body.strip():
        out.append(Finding(
            NAME, "WordPress debug log is publicly readable", "high",
            "/wp-content/debug.log is reachable and may leak paths, queries, "
            "secrets and stack traces.",
            evidence="GET /wp-content/debug.log -> 200",
            recommendation="Disable WP_DEBUG_LOG in production and block the file.",
            rule_id=f"{NAME}.wp-debug-log"))
    st, _ = probe.get("xmlrpc.php", (0, ""))
    if st in (200, 405):     # 405 = method not allowed on GET, but the file is there
        out.append(Finding(
            NAME, "WordPress XML-RPC is enabled", "low",
            "xmlrpc.php is reachable; it enables brute-force amplification "
            "(system.multicall) and pingback-based attacks.",
            evidence=f"GET /xmlrpc.php -> {st}",
            recommendation="Disable XML-RPC if unused, or rate-limit it.",
            rule_id=f"{NAME}.wp-xmlrpc"))
    st, body = probe.get("readme.html", (0, ""))
    if st == 200 and "wordpress" in body.lower():
        m = _WP_VER.search(body)
        out.append(Finding(
            NAME, "WordPress readme.html exposes the version", "low",
            "readme.html is readable and discloses the exact version, tying the "
            "install to known CVEs.",
            evidence=f"GET /readme.html -> 200{(' (v' + m.group(1) + ')') if m else ''}",
            recommendation="Delete or block readme.html.",
            rule_id=f"{NAME}.wp-readme"))
    return out


def run(target: str, ctx) -> list[Finding]:
    scope = ctx.get("scope") or Scope.allow_all()
    limiter = ctx.get("limiter")
    timeout = ctx.get("http_timeout", 15)
    try:
        home = scoped_get(target, scope, timeout=timeout, limiter=limiter)
    except (ScopeViolation, Exception) as e:  # noqa: BLE001
        return [Finding(NAME, "CMS check could not fetch the target", "info",
                        f"Home page fetch failed: {type(e).__name__}.",
                        rule_id=f"{NAME}.unreachable")]

    detected = detect_cms(home.text, dict(home.headers))
    if not detected:
        return [Finding(NAME, "No known CMS detected", "info",
                        "No WordPress/Joomla/Drupal fingerprint on the home page.",
                        rule_id=f"{NAME}.none")]
    cms, version = detected
    findings = [analyze_home(target, cms, version)]

    if cms == "WordPress":
        base = target.rstrip("/") + "/"
        probe: dict[str, tuple[int, str]] = {}
        for path in WP_PATHS:
            try:
                r = scoped_get(urljoin(base, path), scope, timeout=timeout,
                               limiter=limiter)
                probe[path] = (r.status_code, r.text[:4096])
            except (ScopeViolation, Exception):  # noqa: BLE001
                continue
        findings += analyze_wordpress(probe)
    return findings
