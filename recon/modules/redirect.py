"""Open-redirect detection (read-only, benign canary, never follows).

For crawled URLs whose parameter looks redirect-related (`next`, `url`,
`redirect`, …), replace the value with a reserved canary (`https://example.org/`)
and check whether the response's `Location`, a meta refresh, or a JS
`window.location` points at the canary host. The redirect is never followed
(the canary is a reserved documentation domain, so a mistaken follow is harmless
anyway). Pure analysis is split from `run()`.
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from ..findings import Finding
from ..scope import Scope, ScopeViolation, scoped_get

NAME = "redirect"
NEEDS_DOCKER = False

REDIRECT_PARAMS = {
    "next", "url", "redirect", "redirect_uri", "redirect_url", "return",
    "return_to", "returnurl", "continue", "dest", "destination", "goto",
    "target", "rurl", "callback", "forward", "to", "out", "link",
}
CANARY = "https://example.org/recon-canary"
CANARY_HOST = "example.org"
MAX_CANDIDATES = 25


def select_candidates(crawled_urls) -> list[tuple[str, str]]:
    """Pure: [(url, param)] for redirect-style params, deduped per (path, param)."""
    seen: set[tuple[str, str, str]] = set()
    out: list[tuple[str, str]] = []
    for url in crawled_urls or []:
        p = urlparse(url)
        for key, _ in parse_qsl(p.query):
            if key.lower() in REDIRECT_PARAMS:
                sig = (p.netloc, p.path, key.lower())
                if sig not in seen:
                    seen.add(sig)
                    out.append((url, key))
    return out[:MAX_CANDIDATES]


def build_probe(url: str, param: str, canary: str = CANARY) -> str:
    """Pure: `url` with `param` replaced by the canary value."""
    p = urlparse(url)
    q = [(k, canary if k == param else v) for k, v in parse_qsl(p.query)]
    return urlunparse(p._replace(query=urlencode(q)))


def analyze_redirect(url: str, status: int, location: str, body_head: str,
                     canary_host: str = CANARY_HOST) -> Finding | None:
    """Pure: flag a redirect/body that points at the canary host."""
    if status in (301, 302, 303, 307, 308) and location:
        loc_host = (urlparse(urljoin(url, location)).hostname or "").lower()
        if loc_host == canary_host:
            return Finding(
                NAME, f"Open redirect: {url}", "medium",
                "A redirect-style parameter sends users to an attacker-chosen host.",
                evidence=f"{url} -> Location: {location}",
                recommendation="Validate redirect targets against an allow-list.",
                rule_id=f"{NAME}.open-redirect", msg_key=f"{NAME}.open-redirect",
                params={"url": url})
    low = (body_head or "").lower()
    if canary_host in low and ("http-equiv=\"refresh\"" in low or "window.location" in low
                               or "location.href" in low):
        return Finding(
            NAME, f"Open redirect (meta/JS): {url}", "medium",
            "A meta-refresh or JavaScript redirect points at an attacker-chosen host.",
            evidence=f"{url} -> body redirect to {canary_host}",
            recommendation="Validate redirect targets against an allow-list.",
            rule_id=f"{NAME}.open-redirect-meta", msg_key=f"{NAME}.open-redirect",
            params={"url": url})
    if canary_host in low:
        return Finding(
            NAME, f"Redirect parameter reflected (not redirected): {url}", "info",
            "The canary value is reflected in the page but no redirect happened; "
            "worth a manual check.",
            evidence=f"{url}: canary reflected",
            rule_id=f"{NAME}.reflected-not-redirected", params={"url": url})
    return None


def run(target: str, ctx) -> list[Finding]:
    scope = ctx.get("scope") or Scope.allow_all()
    limiter = ctx.get("limiter")
    timeout = ctx.get("http_timeout", 15)
    candidates = select_candidates(ctx.get("crawled_urls"))
    if not candidates:
        return [Finding(
            NAME, "No redirect-style parameters found", "info",
            "No crawled URL had a redirect-style parameter (run with the crawl "
            "module to discover them).",
            rule_id=f"{NAME}.no-candidates")]

    findings: list[Finding] = []
    for url, param in candidates:
        probe = build_probe(url, param)
        try:
            r = scoped_get(probe, scope, timeout=timeout, max_redirects=0,
                           limiter=limiter, max_bytes=65536)
        except (ScopeViolation, Exception):  # noqa: BLE001
            continue
        f = analyze_redirect(probe, r.status_code, r.headers.get("Location", ""),
                             r.text or "")
        if f:
            findings.append(f)
    if not findings:
        findings.append(Finding(
            NAME, "No open redirect found", "info",
            f"Tested {len(candidates)} redirect-style parameter(s); none redirected "
            "off-site.", rule_id=f"{NAME}.clean", params={"tested": len(candidates)}))
    return findings
