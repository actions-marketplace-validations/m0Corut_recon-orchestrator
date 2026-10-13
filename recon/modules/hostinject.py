"""Host-header injection / cache-poisoning SIGNALS (read-only, verify manually).

Sends a baseline request, then repeats it with a spoofed `X-Forwarded-Host`
(and variants) set to a reserved canary, and checks whether the canary is
reflected back into the response's `Location`, canonical/base link, resource URLs
or body — a sign the app trusts the host header (password-reset poisoning,
cache poisoning behind a shared cache).

Safety: GET only; the canary is a reserved subdomain of example.org; and every
probe carries a unique cache-buster query parameter so a real shared cache is
never poisoned for other users. Findings are signals ("verify manually"), not
confirmed vulnerabilities, so this module is opt-in and runs last. Pure analysis
is split from `run()`.
"""
from __future__ import annotations

import re
import secrets
from urllib.parse import urlparse

from ..findings import Finding
from ..scope import Scope, ScopeViolation, scoped_get

NAME = "hostinject"
NEEDS_DOCKER = False

CANARY = "recon-canary.example.org"

# label -> headers to inject. Host-reflection vectors only (no path override).
VARIANTS = {
    "x-forwarded-host": {"X-Forwarded-Host": CANARY},
    "x-forwarded-host+proto": {"X-Forwarded-Host": CANARY, "X-Forwarded-Proto": "http"},
    "forwarded": {"Forwarded": f"host={CANARY}"},
}


def build_variants() -> dict[str, dict[str, str]]:
    """Pure: the header sets to try (kept as a function for testability)."""
    return {k: dict(v) for k, v in VARIANTS.items()}


def _resource_reflection(body: str, canary: str) -> bool:
    """canary inside a canonical/base/resource URL or form action."""
    patterns = (
        rf'rel=["\']canonical["\'][^>]*href=["\'][^"\']*{re.escape(canary)}',
        rf'<base[^>]+href=["\'][^"\']*{re.escape(canary)}',
        rf'(?:src|href|action)=["\'][^"\']*//{re.escape(canary)}',
    )
    return any(re.search(p, body, re.I) for p in patterns)


def analyze_cacheability(headers: dict) -> bool:
    low = {k.lower(): str(v).lower() for k, v in headers.items()}
    cc = low.get("cache-control", "")
    # no-store / private are never served by a shared cache: can't be poisoned.
    if "no-store" in cc or "private" in cc:
        return False
    if "public" in cc or "s-maxage" in cc:
        return True
    if "age" in low:
        return True
    if "hit" in low.get("x-cache", ""):
        return True
    # A CDN cache header counts only when its value is a real caching state;
    # "dynamic"/"bypass"/"none" mean the response was NOT cached.
    cf = low.get("cf-cache-status", "")
    return cf not in ("", "dynamic", "bypass", "none")


def analyze_reflection(baseline_body: str, status: int, location: str,
                       variant_body: str, variant_headers: dict,
                       canary: str = CANARY) -> list[Finding]:
    """Pure: signals that the canary host was reflected by a variant request."""
    # if the baseline already contains the canary, reflection proves nothing
    if canary in (baseline_body or ""):
        return []
    cacheable = analyze_cacheability(variant_headers)

    def sig(slug, sev, detail, ev):
        return Finding(NAME, f"{detail} (signal, verify manually)",
                       sev, detail + " Confirm manually before acting.",
                       evidence=ev, recommendation="Validate Host against an allow-list; "
                       "ignore X-Forwarded-Host at the origin; strip unkeyed headers at the CDN.",
                       rule_id=f"{NAME}.{slug}", msg_key=f"{NAME}.{slug}",
                       params={"signal": True})

    out: list[Finding] = []
    if location and canary in location:
        out.append(sig("reflected-in-location", "medium",
                       "Spoofed host reflected in the Location header",
                       f"Location: {location}"))
    if _resource_reflection(variant_body, canary):
        out.append(sig("reflected-in-resource-url", "high" if cacheable else "medium",
                       "Spoofed host reflected in a resource/canonical URL",
                       f"canary in resource URL{' (cacheable)' if cacheable else ''}"))
    if not out and canary in (variant_body or ""):
        out.append(sig("reflected-in-body", "low",
                       "Spoofed host reflected in the response body",
                       "canary in body"))
    if cacheable and out:
        out.append(Finding(NAME,
                           "Reflecting response is cacheable (signal, verify manually)",
                           "info",
                           "The reflecting response carries cache headers; a shared "
                           "cache could serve the poisoned content.",
                           evidence="cache-control/age/x-cache present",
                           rule_id=f"{NAME}.cacheable-response", params={"signal": True}))
    return out


def _bust(url: str) -> str:
    sep = "&" if urlparse(url).query else "?"
    return f"{url}{sep}rc={secrets.token_hex(6)}"


def run(target: str, ctx) -> list[Finding]:
    scope = ctx.get("scope") or Scope.allow_all()
    limiter = ctx.get("limiter")
    timeout = ctx.get("http_timeout", 15)

    try:  # baseline (no injected header), own cache-buster
        base_resp = scoped_get(_bust(target), scope, timeout=timeout,
                               limiter=limiter, max_bytes=200_000)
    except (ScopeViolation, Exception) as e:  # noqa: BLE001
        return [Finding(NAME, "Host-header check could not fetch the target", "info",
                        f"Baseline fetch failed: {type(e).__name__}.",
                        rule_id=f"{NAME}.unreachable")]
    baseline_body = base_resp.text or ""

    findings: list[Finding] = []
    seen: set[str] = set()
    for _label, headers in build_variants().items():
        try:
            r = scoped_get(_bust(target), scope, timeout=timeout, headers=headers,
                           max_redirects=0, limiter=limiter, max_bytes=200_000)
        except (ScopeViolation, Exception):  # noqa: BLE001
            continue
        for f in analyze_reflection(baseline_body, r.status_code,
                                    r.headers.get("Location", ""), r.text or "",
                                    dict(r.headers)):
            if f.rule_id not in seen:       # one finding per rule across variants
                seen.add(f.rule_id)
                findings.append(f)

    if not findings:
        findings.append(Finding(NAME, "No host-header reflection observed", "info",
                                "The target did not reflect a spoofed host header.",
                                rule_id=f"{NAME}.no-reflection"))
    return findings
