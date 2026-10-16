"""Authenticated, READ-ONLY access-control checks.

Deliberately narrow and non-destructive: GET/HEAD only, never submits forms,
never writes the credential into any report (evidence redacts header values).
The user supplies a session header (preferably via an env var, not shell history)
and a list of pages known to require login.

Checks:
  - authenticated pages set Cache-Control: no-store/private
  - each protected page fetched WITHOUT the credential: a 200 with a similar body
    length is an access-control gap (the page is reachable unauthenticated)
Credentials are provided through ScanContext.extra:
  auth_header      e.g. "Cookie: session=..."  (or any header line)
  auth_pages       list of paths known to require login
"""
from __future__ import annotations

from urllib.parse import urljoin

import requests

from ..findings import Finding
from ..scope import Scope, ScopeViolation, scoped_get

NAME = "authz"
NEEDS_DOCKER = False


def _parse_header(header_line: str) -> dict[str, str]:
    if not header_line or ":" not in header_line:
        return {}
    name, _, value = header_line.partition(":")
    return {name.strip(): value.strip()}


def analyze_pair(path: str, auth_status: int, auth_len: int,
                 anon_status: int, anon_len: int) -> list[Finding]:
    """Pure comparison of an authenticated vs unauthenticated fetch of a page."""
    findings: list[Finding] = []
    # Access-control gap: protected page returns 200 unauthenticated with a
    # body of similar size (within 10%) to the authenticated one.
    if anon_status == 200 and auth_status == 200 and auth_len > 0:
        ratio = anon_len / auth_len
        if 0.9 <= ratio <= 1.1:
            findings.append(Finding(
                NAME, f"Protected page reachable unauthenticated: {path}", "high",
                "Page returns 200 with a similar body WITHOUT credentials; "
                "access control may be missing.",
                evidence=f"{path}: auth={auth_status}/{auth_len}B "
                         f"anon={anon_status}/{anon_len}B",
                recommendation="Enforce authentication/authorization on this route.",
                rule_id=f"{NAME}.missing-access-control",
            ))
    return findings


def run(target: str, ctx: dict) -> list[Finding]:
    auth_header = ctx.get("auth_header")
    pages = ctx.get("auth_pages") or []
    if not auth_header:
        return [Finding(NAME, "No credentials provided", "info",
                        "authz module needs --auth-header / --auth-header-env and "
                        "--auth-page to run.",
                        rule_id=f"{NAME}.no-credentials")]
    if not pages:
        return [Finding(NAME, "No authenticated pages listed", "info",
                        "Provide --auth-page paths known to require login.",
                        rule_id=f"{NAME}.no-pages")]

    scope = ctx.get("scope") or Scope.allow_all()
    limiter = ctx.get("limiter")
    timeout = ctx.get("http_timeout", 15)
    headers = _parse_header(auth_header)
    base = target.rstrip("/") + "/"

    findings: list[Finding] = []
    skipped = 0
    cache_check_done = False
    for page in pages:
        url = urljoin(base, page.lstrip("/"))
        try:
            ra = scoped_get(url, scope, timeout=timeout, auth_headers=headers,
                            limiter=limiter)
            rn = scoped_get(url, scope, timeout=timeout, limiter=limiter)
        except (ScopeViolation, requests.RequestException) as e:
            # A skipped page must not read as "protected": report it.
            skipped += 1
            reason = f"out of scope ({e})" if isinstance(e, ScopeViolation) \
                else type(e).__name__
            findings.append(Finding(
                NAME, f"Page not checked: {page}", "info",
                f"The page could not be fetched, so its access control was not "
                f"verified: {reason}.",
                evidence=f"{page}: {reason}",
                recommendation="Check the path and that the target is reachable, "
                               "then re-run.",
                rule_id=f"{NAME}.page-not-checked",
                params={"page": page, "reason": reason},
            ))
            continue
        findings += analyze_pair(page, ra.status_code, len(ra.content),
                                 rn.status_code, len(rn.content))
        # authenticated pages should not be cached
        if ra.status_code == 200 and not cache_check_done:
            cc = ra.headers.get("Cache-Control", "").lower()
            if "no-store" not in cc and "private" not in cc:
                findings.append(Finding(
                    NAME, f"Authenticated page is cacheable: {page}", "low",
                    "Authenticated response lacks Cache-Control: no-store/private.",
                    evidence=f"Cache-Control: {ra.headers.get('Cache-Control', '-')}",
                    recommendation="Set Cache-Control: no-store on authenticated pages.",
                    rule_id=f"{NAME}.cacheable-auth-page",
                ))
            cache_check_done = True

    if not findings and not skipped:
        findings.append(Finding(
            NAME, "authz: no access-control gaps found", "info",
            "Protected pages required credentials as expected.",
            rule_id=f"{NAME}.clean",
        ))
    return findings
