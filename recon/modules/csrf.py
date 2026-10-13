"""CSRF protection detection (passive). No payloads, read-only GET.

For each state-changing HTML form the site serves, check whether it carries an
anti-CSRF token (a hidden token field or a page-level `<meta name=csrf-token>`)
or is protected by a `SameSite=Lax/Strict` session cookie. Forms with neither are
reported. Login forms are reported separately (login-CSRF has a different risk
model). Pure analysis is split out so it unit-tests without the network.

JSON APIs / SPAs that submit via `fetch` have no HTML forms, so they are out of
this module's reach by design (reported as `csrf.no-forms-found`).
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ..findings import Finding
from ..scope import Scope, ScopeViolation, scoped_get
from ._pages import fetch_pages, parse_html

NAME = "csrf"
NEEDS_DOCKER = False

TOKEN_HINTS = ("csrf", "xsrf", "_token", "authenticity_token",
               "verificationtoken", "nonce", "_wpnonce", "anticsrf")
WRITE_METHODS = {"post", "put", "patch", "delete"}
SEARCH_NAMES = {"q", "s", "query", "search", "keyword", "kw"}
_META_TOKEN = re.compile(
    r'<meta[^>]+name=["\']?(?:csrf-token|csrf_token|_token)["\']?', re.I)


def _form_host(action: str, target_host: str) -> str:
    action = (action or "").strip()
    # Protocol-relative //host/path targets `host`, NOT the current host.
    # It starts with "/", so it must be handled before the leading-"/" check
    # below (otherwise an off-host //evil.com action would look same-host).
    if action.startswith("//"):
        return (urlparse(action).hostname or target_host).lower()
    if not action or action.startswith(("/", "?", "#")) or ":" not in action:
        return target_host
    return (urlparse(action).hostname or target_host).lower()


def classify_form(form, target_host: str) -> str:
    """Pure: 'state-changing' | 'login' | 'search' | 'ignored'."""
    if _form_host(form.action, target_host) != target_host:
        return "ignored"
    method = (form.method or "get").lower()
    types = {t.lower() for _, t in form.inputs}
    if "password" in types:
        return "login"
    if method in WRITE_METHODS:
        return "state-changing"
    # GET form: a search box is not a CSRF concern
    named = [n for n, _ in form.inputs if n]
    if any(n.lower() in SEARCH_NAMES for n in named):
        return "search"
    return "ignored"


def _has_token(form, has_meta_token: bool) -> bool:
    if has_meta_token:
        return True
    for name, _ in form.inputs:
        low = name.lower()
        if any(h in low for h in TOKEN_HINTS):
            return True
    return False


def analyze_forms(url: str, forms, has_meta_token: bool, samesite_protected: bool,
                  target_host: str) -> list[Finding]:
    """Pure: findings for the forms on one page."""
    out: list[Finding] = []
    for form in forms:
        kind = classify_form(form, target_host)
        ev = f"{url} form action={form.action or '(self)'}"
        if kind == "state-changing" and not _has_token(form, has_meta_token):
            if samesite_protected:
                out.append(Finding(
                    NAME, f"State-changing form without CSRF token: {form.action or '(self)'}",
                    "low",
                    "No anti-CSRF token, but a SameSite session cookie gives "
                    "partial protection. Add a token for defence in depth.",
                    evidence=ev, recommendation="Add a per-request anti-CSRF token.",
                    rule_id=f"{NAME}.form-without-token-samesite-only"))
            else:
                out.append(Finding(
                    NAME, f"State-changing form without CSRF protection: {form.action or '(self)'}",
                    "medium",
                    "A POST/PUT/PATCH/DELETE form has no anti-CSRF token and no "
                    "SameSite session cookie; it may be forgeable cross-site.",
                    evidence=ev, recommendation="Add a per-request anti-CSRF token "
                    "and set SameSite on the session cookie.",
                    rule_id=f"{NAME}.form-without-token"))
        elif kind == "login" and not _has_token(form, has_meta_token):
            out.append(Finding(
                NAME, f"Login form without CSRF token: {form.action or '(self)'}", "info",
                "Login form has no anti-CSRF token (login-CSRF risk).",
                evidence=ev, recommendation="Add an anti-CSRF token to the login form.",
                rule_id=f"{NAME}.login-form-without-token"))
    return out


def _session_is_samesite(set_cookie_values: list[str]) -> bool:
    from .headers import _is_session_cookie, _parse_cookie
    for raw in set_cookie_values:
        name, attrs = _parse_cookie(raw)
        if _is_session_cookie(name) and attrs.get("samesite", "").lower() in ("lax", "strict"):
            return True
    return False


def run(target: str, ctx) -> list[Finding]:
    from .headers import _set_cookie_list
    scope = ctx.get("scope") or Scope.allow_all()
    limiter = ctx.get("limiter")
    timeout = ctx.get("http_timeout", 15)
    target_host = (urlparse(target).hostname or "").lower()

    # one fetch of the target to read its session-cookie SameSite posture
    samesite_protected = False
    try:
        r = scoped_get(target, scope, timeout=timeout, limiter=limiter)
        samesite_protected = _session_is_samesite(_set_cookie_list(r))
    except (ScopeViolation, Exception):  # noqa: BLE001
        pass

    findings: list[Finding] = []
    any_form = False
    for url, status, _headers, body in fetch_pages(target, ctx):
        if status != 200 or not body:
            continue
        page = parse_html(body)
        if page.forms:
            any_form = True
        has_meta = bool(_META_TOKEN.search(body))
        findings += analyze_forms(url, page.forms, has_meta, samesite_protected,
                                  target_host)

    if not any_form:
        findings.append(Finding(
            NAME, "No HTML forms found", "info",
            "No HTML forms to assess (a JSON API / SPA submits via fetch, which "
            "this passive check does not cover).",
            rule_id=f"{NAME}.no-forms-found"))
    return findings
