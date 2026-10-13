"""Passive extras: parse-only checks on pages already fetched. Read-only.

A grab-bag of low-cost, low-risk checks that each parse a response already
fetched (plus two tiny extra GETs for robots.txt and security.txt):
JWT hygiene (decode only), Subresource Integrity, cross-domain scripts,
session id in URL, internal/IP/path/stack-trace disclosure, mixed content,
robots and security.txt. No payloads. Pure analyzers are split from `run()`.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import re
from urllib.parse import parse_qsl, urljoin, urlparse

from ..findings import Finding
from ..scope import Scope, ScopeViolation, scoped_get
from ._pages import fetch_pages, parse_html

NAME = "passive"
NEEDS_DOCKER = False

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\b")
_PRIVATE_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_INTERNAL_HOST_RE = re.compile(r"\b[a-z0-9][a-z0-9\-]{1,62}\.(?:local|internal|corp|lan)\b", re.I)
_ABS_PATH_RE = re.compile(r"(?:/var/www/|/home/[a-z0-9_.-]+/|/usr/local/|[A-Z]:\\inetpub\\)")
_STACK_RE = re.compile(
    r"(Traceback \(most recent call last\)|\bat [a-z0-9_.]+\([A-Za-z0-9_]+\.java:\d+\)"
    r"|Fatal error:|Warning: [a-z_]+\(\)|Werkzeug Debugger|<b>Stack trace:</b>)")
_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
_SENSITIVE_COMMENT = re.compile(
    r"\b(todo|fixme|hack|password|passwd|secret|debug|api[_-]?key)\b", re.I)
SESSION_PARAMS = {"phpsessid", "jsessionid", "sid", "sessionid", "token", "jwt", "auth"}
SENSITIVE_CLAIMS = {"email", "role", "roles", "is_admin", "admin", "password",
                    "ssn", "phone", "user", "username"}


def _b64url(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _mask_token(tok: str) -> str:
    return f"{tok[:8]}...{tok[-4:]}" if len(tok) > 16 else tok[:6] + "..."


def analyze_jwt(token: str, where: str, in_url: bool = False) -> list[Finding]:
    """Pure: decode a JWT (header+payload only) and flag hygiene issues."""
    parts = token.split(".")
    if len(parts) != 3:
        return []
    try:
        header = json.loads(_b64url(parts[0]))
        payload = json.loads(_b64url(parts[1]))
    except (ValueError, json.JSONDecodeError, TypeError):
        return []
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return []
    out: list[Finding] = []
    ev = f"{where}: {_mask_token(token)}"

    def add(slug, sev, detail):
        out.append(Finding(NAME, f"JWT: {slug}", sev, detail, evidence=ev,
                           rule_id=f"{NAME}.{slug}", msg_key=f"{NAME}.{slug}",
                           params={"where": where}))

    if str(header.get("alg", "")).lower() == "none":
        add("jwt-alg-none", "high", "JWT uses alg=none (signature not verified).")
    if "exp" not in payload:
        add("jwt-no-exp", "medium", "JWT has no exp claim (does not expire).")
    elif isinstance(payload.get("exp"), (int, float)) \
            and isinstance(payload.get("iat"), (int, float)):
        if payload["exp"] - payload["iat"] > 2592000:
            add("jwt-long-lived", "low", "JWT lifetime exceeds 30 days.")
    if any(k.lower() in SENSITIVE_CLAIMS for k in payload):
        add("jwt-sensitive-claims", "low",
            "JWT payload carries identity/role claims (readable by anyone).")
    if in_url:
        add("jwt-in-url", "medium", "A JWT appears in a URL (logs/referrer leakage).")
    return out


def analyze_sri(scripts, links, host: str, page_url: str) -> list[Finding]:
    out: list[Finding] = []
    for tag in list(scripts) + [li for li in links
                                if li.attrs.get("rel", "").lower() == "stylesheet"]:
        src = tag.attrs.get("src") or tag.attrs.get("href") or ""
        if not src.startswith(("http://", "https://")):
            continue
        if (urlparse(src).hostname or "").lower() == host:
            continue
        if "integrity" not in tag.attrs:
            out.append(Finding(
                NAME, f"Third-party resource without SRI: {src}", "low",
                "A cross-origin script/stylesheet has no integrity attribute "
                "(supply-chain risk).",
                evidence=f"{page_url}: {src}", recommendation="Add an SRI integrity hash.",
                rule_id=f"{NAME}.sri-missing", msg_key=f"{NAME}.sri-missing",
                params={"src": src}))
    return out


def analyze_cross_domain_js(scripts, host: str, page_url: str) -> list[Finding]:
    hosts = sorted({(urlparse(t.attrs.get("src", "")).hostname or "").lower()
                    for t in scripts
                    if t.attrs.get("src", "").startswith(("http://", "https://"))}
                   - {host, ""})
    return [Finding(
        NAME, f"Third-party script host: {h}", "info",
        "Script loaded from a third-party host (trust/supply-chain surface).",
        evidence=f"{page_url}: {h}", rule_id=f"{NAME}.cross-domain-script",
        msg_key=f"{NAME}.cross-domain-script", params={"host": h}) for h in hosts]


def analyze_session_in_url(urls) -> list[Finding]:
    out: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for url in urls:
        p = urlparse(url)
        hit = None
        for k, v in parse_qsl(p.query):
            if k.lower() in SESSION_PARAMS and v:
                hit = k
                break
        if not hit and ";jsessionid=" in url.lower():
            hit = "jsessionid"
        if hit and (p.path, hit) not in seen:
            seen.add((p.path, hit))
            out.append(Finding(
                NAME, f"Session id in URL: {hit}", "medium",
                "A session/token identifier is passed in the URL (leaks via logs, "
                "referrer, history).",
                evidence=f"{p.path}?{hit}=...", rule_id=f"{NAME}.session-id-in-url",
                params={"param": hit}))
    return out


def _is_private_ip(s: str) -> bool:
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def analyze_internal_disclosure(body: str, page_url: str) -> list[Finding]:
    out: list[Finding] = []

    def add(slug, sev, detail, ev):
        out.append(Finding(NAME, f"Disclosure: {slug}", sev, detail,
                           evidence=f"{page_url}: {ev}", rule_id=f"{NAME}.{slug}",
                           msg_key=f"{NAME}.{slug}", params={}))

    priv = sorted({m for m in _PRIVATE_IP_RE.findall(body) if _is_private_ip(m)})
    if priv:
        add("private-ip-disclosure", "low",
            "Private/internal IP address exposed in the response.", priv[0])
    host_m = _INTERNAL_HOST_RE.search(body)
    if host_m:
        add("internal-hostname-disclosure", "low",
            "Internal hostname (.local/.internal/.corp/.lan) exposed.", host_m.group(0))
    path_m = _ABS_PATH_RE.search(body)
    if path_m:
        add("absolute-path-disclosure", "low",
            "Server filesystem path exposed.", path_m.group(0))
    if _STACK_RE.search(body):
        add("stack-trace", "medium",
            "A framework stack trace / debug error is exposed.", "stack trace marker")
    # finditer (not findall) so we stop at the first sensitive comment without
    # materialising every comment on a large body into a list.
    for cm in _COMMENT_RE.finditer(body):
        if _SENSITIVE_COMMENT.search(cm.group(1)):
            add("html-comment-sensitive", "info",
                "HTML comment mentions sensitive keywords.", cm.group(1).strip()[:60])
            break
    return out


def analyze_mixed_content(scripts, links, page_scheme: str, page_url: str) -> list[Finding]:
    if page_scheme != "https":
        return []
    out: list[Finding] = []
    for tag in scripts:
        if tag.attrs.get("src", "").startswith("http://"):
            out.append(Finding(
                NAME, "Active mixed content (http script on https page)", "medium",
                "An http:// script is loaded on an https page (MITM/injection).",
                evidence=f"{page_url}: {tag.attrs['src']}",
                rule_id=f"{NAME}.mixed-content-active", msg_key=f"{NAME}.mixed-content-active",
                params={}))
            break
    for li in links:
        if li.attrs.get("rel", "").lower() == "stylesheet" \
                and li.attrs.get("href", "").startswith("http://"):
            out.append(Finding(
                NAME, "Passive mixed content (http stylesheet on https page)", "info",
                "An http:// stylesheet is loaded on an https page.",
                evidence=f"{page_url}: {li.attrs['href']}",
                rule_id=f"{NAME}.mixed-content-passive", params={}))
            break
    return out


def analyze_robots(status: int, body: str) -> list[Finding]:
    if status != 200 or not body.strip():
        return [Finding(NAME, "robots.txt missing", "info",
                        "No robots.txt served.", rule_id=f"{NAME}.robots-missing")]
    interesting = [ln.split(":", 1)[1].strip() for ln in body.splitlines()
                   if ln.lower().startswith("disallow:")
                   and any(w in ln.lower() for w in
                           ("admin", "backup", "api", "private", "secret", "config",
                            "internal", "dashboard"))]
    if interesting:
        return [Finding(
            NAME, "robots.txt reveals sensitive paths", "info",
            "robots.txt Disallow entries point at sensitive paths (not fetched).",
            evidence="; ".join(interesting[:8]), rule_id=f"{NAME}.robots-reveals-paths",
            params={"count": len(interesting)})]
    return []


def analyze_security_txt(status: int, body: str) -> list[Finding]:
    if status != 200 or not body.strip():
        return [Finding(NAME, "security.txt missing", "info",
                        "No /.well-known/security.txt (RFC 9116).",
                        rule_id=f"{NAME}.security-txt-missing")]
    out: list[Finding] = []
    low = body.lower()
    if "contact:" not in low:
        out.append(Finding(NAME, "security.txt has no Contact", "low",
                           "security.txt is present but has no Contact field.",
                           rule_id=f"{NAME}.security-txt-no-contact"))
    m = re.search(r"(?im)^expires:\s*(\S+)", body)
    if m:
        from datetime import datetime, timezone
        try:
            exp = datetime.fromisoformat(m.group(1).replace("Z", "+00:00"))
            if exp.tzinfo is None:                 # date-only / naive datetime
                exp = exp.replace(tzinfo=timezone.utc)
            if exp < datetime.now(timezone.utc):
                out.append(Finding(NAME, "security.txt expired", "low",
                                   f"security.txt Expires is in the past ({m.group(1)}).",
                                   rule_id=f"{NAME}.security-txt-expired"))
        except (ValueError, TypeError):            # unparseable / non-ISO date formats
            pass
    return out


def run(target: str, ctx) -> list[Finding]:
    scope = ctx.get("scope") or Scope.allow_all()
    limiter = ctx.get("limiter")
    timeout = ctx.get("http_timeout", 15)
    host = (urlparse(target).hostname or "").lower()
    base = target.rstrip("/") + "/"

    findings: list[Finding] = []
    jwt_seen: set[str] = set()
    seen_keys: set[tuple] = set()

    def _add(new: list[Finding]) -> None:
        # Collapse the same issue repeated across many similar pages (e.g. a CDN
        # without SRI on every page) to one finding per (rule, identifying param)
        # so the report volume stays reasonable; the first page's URL is kept as
        # evidence for run diffing.
        for f in new:
            key = (f.rule_id, *sorted((k, str(v)) for k, v in (f.params or {}).items()))
            if key in seen_keys:
                continue
            seen_keys.add(key)
            findings.append(f)

    for url, status, headers, body in fetch_pages(target, ctx):
        if status >= 400 or not body:
            continue
        page = parse_html(body)
        scheme = urlparse(url).scheme or "https"
        _add(analyze_sri(page.scripts, page.links, host, url))
        _add(analyze_cross_domain_js(page.scripts, host, url))
        _add(analyze_mixed_content(page.scripts, page.links, scheme, url))
        _add(analyze_internal_disclosure(body, url))
        hdr_blob = " ".join(f"{k}: {v}" for k, v in headers.items())
        for tok in set(_JWT_RE.findall(body + " " + hdr_blob)):
            if tok not in jwt_seen:
                jwt_seen.add(tok)
                _add(analyze_jwt(tok, url))

    url_pool = [target] + list(ctx.get("crawled_urls") or [])
    findings += analyze_session_in_url(url_pool)
    for u in url_pool:
        for tok in _JWT_RE.findall(u):
            if tok not in jwt_seen:
                jwt_seen.add(tok)
                _add(analyze_jwt(tok, u, in_url=True))

    for path, analyzer in (("robots.txt", analyze_robots),
                           (".well-known/security.txt", analyze_security_txt)):
        try:
            r = scoped_get(urljoin(base, path), scope, timeout=timeout,
                           limiter=limiter, max_bytes=65536)
            findings += analyzer(r.status_code, r.text or "")
        except (ScopeViolation, Exception):  # noqa: BLE001
            continue

    if not findings:
        findings.append(Finding(NAME, "passive: nothing notable", "info",
                                "No passive issues found on the fetched pages.",
                                rule_id=f"{NAME}.clean"))
    return findings
