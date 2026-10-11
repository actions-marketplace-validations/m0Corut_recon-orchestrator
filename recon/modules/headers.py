"""Security-header and cookie-flag checks. Pure-Python (requests), no Docker.

Parsing/analysis lives in `analyze()` which takes plain data (a headers dict)
so it can be unit-tested without any network access.
"""
from __future__ import annotations

import requests

from ..findings import Finding

NAME = "headers"
NEEDS_DOCKER = False

# header -> (rule slug, severity, why it matters)
EXPECTED = {
    "Strict-Transport-Security": ("missing-hsts", "medium",
        "HSTS yok: protokol düşürme / MITM riski"),
    "Content-Security-Policy": ("missing-csp", "medium",
        "CSP yok: XSS etki alanı genişler"),
    "X-Content-Type-Options": ("missing-nosniff", "low",
        "nosniff yok: MIME sniffing riski"),
    "X-Frame-Options": ("missing-xfo", "low",
        "yok: clickjacking riski (CSP frame-ancestors yoksa)"),
    "Referrer-Policy": ("missing-referrer-policy", "info",
        "yok: referrer üzerinden bilgi sızıntısı"),
    "Permissions-Policy": ("missing-permissions-policy", "info",
        "yok: tarayıcı özellikleri kısıtlanmamış"),
}


def analyze(headers: dict, status: int, url: str) -> list[Finding]:
    """Pure analysis of a response's headers. `headers` is case-insensitive-ish:
    we lowercase keys here, so pass the raw dict."""
    present = {k.lower(): v for k, v in headers.items()}
    findings: list[Finding] = []

    for header, (slug, sev, why) in EXPECTED.items():
        if header.lower() not in present:
            findings.append(Finding(
                NAME, f"Güvenlik başlığı eksik: {header}", sev, why,
                evidence=f"GET {url} -> {status}",
                recommendation=f"{header} yanıt başlığını ekle.",
                rule_id=f"{NAME}.{slug}",
            ))

    for h in ("Server", "X-Powered-By", "X-AspNet-Version"):
        if h.lower() in present:
            findings.append(Finding(
                NAME, f"Teknoloji ifşası: {h}", "info",
                f"{h}: {present[h.lower()]}",
                recommendation=f"{h} başlığını kaldır/genelleştir.",
                rule_id=f"{NAME}.tech-disclosure-{h.lower()}",
            ))

    set_cookie = present.get("set-cookie", "")
    if set_cookie:
        low = set_cookie.lower()
        missing = [flag for flag, key in
                   (("Secure", "secure"), ("HttpOnly", "httponly"),
                    ("SameSite", "samesite")) if key not in low]
        if missing:
            findings.append(Finding(
                NAME, "Cookie bayrağı eksik", "low",
                "Eksik: " + ", ".join(missing),
                evidence="Set-Cookie başlığında bayrak eksik",
                recommendation="Session cookie'lerine Secure + HttpOnly + SameSite ekle.",
                rule_id=f"{NAME}.cookie-flags",
            ))
    return findings


def run(target: str, ctx: dict) -> list[Finding]:
    try:
        r = requests.get(target, timeout=ctx.get("http_timeout", 15),
                         allow_redirects=True)
    except Exception as e:
        return [Finding(NAME, "HTTP isteği başarısız", "info",
                        f"{target} alınamadı: {e}",
                        rule_id=f"{NAME}.request-failed")]
    return analyze(dict(r.headers), r.status_code, r.url)
