"""Security-header and cookie-flag checks. Pure-Python (requests), no Docker."""
from __future__ import annotations

import requests

from ..findings import Finding

NAME = "headers"
NEEDS_DOCKER = False

# header -> (severity, why it matters)
EXPECTED = {
    "Strict-Transport-Security": ("medium", "HSTS yok: protokol düşürme / MITM riski"),
    "Content-Security-Policy": ("medium", "CSP yok: XSS etki alanı genişler"),
    "X-Content-Type-Options": ("low", "nosniff yok: MIME sniffing riski"),
    "X-Frame-Options": ("low", "yok: clickjacking riski (CSP frame-ancestors yoksa)"),
    "Referrer-Policy": ("info", "yok: referrer üzerinden bilgi sızıntısı"),
    "Permissions-Policy": ("info", "yok: tarayıcı özellikleri kısıtlanmamış"),
}


def run(target: str, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    try:
        r = requests.get(target, timeout=ctx.get("http_timeout", 15),
                         allow_redirects=True)
    except Exception as e:
        return [Finding(NAME, "HTTP isteği başarısız", "info",
                        f"{target} alınamadı: {e}")]

    present = {k.lower(): v for k, v in r.headers.items()}

    for header, (sev, why) in EXPECTED.items():
        if header.lower() not in present:
            findings.append(Finding(
                NAME, f"Güvenlik başlığı eksik: {header}", sev, why,
                evidence=f"GET {r.url} -> {r.status_code}",
                recommendation=f"{header} yanıt başlığını ekle.",
            ))

    # Server / tech disclosure
    for h in ("Server", "X-Powered-By", "X-AspNet-Version"):
        if h in r.headers:
            findings.append(Finding(
                NAME, f"Teknoloji ifşası: {h}", "info",
                f"{h}: {r.headers[h]}",
                recommendation=f"{h} başlığını kaldır/genelleştir.",
            ))

    # Cookie flags
    set_cookie = r.headers.get("Set-Cookie", "")
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
            ))
    return findings
