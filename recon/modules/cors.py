"""CORS misconfiguration check: does the server reflect an attacker Origin?"""
from __future__ import annotations

import requests

from ..findings import Finding

NAME = "cors"
NEEDS_DOCKER = False

PROBES = [
    "https://evil.example.com",
    "null",
]


def run(target: str, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    timeout = ctx.get("http_timeout", 15)
    for origin in PROBES:
        try:
            r = requests.get(target, headers={"Origin": origin},
                             timeout=timeout, allow_redirects=True)
        except Exception:
            continue
        acao = r.headers.get("Access-Control-Allow-Origin")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
        if not acao:
            continue
        if acao == origin or acao == "*":
            sev = "high" if (acao == origin and acac == "true") else "medium"
            findings.append(Finding(
                NAME, "CORS yanlış yapılandırması", sev,
                f"Sunucu Origin '{origin}' değerini yansıtıyor "
                f"(ACAO={acao}, credentials={acac or 'yok'}).",
                evidence=f"Origin: {origin} -> ACAO: {acao}",
                recommendation="İzin verilen origin'leri allowlist ile sınırla; "
                               "'*' + credentials birlikte kullanma.",
            ))
    return findings
