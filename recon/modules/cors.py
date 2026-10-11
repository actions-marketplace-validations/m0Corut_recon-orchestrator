"""CORS misconfiguration check: does the server reflect an attacker Origin?"""
from __future__ import annotations

from ..findings import Finding
from ..scope import Scope, scoped_get

NAME = "cors"
NEEDS_DOCKER = False

PROBES = [
    "https://evil.example.com",
    "null",
]


def run(target: str, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    timeout = ctx.get("http_timeout", 15)
    scope = ctx.get("scope") or Scope.allow_all()
    for origin in PROBES:
        try:
            r = scoped_get(target, scope, timeout=timeout,
                           headers={"Origin": origin})
        except Exception:
            continue
        acao = r.headers.get("Access-Control-Allow-Origin")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
        if not acao:
            continue
        if acao == origin or acao == "*":
            if acao == origin and acac == "true":
                sev, slug = "high", "reflects-origin-with-credentials"
            else:
                sev, slug = "medium", "permissive-acao"
            findings.append(Finding(
                NAME, "CORS misconfiguration", sev,
                f"Server reflects Origin '{origin}' "
                f"(ACAO={acao}, credentials={acac or 'none'}).",
                evidence=f"Origin: {origin} -> ACAO: {acao}",
                recommendation="Restrict allowed origins to an allowlist; "
                               "never combine '*' with credentials.",
                rule_id=f"{NAME}.{slug}",
                params={"origin": origin, "acao": acao},
            ))
    return findings
