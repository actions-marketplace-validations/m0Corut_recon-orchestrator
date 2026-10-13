"""CORS misconfiguration check: does the server reflect an attacker Origin?

Pure `analyze_cors()` classifies one (origin, ACAO, ACAC) triple so it is unit-
tested without the network; `run()` sends the probes.
"""
from __future__ import annotations

import requests

from ..findings import Finding
from ..scope import Scope, ScopeViolation, scoped_get

NAME = "cors"
NEEDS_DOCKER = False

PROBES = [
    "https://evil.example.com",
    "null",
]


def analyze_cors(origin: str, acao: str | None, acac: str) -> Finding | None:
    """Pure: classify one CORS response. acac is the lowercased ACAC header."""
    if not acao:
        return None
    if acao != origin and acao != "*":
        return None
    if acao == origin and acac == "true":
        sev, slug = "high", "reflects-origin-with-credentials"
    else:
        sev, slug = "medium", "permissive-acao"
    return Finding(
        NAME, "CORS misconfiguration", sev,
        f"Server reflects Origin '{origin}' (ACAO={acao}, credentials={acac or 'none'}).",
        evidence=f"Origin: {origin} -> ACAO: {acao}",
        recommendation="Restrict allowed origins to an allowlist; never combine "
                       "'*' with credentials.",
        rule_id=f"{NAME}.{slug}", params={"origin": origin, "acao": acao})


def run(target: str, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    timeout = ctx.get("http_timeout", 15)
    scope = ctx.get("scope") or Scope.allow_all()
    limiter = ctx.get("limiter")
    for origin in PROBES:
        try:
            r = scoped_get(target, scope, timeout=timeout,
                           headers={"Origin": origin}, limiter=limiter)
        except (ScopeViolation, requests.RequestException):
            continue
        f = analyze_cors(origin, r.headers.get("Access-Control-Allow-Origin"),
                         r.headers.get("Access-Control-Allow-Credentials", "").lower())
        if f:
            findings.append(f)
    if not findings:
        findings.append(Finding(
            NAME, "CORS: no origin reflection", "info",
            "The server did not reflect an attacker-supplied Origin.",
            rule_id=f"{NAME}.clean"))
    return findings
