"""OpenAPI/Swagger-driven endpoint coverage.

Turns an API's own spec into a precise, low-noise check list. Discovers the spec
at common paths (or takes --spec), parses OpenAPI 3 / Swagger 2, and for each
GET/HEAD operation with no required path parameters, requests it WITHOUT
credentials. A 200 on an operation the spec marks as secured is an access-control
gap. Never issues POST/PUT/DELETE — read-only by design.
"""
from __future__ import annotations

import json
from urllib.parse import urljoin

from ..findings import Finding
from ..scope import Scope, ScopeViolation, scoped_get

NAME = "openapi"
NEEDS_DOCKER = False

COMMON_SPEC_PATHS = [
    "openapi.json", "swagger.json", "api-docs", "v3/api-docs",
    "api/openapi.json", "api/swagger.json", "swagger/v1/swagger.json",
]


def extract_operations(spec: dict) -> list[dict]:
    """Pure: return GET/HEAD operations with no required path params.

    Each op: {path, method, secured(bool)}.
    """
    ops: list[dict] = []
    if not isinstance(spec, dict):
        return ops
    global_sec = spec.get("security")
    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        return ops
    for path, item in paths.items():
        if "{" in path:   # required path params we cannot safely fill
            continue
        if not isinstance(item, dict):
            continue
        for method in ("get", "head"):
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            if "security" in op:
                effective = op["security"]
            else:
                effective = global_sec
            secured = bool(effective)
            ops.append({"path": path, "method": method, "secured": secured})
    return ops


def analyze_response(path: str, secured: bool, status: int) -> list[Finding]:
    """Pure: classify an unauthenticated response to a spec operation."""
    if secured and status == 200:
        return [Finding(
            NAME, f"Secured endpoint reachable unauthenticated: {path}", "high",
            "Spec marks this operation as secured, but it returned 200 without "
            "credentials.",
            evidence=f"GET {path} -> {status} (spec: secured)",
            recommendation="Enforce the declared security on this endpoint.",
            rule_id=f"{NAME}.missing-auth-enforcement",
        )]
    if not secured and status == 200:
        return [Finding(
            NAME, f"Public endpoint: {path}", "info",
            "Operation has no security requirement and is reachable.",
            evidence=f"GET {path} -> {status}",
            rule_id=f"{NAME}.public-endpoint",
        )]
    return []


def _load_spec(target: str, ctx: dict, scope, limiter, timeout):
    spec_url = ctx.get("spec")
    candidates = [spec_url] if spec_url else \
        [urljoin(target.rstrip("/") + "/", p) for p in COMMON_SPEC_PATHS]
    for url in candidates:
        if not url:
            continue
        try:
            r = scoped_get(url, scope, timeout=timeout, limiter=limiter)
        except (ScopeViolation, Exception):
            continue
        if r.status_code != 200:
            continue
        try:
            return url, r.json()
        except (json.JSONDecodeError, ValueError):
            try:
                import yaml
                return url, yaml.safe_load(r.text)
            except Exception:
                continue
    return None, None


def run(target: str, ctx: dict) -> list[Finding]:
    scope = ctx.get("scope") or Scope.allow_all()
    limiter = ctx.get("limiter")
    timeout = ctx.get("http_timeout", 15)

    spec_url, spec = _load_spec(target, ctx, scope, limiter, timeout)
    if not spec:
        return [Finding(NAME, "No API spec found", "info",
                        "No OpenAPI/Swagger spec at --spec or common paths.",
                        rule_id=f"{NAME}.no-spec")]

    findings: list[Finding] = [Finding(
        NAME, "API spec reachable", "info",
        "An OpenAPI/Swagger spec is publicly reachable.",
        evidence=spec_url, rule_id=f"{NAME}.spec-exposed")]

    for op in extract_operations(spec):
        url = urljoin(target.rstrip("/") + "/", op["path"].lstrip("/"))
        try:
            r = scoped_get(url, scope, timeout=timeout, limiter=limiter)
        except (ScopeViolation, Exception):
            continue
        findings += analyze_response(op["path"], op["secured"], r.status_code)
    return findings
