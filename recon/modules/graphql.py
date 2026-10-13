"""GraphQL exposure checks (read-only, one tiny probe per endpoint).

Finds GraphQL endpoints and reports production-unsafe defaults: introspection
enabled (full schema leak), an exposed GraphiQL/Playground IDE, verbose debug
error payloads, and queries accepted over GET (CSRF-relevant). The only query
ever sent is a fixed `{__schema{queryType{name}}}`; no field enumeration, no
mutations, no batching. Pure analysis is split from `run()`.
"""
from __future__ import annotations

import json
from urllib.parse import quote, urljoin, urlparse

from ..findings import Finding
from ..scope import Scope, ScopeViolation, scoped_get, scoped_post

NAME = "graphql"
NEEDS_DOCKER = False

PROBE = {"query": "{__schema{queryType{name}}}"}
COMMON_PATHS = ("graphql", "api/graphql", "v1/graphql", "query", "graphql/console")
IDE_PATHS = ("graphiql", "playground", "altair", "voyager")
MAX_ENDPOINTS = 8
# Never hand a pathologically large body to json.loads (a probe may hit a big
# non-JSON file); the real GraphQL probe answer is tiny.
MAX_JSON_BYTES = 2_000_000


def candidate_endpoints(target: str, crawled_urls=None) -> list[str]:
    """Pure: likely GraphQL endpoint URLs (common paths + crawled graphql paths)."""
    base = target.rstrip("/") + "/"
    out = [urljoin(base, p) for p in COMMON_PATHS]
    host = (urlparse(target).hostname or "").lower()
    for u in (crawled_urls or []):
        if "graphql" in u.lower() and (urlparse(u).hostname or "").lower() == host \
                and u not in out:
            out.append(u)
    return out[:MAX_ENDPOINTS]


def _json(body: str):
    if not body or len(body) > MAX_JSON_BYTES:
        return None
    try:
        return json.loads(body)
    except (json.JSONDecodeError, ValueError, RecursionError):
        return None


def analyze_introspection(url: str, status: int, body: str) -> Finding | None:
    data = _json(body)
    if not isinstance(data, dict):
        return None
    inner = data.get("data")
    schema = inner.get("__schema") if isinstance(inner, dict) else None
    if isinstance(schema, dict) and schema.get("queryType"):
        return Finding(
            NAME, f"GraphQL introspection enabled: {url}", "medium",
            "Introspection returns the full schema; disable it in production.",
            evidence=f"POST {url} {PROBE['query']} -> __schema",
            recommendation="Disable introspection in production.",
            rule_id=f"{NAME}.introspection-enabled", msg_key=f"{NAME}.introspection-enabled",
            params={"url": url})
    # endpoint exists (GraphQL-shaped response) but introspection is off
    if "data" in data or "errors" in data:
        return Finding(
            NAME, f"GraphQL endpoint found: {url}", "info",
            "A GraphQL endpoint responds (introspection appears disabled).",
            evidence=f"POST {url} -> GraphQL JSON",
            rule_id=f"{NAME}.endpoint-found", params={"url": url})
    return None


def analyze_graphql_errors(url: str, body: str) -> Finding | None:
    data = _json(body)
    if not isinstance(data, dict):
        return None
    errors = data.get("errors")
    if not isinstance(errors, list):
        return None
    # Debug mode = a stack trace inside extensions (exception) of an error, not
    # merely the word "exception" in a message (that would be a false positive).
    for err in errors:
        if not isinstance(err, dict):
            continue
        ext = err.get("extensions")
        if not isinstance(ext, dict):
            continue
        stack = ext.get("stacktrace") or ext.get("stackTrace")
        exc = ext.get("exception")
        if isinstance(exc, dict):
            stack = stack or exc.get("stacktrace") or exc.get("stackTrace")
        if stack:
            return Finding(
                NAME, f"GraphQL verbose errors: {url}", "medium",
                "Error payload includes stack traces / exception detail (debug mode).",
                evidence=f"POST {url} -> errors with stacktrace",
                recommendation="Disable debug error output in production.",
                rule_id=f"{NAME}.debug-errors", params={"url": url})
    return None


def analyze_panel(url: str, status: int, body: str) -> Finding | None:
    # Detect the IDE by a body marker, not the status code: some setups serve the
    # IDE page under a non-200 status, and a bare 200 proves nothing on its own.
    if body and any(m in body for m in
                    ("GraphiQL", "GraphQL Playground", "Altair", "Voyager",
                     "graphql-playground")):
        return Finding(
            NAME, f"GraphQL IDE exposed: {url}", "low",
            "A GraphiQL/Playground IDE is served; it eases schema discovery.",
            evidence=f"GET {url} -> IDE page",
            recommendation="Do not expose the GraphQL IDE in production.",
            rule_id=f"{NAME}.ide-exposed", params={"url": url})
    return None


def run(target: str, ctx) -> list[Finding]:
    scope = ctx.get("scope") or Scope.allow_all()
    limiter = ctx.get("limiter")
    timeout = ctx.get("http_timeout", 15)
    base = target.rstrip("/") + "/"

    findings: list[Finding] = []
    found_endpoint: str | None = None
    for url in candidate_endpoints(target, ctx.get("crawled_urls")):
        try:
            r = scoped_post(url, scope, json=PROBE, timeout=timeout, limiter=limiter)
        except (ScopeViolation, Exception):  # noqa: BLE001
            continue
        body = r.text or ""
        intro = analyze_introspection(url, r.status_code, body)
        if intro:
            findings.append(intro)
            found_endpoint = found_endpoint or url
        err = analyze_graphql_errors(url, body)
        if err:
            findings.append(err)

    for ide in IDE_PATHS:
        url = urljoin(base, ide)
        try:
            r = scoped_get(url, scope, timeout=timeout, limiter=limiter, max_bytes=65536)
        except (ScopeViolation, Exception):  # noqa: BLE001
            continue
        panel = analyze_panel(url, r.status_code, r.text or "")
        if panel:
            findings.append(panel)

    if found_endpoint:  # does the same fixed probe answer over GET? (CSRF-relevant)
        try:
            gurl = found_endpoint + ("&" if "?" in found_endpoint else "?") \
                + "query=" + quote(PROBE["query"])
            r = scoped_get(gurl, scope, timeout=timeout, limiter=limiter, max_bytes=65536)
            d = _json(r.text or "")
            if isinstance(d, dict) and ("data" in d or "errors" in d):
                findings.append(Finding(
                    NAME, f"GraphQL accepts queries over GET: {found_endpoint}", "low",
                    "GET queries are CSRF-reachable and may be cached.",
                    evidence=f"GET {found_endpoint}?query=... -> GraphQL JSON",
                    recommendation="Accept GraphQL only over POST.",
                    rule_id=f"{NAME}.get-query-allowed", params={"url": found_endpoint}))
        except (ScopeViolation, Exception):  # noqa: BLE001
            pass

    if not findings:
        findings.append(Finding(NAME, "No GraphQL endpoint found", "info",
                                "No GraphQL endpoint responded on the common paths.",
                                rule_id=f"{NAME}.none-found"))
    return findings
