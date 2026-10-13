"""Content/path discovery. Pure-Python brute force with a small built-in list.

Kept dependency-light: no ffuf required. For larger wordlists pass --wordlist
on the CLI. A baseline request establishes the "catch-all" status (e.g. an SPA
that 307-redirects everything to /login) so those are filtered out.
"""
from __future__ import annotations

import concurrent.futures as cf
import re
from urllib.parse import urljoin, urlparse

import requests

from ..findings import Finding
from ..scope import Scope, ScopeViolation, scoped_get

NAME = "content"
NEEDS_DOCKER = False

# path substring -> predicate(body_head: bytes) -> bool. A 200 whose body matches
# is a CONFIRMED leak; a 200 that does NOT match is a soft-404/SPA catch-all
# (reported as unverified, not high). Bodies are checked on the first ~4 KB only.
_ENV_RE = re.compile(rb"(?im)^[A-Z0-9_]*(SECRET|PASSWORD|TOKEN|KEY|DSN)[A-Z0-9_]*\s*=")

SENSITIVE_SIG = {
    ".git/head": lambda b: b.lstrip().startswith(b"ref:")
    or bool(re.match(rb"[0-9a-f]{40}", b.strip())),
    ".git/config": lambda b: b"[core]" in b,
    ".ds_store": lambda b: b[:8] == b"\x00\x00\x00\x01Bud1",
    ".env": lambda b: bool(_ENV_RE.search(b)),
    ".sql": lambda b: b"CREATE TABLE" in b.upper() or b"INSERT INTO" in b.upper(),
    ".zip": lambda b: b[:2] == b"PK",
    "dump": lambda b: b"CREATE TABLE" in b.upper() or b[:2] == b"PK",
    "backup": lambda b: b[:2] == b"PK" or b"CREATE TABLE" in b.upper(),
    "wp-config": lambda b: b"DB_PASSWORD" in b or b"define(" in b,
}
PANEL_SIG = {
    "phpinfo": lambda b: b"phpinfo()" in b or b"<title>PHP " in b or b"PHP Version" in b,
    "server-status": lambda b: b"Apache Server Status" in b or b"Server uptime" in b,
    "actuator": lambda b: b'"status"' in b or b'"propertySources"' in b or b'"_links"' in b,
    "swagger.json": lambda b: b'"swagger"' in b or b'"openapi"' in b,
    "openapi.json": lambda b: b'"openapi"' in b or b'"swagger"' in b,
}


def host_candidates(hostname: str) -> list[str]:
    """Pure: host-named backup guesses, e.g. example.com.zip, backup-example.zip."""
    host = (hostname or "").lower()
    label = host.split(".")[0] if host else ""
    out: list[str] = []
    for base in filter(None, (host, label)):
        out += [f"{base}.zip", f"{base}.tar.gz", f"{base}.sql"]
    out += [f"backup-{label}.zip"] if label else []
    return list(dict.fromkeys(out))


def judge_body(path: str, status: int, body_head: bytes) -> tuple[str, str]:
    """Pure: (kind, verdict). kind: sensitive|panel|path; verdict: confirmed|plausible|reject."""
    low = path.lower()
    for key, pred in SENSITIVE_SIG.items():
        if key in low:
            if status == 200 and pred(body_head):
                return "sensitive", "confirmed"
            return "sensitive", ("plausible" if status == 200 else "reject")
    for key, pred in PANEL_SIG.items():
        if key in low:
            if status == 200 and pred(body_head):
                return "panel", "confirmed"
            return "panel", ("plausible" if status == 200 else "reject")
    return "path", "generic"

BUILTIN = [
    ".env", ".git/config", ".git/HEAD", ".gitignore", "config.json",
    "package.json", "composer.json", "wp-config.php", "backup.zip",
    "backup.sql", "dump.sql", "db.sql", "admin", "administrator",
    "login", "api", "api/health", "api/status", "api/debug", "api/swagger",
    "swagger.json", "openapi.json", "graphql", "robots.txt", "sitemap.xml",
    ".well-known/security.txt", "server-status", "actuator", "actuator/health",
    "phpinfo.php", "test", "debug", "console", "metrics", ".DS_Store",
]

# Interesting if the status is one of these (not the catch-all) and not 404.
INTERESTING = {200, 201, 204, 301, 302, 401, 403, 405, 500}

# Only the first ~4 KB of any body is ever inspected (see SENSITIVE_SIG/PANEL_SIG),
# so the probe never downloads more than this. Paths in the list include backup
# archives and DB dumps (.zip/.sql/.tar.gz) that can be gigabytes on a real
# target; the cap keeps a single probe from buffering such a file into memory.
BODY_CAP = 65536
BODY_HEAD = 4096


def _baseline(target: str, scope, timeout: int, limiter) -> tuple[int, int] | None:
    """(status, content_length) for a random nonexistent path, or None if the
    target is unreachable (so the caller can avoid reporting a false 'clean')."""
    try:
        r = scoped_get(urljoin(target + "/", "zzz_nonexistent_" + "a" * 12),
                       scope, timeout=timeout, max_redirects=0, limiter=limiter,
                       max_bytes=BODY_CAP)
        return r.status_code, len(r.content)
    except (ScopeViolation, requests.RequestException):
        return None


def run(target: str, ctx: dict) -> list[Finding]:
    timeout = ctx.get("http_timeout", 15)
    words = list(ctx.get("wordlist_entries") or BUILTIN)
    words += host_candidates(urlparse(target).hostname or "")
    words = list(dict.fromkeys(words))
    base = target.rstrip("/") + "/"
    scope = ctx.get("scope") or Scope.allow_all()
    limiter = ctx.get("limiter")
    baseline = _baseline(target, scope, timeout, limiter)
    if baseline is None:
        return [Finding(NAME, "Content discovery could not reach the target", "info",
                        "The baseline request failed, so no path was probed.",
                        rule_id=f"{NAME}.unreachable", params={"target": target})]
    base_status, _ = baseline

    def probe(path: str):
        url = urljoin(base, path)
        try:
            # max_redirects=0: a 301/302 is itself a signal, don't follow it.
            # max_bytes: never buffer a whole backup/dump, only the head we judge.
            r = scoped_get(url, scope, timeout=timeout, max_redirects=0,
                           limiter=limiter, max_bytes=BODY_CAP)
        except (ScopeViolation, Exception):
            return None
        if r.status_code == base_status or r.status_code == 404:
            return None
        if r.status_code not in INTERESTING:
            return None
        return (path, r.status_code, url, r.content[:BODY_HEAD])

    findings: list[Finding] = []
    hits = []
    with cf.ThreadPoolExecutor(max_workers=ctx.get("content_threads", 10)) as ex:
        for res in ex.map(probe, words):
            if res:
                hits.append(res)

    for path, status, url, body_head in sorted(hits, key=lambda x: x[1]):
        kind, verdict = judge_body(path, status, body_head)
        if verdict == "reject":
            continue
        if verdict == "confirmed" and kind == "sensitive":
            sev, slug, label = "high", "sensitive-file", "Accessible sensitive file"
        elif verdict == "confirmed" and kind == "panel":
            sev, slug, label = "medium", "exposed-panel", "Exposed panel/endpoint"
        elif verdict == "plausible":
            sev, slug, label = "info", "unverified-path", "Path returns 200 (unverified)"
        else:
            sev, slug, label = "info", "accessible-path", "Accessible path"
        detail = (f"Returned HTTP {status} (not the catch-all {base_status})."
                  if verdict != "plausible" else
                  "HTTP 200 but no sensitive-content signature matched "
                  "(possible catch-all/soft-404).")
        findings.append(Finding(
            NAME, f"{label}: /{path}", sev, detail,
            evidence=f"{status} {url}",
            recommendation="Restrict access if this is sensitive.",
            rule_id=f"{NAME}.{slug}",
            params={"path": path, "status": status, "base": base_status},
        ))
    if not findings:
        findings.append(Finding(
            NAME, "Content discovery: clean", "info",
            f"Tried {len(words)} paths, nothing notable "
            f"(catch-all status: {base_status}).",
            rule_id=f"{NAME}.clean",
            params={"count": len(words), "base": base_status},
        ))
    return findings
