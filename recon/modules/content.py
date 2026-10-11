"""Content/path discovery. Pure-Python brute force with a small built-in list.

Kept dependency-light: no ffuf required. For larger wordlists pass --wordlist
on the CLI. A baseline request establishes the "catch-all" status (e.g. an SPA
that 307-redirects everything to /login) so those are filtered out.
"""
from __future__ import annotations

import concurrent.futures as cf
from urllib.parse import urljoin

import requests

from ..findings import Finding

NAME = "content"
NEEDS_DOCKER = False

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


def _baseline(target: str, timeout: int) -> tuple[int, int]:
    """Return (status, content_length) for a random nonexistent path."""
    try:
        r = requests.get(urljoin(target + "/", "zzz_nonexistent_" + "a" * 12),
                         timeout=timeout, allow_redirects=False)
        return r.status_code, len(r.content)
    except Exception:
        return 404, 0


def run(target: str, ctx: dict) -> list[Finding]:
    timeout = ctx.get("http_timeout", 15)
    words = ctx.get("wordlist_entries") or BUILTIN
    base = target.rstrip("/") + "/"
    base_status, _ = _baseline(target, timeout)

    def probe(path: str):
        url = urljoin(base, path)
        try:
            r = requests.get(url, timeout=timeout, allow_redirects=False)
        except Exception:
            return None
        if r.status_code == base_status or r.status_code == 404:
            return None
        if r.status_code not in INTERESTING:
            return None
        return (path, r.status_code, url)

    findings: list[Finding] = []
    hits = []
    with cf.ThreadPoolExecutor(max_workers=ctx.get("content_threads", 10)) as ex:
        for res in ex.map(probe, words):
            if res:
                hits.append(res)

    for path, status, url in sorted(hits, key=lambda x: x[1]):
        # Heuristic severity for obviously sensitive paths
        sev = "info"
        low = path.lower()
        if any(s in low for s in (".env", ".git", ".sql", "wp-config",
                                   "backup", "dump", ".ds_store")) and status == 200:
            sev = "high"
        elif status in (401, 403):
            sev = "info"
        findings.append(Finding(
            NAME, f"Erişilebilir yol: /{path}", sev,
            f"HTTP {status} döndü (catch-all {base_status} değil).",
            evidence=f"{status} {url}",
            recommendation="Hassas dosya/dizinse erişimi kapat.",
        ))
    if not findings:
        findings.append(Finding(
            NAME, "İçerik keşfi: temiz", "info",
            f"{len(words)} yol denendi, kayda değer yol bulunamadı "
            f"(catch-all durum: {base_status}).",
        ))
    return findings
