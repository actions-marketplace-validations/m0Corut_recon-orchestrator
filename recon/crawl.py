"""Endpoint discovery by crawling, via katana.

A URL scan can only find injection-class bugs in the parameters it actually
visits. nuclei does not crawl, so without this step the scan never sees past the
one URL it was given — which is why a login page alone yields nothing. katana
walks the site (same host only) and returns the URLs and query parameters it
finds; those become the inputs for DAST fuzzing (see ``web._run_dast``) and a
surface-mapping finding (see ``modules.crawl``).

Crawling sends GET requests only, stays on the target's exact host, and goes
through the shared rate limit — same safety envelope as the other active
modules. Pure parsing is split out so it is unit-tested without katana.
"""
from __future__ import annotations

from urllib.parse import urlparse

NAME_TOOL = "katana"


def parse_katana(stdout: str, host: str) -> list[str]:
    """Pure parser for `katana -silent` output: one URL per line.

    Keeps only http(s) URLs on ``host`` (defence in depth on top of katana's
    own scope flag), de-duplicated, order preserved.
    """
    seen: set[str] = set()
    out: list[str] = []
    for line in stdout.splitlines():
        url = line.strip()
        if not url or " " in url:
            continue
        p = urlparse(url)
        if p.scheme not in ("http", "https") or (p.hostname or "").lower() != host.lower():
            continue
        if url not in seen:
            seen.add(url)
            out.append(url)
    return out


def with_params(urls: list[str]) -> list[str]:
    """URLs that carry at least one query parameter (what DAST can fuzz)."""
    return [u for u in urls if urlparse(u).query]


def crawl(target: str, runner, *, depth: int = 2, rate: int = 20,
          timeout: int = 300, max_urls: int = 500, headless: bool = False) -> list[str]:
    """Run katana against `target`; return discovered in-host URLs (capped).

    headless=True drives a real browser so a single-page app's runtime API calls
    are seen (static JS parsing misses them). It needs Chrome/Chromium available
    to katana, which the all-in-one image installs; the stock katana image has no
    browser, so headless there finds nothing. ``-nos`` runs the browser without a
    sandbox (required as root in a container); ``-sc`` uses the system Chrome.
    """
    if runner is None or not runner.can_run(NAME_TOOL):
        return []
    host = urlparse(target).hostname or target
    args = [
        "-u", target,
        "-silent",
        "-d", str(depth),
        "-fs", "fqdn",            # stay on the exact target host
        "-jc",                    # parse linked JS for endpoints (SPAs hide them there)
        "-rl", str(rate),         # requests/second, matches --rate
        "-timeout", "10",
        "-c", "10",
        "-iqp",                   # include query params in the crawl surface
    ]
    if headless:
        args += ["-headless", "-nos", "-sc"]
    stdout = runner.run_capture(NAME_TOOL, args, timeout)
    return parse_katana(stdout, host)[:max_urls]
