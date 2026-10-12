"""Surface mapping: crawl the target and report the endpoints found.

Runs katana (via the shared crawl helper) and turns the result into a picture of
the attack surface: how many URLs, how many carry query parameters (the inputs
DAST can fuzz), and a sample. Discovered URLs are stored on the context so a
later step can reuse them. Read-only: GET crawl, target host only, shared rate
limit. Opt-in (needs ``katana``); not in the default module set.
"""
from __future__ import annotations

from urllib.parse import urlparse

from ..crawl import crawl, with_params
from ..findings import Finding

NAME = "crawl"
NEEDS_DOCKER = True
TOOLS = ("katana",)

SAMPLE = 15


def build_findings(target: str, urls: list[str]) -> list[Finding]:
    """Pure: turn a crawl result into findings."""
    if not urls:
        return [Finding(
            NAME, "Crawl found no additional endpoints", "info",
            "katana did not discover any in-host URLs beyond the target.",
            rule_id=f"{NAME}.empty")]
    params = with_params(urls)
    host = urlparse(target).hostname or target
    sample = "; ".join(u for u in params[:SAMPLE]) or "; ".join(urls[:SAMPLE])
    return [Finding(
        NAME, f"Attack surface: {len(urls)} endpoint(s) on {host}", "info",
        f"Crawl found {len(urls)} in-host URL(s), {len(params)} with query "
        f"parameters (fuzzable). Run with --dast to fuzz the parameterised ones.",
        evidence=sample,
        rule_id=f"{NAME}.surface", msg_key=f"{NAME}.surface",
        params={"host": host, "urls": len(urls), "params": len(params)})]


def run(target: str, ctx) -> list[Finding]:
    runner = ctx.get("runner")
    urls = crawl(target, runner,
                 depth=int(ctx.get("crawl_depth", 2)),
                 rate=int(ctx.get("rate", 20)),
                 timeout=int(ctx.get("crawl_timeout", 300)),
                 max_urls=int(ctx.get("crawl_max_urls", 500)))
    if isinstance(getattr(ctx, "extra", None), dict):
        ctx.extra["crawled_urls"] = urls
    return build_findings(target, urls)
