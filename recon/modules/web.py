"""Web vulnerability & tech scan via nuclei (Docker).

Runs nuclei's community templates against the target. Nuclei findings are
detection-based and non-destructive by default, which suits authorized recon.
"""
from __future__ import annotations

import re

from ..dockerutil import ensure_image, run as docker_run
from ..findings import Finding

NAME = "web"
NEEDS_DOCKER = True
IMAGE = "projectdiscovery/nuclei:latest"

# nuclei -nc line: [template-id] [protocol] [severity] matched-url
LINE_RE = re.compile(r"^\[(?P<id>[^\]]+)\]\s+\[(?P<proto>[^\]]+)\]\s+"
                     r"\[(?P<sev>[^\]]+)\]\s+(?P<url>.+)$")

VALID_SEV = {"info", "low", "medium", "high", "critical"}


def run(target: str, ctx: dict) -> list[Finding]:
    if not ensure_image(IMAGE):
        return [Finding(NAME, "nuclei imajı indirilemedi", "info", IMAGE)]

    severities = ctx.get("nuclei_severity", "low,medium,high,critical")
    rate = str(ctx.get("rate", 20))
    args = [
        "-u", target,
        "-severity", severities,
        "-rate-limit", rate,
        "-timeout", "10",
        "-nc", "-silent",
    ]
    tags = ctx.get("nuclei_tags")
    if tags:
        args += ["-tags", tags]

    res = docker_run(IMAGE, args, timeout=ctx.get("nuclei_timeout", 1200))
    findings: list[Finding] = []
    for line in res.stdout.splitlines():
        m = LINE_RE.match(line.strip())
        if not m:
            continue
        sev = m.group("sev").lower()
        if sev not in VALID_SEV:
            sev = "info"
        findings.append(Finding(
            NAME, f"nuclei: {m.group('id')}", sev,
            f"{m.group('proto')} şablonu eşleşti.",
            evidence=f"{m.group('id')} -> {m.group('url')}",
        ))
    if not findings:
        findings.append(Finding(
            NAME, "nuclei: eşleşme yok", "info",
            f"{severities} seviyesinde bulgu yok.",
        ))
    return findings
