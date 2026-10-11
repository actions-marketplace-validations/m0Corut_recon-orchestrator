"""Web vulnerability & tech scan via nuclei (Docker).

Runs nuclei's community templates against the target. Nuclei findings are
detection-based and non-destructive by default, which suits authorized recon.
"""
from __future__ import annotations

import re

from ..dockerutil import ensure_image
from ..dockerutil import run as docker_run
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
    return parse_nuclei(res.stdout, severities)


def parse_nuclei(stdout: str, severities: str = "") -> list[Finding]:
    """Pure parser for `nuclei -nc` text lines; testable without Docker."""
    findings: list[Finding] = []
    for line in stdout.splitlines():
        m = LINE_RE.match(line.strip())
        if not m:
            continue
        sev = m.group("sev").lower()
        if sev not in VALID_SEV:
            sev = "info"
        template = m.group("id")
        findings.append(Finding(
            NAME, f"nuclei: {template}", sev,
            f"{m.group('proto')} şablonu eşleşti.",
            evidence=f"{template} -> {m.group('url')}",
            rule_id=f"{NAME}.nuclei.{template}",
        ))
    if not findings:
        findings.append(Finding(
            NAME, "nuclei: eşleşme yok", "info",
            f"{severities or 'seçili'} seviyesinde bulgu yok.",
            rule_id=f"{NAME}.nuclei.no-match",
        ))
    return findings
