"""Web vulnerability & tech scan via nuclei (Docker), parsing JSONL output.

Using nuclei's ``-jsonl`` instead of the coloured text lines gives a stable,
machine-readable record per finding and brings template name, description, CVE
ids and CVSS score along for free.
"""
from __future__ import annotations

import json

from ..dockerutil import ensure_image
from ..dockerutil import run as docker_run
from ..findings import Finding

NAME = "web"
NEEDS_DOCKER = True
IMAGE = "projectdiscovery/nuclei:latest"

VALID_SEV = {"info", "low", "medium", "high", "critical"}


def parse_nuclei_jsonl(stdout: str, severities: str = "") -> list[Finding]:
    """Pure parser for `nuclei -jsonl` output; testable without Docker."""
    findings: list[Finding] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        template = rec.get("template-id") or rec.get("templateID") or "unknown"
        info = rec.get("info", {}) or {}
        sev = str(info.get("severity", "info")).lower()
        if sev not in VALID_SEV:
            sev = "info"
        name = info.get("name") or template
        matched = rec.get("matched-at") or rec.get("matched") or rec.get("host", "")

        # enrich detail with CVE / CVSS when present
        classification = info.get("classification") or {}
        cves = classification.get("cve-id") or []
        if isinstance(cves, str):
            cves = [cves]
        cvss = classification.get("cvss-score")
        extra = []
        if cves:
            extra.append("CVE: " + ", ".join(cves))
        if cvss:
            extra.append(f"CVSS: {cvss}")
        detail = name + (" (" + "; ".join(extra) + ")" if extra else "")

        findings.append(Finding(
            NAME, f"nuclei: {template}", sev, detail,
            evidence=f"{template} -> {matched}",
            rule_id=f"{NAME}.nuclei.{template}",
        ))
    if not findings:
        findings.append(Finding(
            NAME, "nuclei: eşleşme yok", "info",
            f"{severities or 'seçili'} seviyesinde bulgu yok.",
            rule_id=f"{NAME}.nuclei.no-match",
        ))
    return findings


def run(target: str, ctx: dict) -> list[Finding]:
    if not ensure_image(IMAGE):
        return [Finding(NAME, "nuclei imajı indirilemedi", "info", IMAGE,
                        rule_id=f"{NAME}.image-unavailable")]

    severities = ctx.get("nuclei_severity", "low,medium,high,critical")
    args = [
        "-u", target,
        "-severity", severities,
        "-rate-limit", str(ctx.get("rate", 20)),
        "-timeout", "10",
        "-jsonl", "-silent",
    ]
    tags = ctx.get("nuclei_tags")
    if tags:
        args += ["-tags", tags]

    res = docker_run(IMAGE, args, timeout=ctx.get("nuclei_timeout", 1200))
    return parse_nuclei_jsonl(res.stdout, severities)
