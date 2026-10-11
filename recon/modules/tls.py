"""TLS configuration review via testssl.sh (Docker), parsing JSON output.

Using testssl's ``--jsonfile`` instead of grepping the terminal output lets us
trust testssl's own severity rating per check and survives output reformatting.
"""
from __future__ import annotations

import json
from urllib.parse import urlparse

from ..findings import Finding, slugify
from ..runner import OUT_PLACEHOLDER, DockerRunner

NAME = "tls"
NEEDS_DOCKER = True

# testssl severity -> our severity (OK/INFO/DEBUG are not findings)
SEV_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "WARN": "low",
}


def _hostport(target: str) -> str:
    p = urlparse(target)
    host = p.hostname or target
    port = p.port or (443 if p.scheme in ("https", "") else 80)
    return f"{host}:{port}"


def parse_testssl_json(json_text: str) -> list[Finding]:
    """Pure parser for testssl.sh ``--jsonfile`` output; testable without Docker."""
    findings: list[Finding] = []
    try:
        entries = json.loads(json_text)
    except (json.JSONDecodeError, ValueError):
        return findings
    if not isinstance(entries, list):
        return findings

    saw_any = False
    for e in entries:
        if not isinstance(e, dict):
            continue
        saw_any = True
        sev = SEV_MAP.get(str(e.get("severity", "")).upper())
        if not sev:
            continue
        check_id = str(e.get("id", "finding"))
        finding_text = str(e.get("finding", ""))
        findings.append(Finding(
            NAME, f"TLS: {check_id}", sev, finding_text or check_id,
            evidence=f"{check_id}: {finding_text}".strip(": "),
            recommendation="Disable old protocols/weak ciphers; enforce TLS 1.2+.",
            rule_id=f"{NAME}.{slugify(check_id)}",
        ))
    if not findings and saw_any:
        findings.append(Finding(
            NAME, "TLS configuration looks solid", "info",
            "testssl reported no notable (LOW+) issue.",
            rule_id=f"{NAME}.config-ok",
        ))
    return findings


def run(target: str, ctx: dict) -> list[Finding]:
    runner = ctx.get("runner") or DockerRunner()
    content = runner.run_with_outfile(
        "testssl",
        ["--quiet", "--color", "0", "--jsonfile", OUT_PLACEHOLDER,
         _hostport(target)],
        ctx.get("tls_timeout", 400),
        filename="testssl.json",
    )
    if not content:
        return [Finding(NAME, "TLS: no JSON output", "info",
                        "testssl did not produce a JSON file (tool unavailable?).",
                        rule_id=f"{NAME}.no-output")]
    return parse_testssl_json(content)
