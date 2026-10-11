"""Port & service scan via nmap (Docker). Flags notable exposed services."""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ..dockerutil import ensure_image, run as docker_run
from ..findings import Finding

NAME = "ports"
NEEDS_DOCKER = True
IMAGE = "instrumentisto/nmap"

# port -> (severity, note) for ports worth calling out when exposed
NOTABLE = {
    22: ("low", "SSH internete açık — IP allowlist / VPN arkasına almayı değerlendir"),
    23: ("high", "Telnet açık — şifresiz, kapat"),
    3389: ("medium", "RDP açık — brute force hedefi, VPN arkasına al"),
    3306: ("high", "MySQL internete açık — yalnız iç ağa bağla"),
    5432: ("high", "PostgreSQL internete açık — yalnız iç ağa bağla"),
    6379: ("high", "Redis internete açık — yetkisiz erişim riski"),
    27017: ("high", "MongoDB internete açık — yetkisiz erişim riski"),
    9200: ("high", "Elasticsearch internete açık — veri sızıntısı riski"),
}

LINE_RE = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)\s*(.*)$")


def _host(target: str) -> str:
    p = urlparse(target)
    return p.hostname or target


def parse_nmap(stdout: str) -> list[Finding]:
    """Pure parser for `nmap -sV` text output; testable without Docker."""
    findings: list[Finding] = []
    open_ports: list[str] = []
    for line in stdout.splitlines():
        m = LINE_RE.match(line.strip())
        if not m:
            continue
        port = int(m.group(1))
        service = m.group(2)
        version = m.group(3).strip()
        open_ports.append(f"{port}/{service} {version}".strip())
        if port in NOTABLE:
            sev, note = NOTABLE[port]
            findings.append(Finding(
                NAME, f"Açık servis: {port}/{service}", sev, note,
                evidence=f"{port}/tcp open {service} {version}".strip(),
                rule_id=f"{NAME}.exposed-{service}",
            ))
    if open_ports:
        findings.append(Finding(
            NAME, "Açık portlar", "info", "Tespit edilen açık portlar.",
            evidence="; ".join(open_ports),
            rule_id=f"{NAME}.open-ports",
        ))
    return findings


def run(target: str, ctx: dict) -> list[Finding]:
    host = _host(target)
    if not ensure_image(IMAGE):
        return [Finding(NAME, "nmap imajı indirilemedi", "info", IMAGE,
                        rule_id=f"{NAME}.image-unavailable")]
    res = docker_run(
        IMAGE,
        ["-Pn", "-sV", "--top-ports", str(ctx.get("top_ports", 100)), "-T4", host],
        timeout=ctx.get("nmap_timeout", 300),
    )
    return parse_nmap(res.stdout)
