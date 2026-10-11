"""Port & service scan via nmap (Docker), parsing structured XML output.

Using nmap's ``-oX -`` (XML) instead of scraping the human-readable table means
the parser does not break when nmap changes column alignment or wording.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from urllib.parse import urlparse

from ..findings import Finding
from ..runner import DockerRunner

NAME = "ports"
NEEDS_DOCKER = True

# nmap service names that mean "port responds but the service is unconfirmed"
UNIDENTIFIED = {"", "tcpwrapped", "unknown", "unidentified"}

# port -> severity for ports worth calling out when exposed
NOTABLE = {
    22: "low",      # SSH
    23: "high",     # Telnet (cleartext)
    3389: "medium",  # RDP
    3306: "high",   # MySQL
    5432: "high",   # PostgreSQL
    6379: "high",   # Redis
    27017: "high",  # MongoDB
    9200: "high",   # Elasticsearch
}


def _host(target: str) -> str:
    p = urlparse(target)
    return p.hostname or target


def _svc_label(service: str, product: str, version: str) -> str:
    return " ".join(x for x in (service, product, version) if x).strip()


def parse_nmap_xml(xml_text: str) -> list[Finding]:
    """Pure parser for `nmap -oX -` output; testable without Docker."""
    findings: list[Finding] = []
    open_ports: list[str] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return findings

    for port_el in root.iter("port"):
        state_el = port_el.find("state")
        if state_el is None or state_el.get("state") != "open":
            continue
        try:
            port = int(port_el.get("portid", "0"))
        except ValueError:
            continue
        proto = port_el.get("protocol", "tcp")
        svc_el = port_el.find("service")
        service = (svc_el.get("name") if svc_el is not None else "") or "unknown"
        product = (svc_el.get("product") if svc_el is not None else "") or ""
        version = (svc_el.get("version") if svc_el is not None else "") or ""
        label = _svc_label(service, product, version)
        open_ports.append(f"{port}/{service}")
        if port in NOTABLE:
            if service in UNIDENTIFIED:
                # Port responds but nmap could not confirm the service (often a
                # firewall answering every port). Do not claim it is the DB/etc.
                findings.append(Finding(
                    NAME, f"Open port (service unconfirmed): {port}/{proto}", "info",
                    f"{port} responds but the service is unconfirmed "
                    f"(nmap: {service or 'unknown'}). A firewall may be answering "
                    f"every port.",
                    evidence=f"{port}/{proto} open {label}".strip(),
                    rule_id=f"{NAME}.open-unconfirmed",
                    msg_key=f"{NAME}.open-unconfirmed",
                    params={"port": port, "proto": proto,
                            "service": service or "unknown"},
                ))
            else:
                findings.append(Finding(
                    NAME, f"Exposed service: {port}/{service}", NOTABLE[port],
                    "This service is reachable from the internet.",
                    evidence=f"{port}/{proto} open {label}".strip(),
                    recommendation="Restrict access (VPN/allowlist/firewall) or bind "
                                   "to the internal network only.",
                    rule_id=f"{NAME}.exposed-{service}",
                    msg_key=f"{NAME}.exposed",
                    params={"port": port, "service": service},
                ))
    if open_ports:
        findings.append(Finding(
            NAME, "Open ports", "info", "Open ports detected.",
            evidence="; ".join(open_ports),
            rule_id=f"{NAME}.open-ports",
        ))
    return findings


def run(target: str, ctx: dict) -> list[Finding]:
    host = _host(target)
    runner = ctx.get("runner") or DockerRunner()
    stdout = runner.run_capture(
        "nmap",
        ["-Pn", "-sV", "--top-ports", str(ctx.get("top_ports", 100)),
         "-T4", "-oX", "-", host],
        ctx.get("nmap_timeout", 300),
    )
    if not stdout:
        return [Finding(NAME, "nmap produced no output", "info",
                        "Tool unavailable or no response.",
                        rule_id=f"{NAME}.no-output")]
    return parse_nmap_xml(stdout)
