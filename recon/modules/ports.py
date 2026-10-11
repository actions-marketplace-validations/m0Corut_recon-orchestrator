"""Port & service scan via nmap (Docker), parsing structured XML output.

Using nmap's ``-oX -`` (XML) instead of scraping the human-readable table means
the parser does not break when nmap changes column alignment or wording.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from urllib.parse import urlparse

from ..dockerutil import ensure_image
from ..dockerutil import run as docker_run
from ..findings import Finding

NAME = "ports"
NEEDS_DOCKER = True
IMAGE = "instrumentisto/nmap"

# nmap service names that mean "port responds but the service is unconfirmed"
UNIDENTIFIED = {"", "tcpwrapped", "unknown", "unidentified"}

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
            sev, note = NOTABLE[port]
            if service in UNIDENTIFIED:
                # Port responds but nmap could not confirm the service (often a
                # firewall answering every port). Do not claim it is the DB/etc.;
                # report the open port without the service-specific severity.
                findings.append(Finding(
                    NAME, f"Açık port (servis doğrulanamadı): {port}/{proto}", "info",
                    f"{port} portu yanıt veriyor ama servis doğrulanamadı "
                    f"(nmap: {service or 'belirsiz'}). Güvenlik duvarı tüm portlara "
                    f"yanıt veriyor olabilir.",
                    evidence=f"{port}/{proto} open {label}".strip(),
                    rule_id=f"{NAME}.open-unconfirmed",
                ))
            else:
                findings.append(Finding(
                    NAME, f"Açık servis: {port}/{service}", sev, note,
                    evidence=f"{port}/{proto} open {label}".strip(),
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
        ["-Pn", "-sV", "--top-ports", str(ctx.get("top_ports", 100)),
         "-T4", "-oX", "-", host],
        timeout=ctx.get("nmap_timeout", 300),
    )
    return parse_nmap_xml(res.stdout)
