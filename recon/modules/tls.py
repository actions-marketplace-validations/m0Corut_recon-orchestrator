"""TLS configuration review via testssl.sh (Docker)."""
from __future__ import annotations

from urllib.parse import urlparse

from ..dockerutil import ensure_image, run as docker_run
from ..findings import Finding

NAME = "tls"
NEEDS_DOCKER = True
IMAGE = "drwetter/testssl.sh"

# substring in testssl output -> (rule slug, severity, title)
BAD_SIGNALS = {
    "SSLv2      offered": ("sslv2-enabled", "high", "SSLv2 destekleniyor"),
    "SSLv3      offered": ("sslv3-enabled", "high", "SSLv3 destekleniyor"),
    "TLS 1      offered": ("tls10-enabled", "medium", "TLS 1.0 destekleniyor (eski)"),
    "TLS 1.1    offered": ("tls11-enabled", "medium", "TLS 1.1 destekleniyor (eski)"),
    "VULNERABLE": ("vulnerable", "high", "testssl bir zafiyet işaretledi"),
}


def _hostport(target: str) -> str:
    p = urlparse(target)
    host = p.hostname or target
    port = p.port or (443 if p.scheme in ("https", "") else 80)
    return f"{host}:{port}"


def parse_testssl(out: str) -> list[Finding]:
    """Pure parser for testssl.sh text output; testable without Docker."""
    findings: list[Finding] = []
    for signal, (slug, sev, title) in BAD_SIGNALS.items():
        if signal in out:
            ev = next((ln.strip() for ln in out.splitlines() if signal in ln), signal)
            findings.append(Finding(
                NAME, title, sev, "testssl.sh çıktısında işaretlendi.",
                evidence=ev,
                recommendation="Eski protokol/şifreleyicileri kapat; TLS 1.2+ zorla.",
                rule_id=f"{NAME}.{slug}",
            ))
    if not findings and ("TLS 1.3" in out or "TLS 1.2" in out):
        findings.append(Finding(
            NAME, "TLS yapılandırması sağlam", "info",
            "Eski protokol/zayıf şifreleyici tespit edilmedi.",
            rule_id=f"{NAME}.config-ok",
        ))
    return findings


def run(target: str, ctx: dict) -> list[Finding]:
    if not ensure_image(IMAGE):
        return [Finding(NAME, "testssl imajı indirilemedi", "info", IMAGE,
                        rule_id=f"{NAME}.image-unavailable")]
    res = docker_run(
        IMAGE, ["--quiet", "--color", "0", _hostport(target)],
        timeout=ctx.get("tls_timeout", 400),
    )
    return parse_testssl(res.stdout)
