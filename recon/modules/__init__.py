"""Module registry.

Each scanning module is described once here so the engine, CLI, config loader
and future `recon modules`/`recon doctor` commands all read from one source.

A module file must expose:
  - NAME: str
  - NEEDS_DOCKER: bool
  - run(target, ctx) -> list[Finding]
"""
from __future__ import annotations

import importlib
from dataclasses import dataclass
from types import ModuleType


@dataclass(frozen=True)
class ModuleSpec:
    name: str
    import_path: str
    needs_docker: bool    # true = needs an external tool (via Docker or native)
    active: bool          # does it send traffic to the target host?
    description: str
    tools: tuple[str, ...] = ()   # logical tools this module needs (for runner)

    def load(self) -> ModuleType:
        return importlib.import_module(self.import_path)


REGISTRY: dict[str, ModuleSpec] = {
    "headers": ModuleSpec(
        "headers", "recon.modules.headers", False, True,
        "Security headers, cookie flags, and technology disclosure"),
    "cors": ModuleSpec(
        "cors", "recon.modules.cors", False, True,
        "CORS misconfiguration (Origin reflection)"),
    "content": ModuleSpec(
        "content", "recon.modules.content", False, True,
        "Path/file discovery (catch-all filtered)"),
    "ports": ModuleSpec(
        "ports", "recon.modules.ports", True, True,
        "Open port/service scan (nmap)", tools=("nmap",)),
    "tls": ModuleSpec(
        "tls", "recon.modules.tls", True, True,
        "TLS configuration: old protocols/weak ciphers (testssl)",
        tools=("testssl",)),
    "web": ModuleSpec(
        "web", "recon.modules.web", True, True,
        "Known-issue/tech detection via community templates (nuclei)",
        tools=("nuclei",)),
    "dns": ModuleSpec(
        "dns", "recon.modules.dns", False, False,
        "DNS & email security: SPF/DMARC/DKIM/CAA/MX (needs dnspython)"),
    "authz": ModuleSpec(
        "authz", "recon.modules.authz", False, True,
        "Authenticated, read-only access-control checks - needs credentials"),
    "openapi": ModuleSpec(
        "openapi", "recon.modules.openapi", False, True,
        "OpenAPI/Swagger-driven endpoint coverage (read-only)"),
    "mail": ModuleSpec(
        "mail", "recon.modules.mail", False, True,
        "SMTP/mail: STARTTLS, MTA-STS, TLS-RPT (scope-respecting, read-only)"),
}

# Default execution order: cheap pure-Python modules first, Docker ones after.
# 'authz' is opt-in (needs credentials), so it is not in the default set.
DEFAULT_ORDER = ["headers", "cors", "content", "dns", "ports", "tls", "web"]
