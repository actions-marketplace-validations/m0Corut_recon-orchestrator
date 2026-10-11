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
    needs_docker: bool
    active: bool          # does it send traffic to the target host?
    description: str

    def load(self) -> ModuleType:
        return importlib.import_module(self.import_path)


REGISTRY: dict[str, ModuleSpec] = {
    "headers": ModuleSpec(
        "headers", "recon.modules.headers", False, True,
        "Güvenlik başlıkları, cookie bayrakları ve teknoloji ifşası"),
    "cors": ModuleSpec(
        "cors", "recon.modules.cors", False, True,
        "CORS yanlış yapılandırması (Origin yansıması)"),
    "content": ModuleSpec(
        "content", "recon.modules.content", False, True,
        "Dizin/dosya keşfi (catch-all filtreli)"),
    "ports": ModuleSpec(
        "ports", "recon.modules.ports", True, True,
        "Açık port/servis taraması (nmap)"),
    "tls": ModuleSpec(
        "tls", "recon.modules.tls", True, True,
        "TLS yapılandırması: eski protokol/zayıf şifreleyici (testssl)"),
    "web": ModuleSpec(
        "web", "recon.modules.web", True, True,
        "Topluluk şablonlarıyla açık/teknoloji tespiti (nuclei)"),
    "dns": ModuleSpec(
        "dns", "recon.modules.dns", False, False,
        "DNS & e-posta güvenliği: SPF/DMARC/DKIM/CAA/MX (dnspython gerekir)"),
}

# Default execution order: cheap pure-Python modules first, Docker ones after.
DEFAULT_ORDER = ["headers", "cors", "content", "dns", "ports", "tls", "web"]
