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
    "discover": ModuleSpec(
        "discover", "recon.modules.discover", False, True,
        "Subdomain inventory (CT logs + subfinder if available), live-host probe, "
        "dangling CNAME / takeover check"),
    "crawl": ModuleSpec(
        "crawl", "recon.modules.crawl", True, True,
        "Crawl the site to map endpoints/parameters (katana)", tools=("katana",)),
    "cms": ModuleSpec(
        "cms", "recon.modules.cms", False, True,
        "CMS detection + WordPress exposure checks (read-only)"),
    "idor": ModuleSpec(
        "idor", "recon.modules.idor", False, True,
        "IDOR / broken object-level authorization probe (read-only, opt-in)"),
    "csrf": ModuleSpec(
        "csrf", "recon.modules.csrf", False, True,
        "CSRF protection check on HTML forms (passive, read-only)"),
}

# Default execution order: cheap pure-Python modules first, Docker ones after.
# 'authz' is opt-in (needs credentials) and 'discover' widens what is touched
# (use --discover), so neither is in the default set.
DEFAULT_ORDER = ["headers", "cors", "content", "dns", "ports", "tls", "web"]


# ---- third-party modules (plugins) ----------------------------------------------

PLUGIN_GROUP = "recon_orchestrator.modules"
_plugins_loaded = False


def _entry_points():
    from importlib.metadata import entry_points
    eps = entry_points()
    if hasattr(eps, "select"):                      # Python 3.10+
        return list(eps.select(group=PLUGIN_GROUP))
    return list(eps.get(PLUGIN_GROUP, []))          # type: ignore[attr-defined]


def load_plugins() -> list[str]:
    """Register modules published under the ``recon_orchestrator.modules`` group.

    A plugin package declares, in its pyproject.toml::

        [project.entry-points."recon_orchestrator.modules"]
        mycheck = "my_package.mycheck"

    The target is a Python module with the same contract as the built-in ones
    (NAME, NEEDS_DOCKER, run(target, ctx) -> list[Finding]) plus optional
    DESCRIPTION, ACTIVE (default True) and TOOLS. Plugins never replace a
    built-in module and are never added to the default set, so they only run
    when named with -m. Returns warnings for plugins that could not be loaded.
    """
    global _plugins_loaded
    if _plugins_loaded:
        return []
    _plugins_loaded = True
    warnings: list[str] = []
    for ep in _entry_points():
        import_path = ep.value.split(":", 1)[0].strip()
        try:
            mod = importlib.import_module(import_path)
        except Exception as e:  # noqa: BLE001 - a broken plugin must not break the CLI
            warnings.append(f"plugin {ep.name}: import failed ({type(e).__name__}: {e})")
            continue
        name = getattr(mod, "NAME", ep.name)
        if name in REGISTRY:
            warnings.append(f"plugin {ep.name}: name '{name}' is taken, skipped")
            continue
        if not callable(getattr(mod, "run", None)):
            warnings.append(f"plugin {ep.name}: no run(target, ctx), skipped")
            continue
        REGISTRY[name] = ModuleSpec(
            name, import_path, bool(getattr(mod, "NEEDS_DOCKER", False)),
            bool(getattr(mod, "ACTIVE", True)),
            str(getattr(mod, "DESCRIPTION", f"plugin ({ep.value})")),
            tools=tuple(getattr(mod, "TOOLS", ())),
        )
    return warnings
