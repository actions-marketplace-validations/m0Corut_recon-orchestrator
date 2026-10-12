"""Typed scan configuration passed from the CLI/engine down to modules.

Modules still read values via ``ctx.get("key", default)`` so the dataclass is
backward-compatible with the earlier plain-dict context: known settings are
typed fields, anything else lives in ``extra``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScanContext:
    # shared
    rate: int = 20                      # aggregate req/s ceiling for active tools
    http_timeout: int = 15
    # module-specific knobs
    top_ports: int = 100
    nmap_timeout: int = 300
    tls_timeout: int = 400
    nuclei_timeout: int = 1200
    nuclei_severity: str = "low,medium,high,critical"
    nuclei_tags: str | None = None
    content_threads: int = 10
    wordlist_entries: list[str] | None = None
    discover_max_hosts: int = 200
    dast: bool = False                  # nuclei DAST on a GET-only API spec copy
    discover_timeout: int = 300
    # authenticated (authz) module inputs
    auth_header: str | None = None
    auth_pages: list[str] | None = None
    # scope allowlist (set by the engine/CLI); None means unrestricted
    scope: Any = None
    # shared rate limiter (set by the engine); None means no limiting
    limiter: Any = None
    # tool runner (Docker/native); None means modules use a default DockerRunner
    runner: Any = None
    # escape hatch for options not (yet) promoted to fields
    extra: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        if key == "extra":
            return default
        if hasattr(self, key):
            return getattr(self, key)
        return self.extra.get(key, default)
