"""YAML configuration loading and validation.

A config file lets you pin targets, scope, module selection and per-module
options so a scan (and its CI step) is a one-liner. CLI flags override config;
config overrides built-in defaults.
"""
from __future__ import annotations

import os
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - yaml is a runtime dependency
    yaml = None  # type: ignore[assignment]

TOP_KEYS = {
    "targets", "scope", "modules", "rate", "allow_private", "lang",
    "output_dir", "fail_on", "fail_on_new", "options",
    "suppress_file", "notify_env", "notify_min_severity",
}
OPTION_KEYS = {
    "top_ports", "nuclei_tags", "nuclei_severity", "wordlist", "content_threads",
    "http_timeout", "nmap_timeout", "tls_timeout", "nuclei_timeout",
    "discover_max_hosts", "discover_timeout",
}


class ConfigError(Exception):
    pass


def load_config(path: str) -> dict[str, Any]:
    if yaml is None:
        raise ConfigError("pyyaml is not installed: pip install pyyaml")
    if not os.path.exists(path):
        raise ConfigError(f"config not found: {path}")
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except yaml.YAMLError as e:  # type: ignore[union-attr]
        raise ConfigError(f"could not parse YAML: {e}") from e
    if not isinstance(data, dict):
        raise ConfigError("the config root must be a mapping")

    unknown = set(data) - TOP_KEYS
    if unknown:
        raise ConfigError(f"unknown key(s): {', '.join(sorted(unknown))}")

    if "targets" in data and not isinstance(data["targets"], list):
        raise ConfigError("targets must be a list")
    if "scope" in data and not isinstance(data["scope"], list):
        raise ConfigError("scope must be a list")
    if "options" in data:
        if not isinstance(data["options"], dict):
            raise ConfigError("options must be a mapping")
        bad = set(data["options"]) - OPTION_KEYS
        if bad:
            raise ConfigError(f"unknown options key(s): {', '.join(sorted(bad))}")
    return data


TEMPLATE = """\
# recon-orchestrator configuration. Every field is optional; CLI flags take priority.

# Targets to scan (only systems you are authorized to test).
targets:
  - https://example.com

# Extra allowed hosts (default: the target host only). *.domain is supported.
# scope:
#   - api.example.com
#   - "*.cdn.example.com"

# Modules to run ("all" or a list).
modules: all
#   - headers
#   - cors
#   - content
#   - ports
#   - tls
#   - web

rate: 20              # requests/sec for active tools
allow_private: false  # allow private/loopback addresses
lang: en              # report language: en | tr
output_dir: recon_runs

# CI exit-code gates (optional):
# fail_on: high        # any finding at this severity+ -> exit 2
# fail_on_new: medium  # a NEW finding at this severity+ -> exit 2

# Accepted risks (default: .reconignore.yml if it exists):
# suppress_file: .reconignore.yml

# Webhook notification on NEW findings. The URL is a secret, so it is read from
# an environment variable (comma-separated for several webhooks):
# notify_env: RECON_WEBHOOK
# notify_min_severity: medium

# Per-module options (optional):
# options:
#   top_ports: 100
#   nuclei_tags: cve,exposure,misconfig
#   nuclei_severity: low,medium,high,critical
#   wordlist: ./paths.txt
#   content_threads: 10
#   discover_max_hosts: 200   # cap on names resolved by --discover
"""


def write_template(path: str) -> None:
    if os.path.exists(path):
        raise ConfigError(f"file already exists: {path}")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(TEMPLATE)
