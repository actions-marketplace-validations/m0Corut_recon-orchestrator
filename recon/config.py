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
}
OPTION_KEYS = {
    "top_ports", "nuclei_tags", "nuclei_severity", "wordlist", "content_threads",
    "http_timeout", "nmap_timeout", "tls_timeout", "nuclei_timeout",
}


class ConfigError(Exception):
    pass


def load_config(path: str) -> dict[str, Any]:
    if yaml is None:
        raise ConfigError("pyyaml kurulu değil: pip install pyyaml")
    if not os.path.exists(path):
        raise ConfigError(f"config bulunamadı: {path}")
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except yaml.YAMLError as e:  # type: ignore[union-attr]
        raise ConfigError(f"YAML ayrıştırılamadı: {e}") from e
    if not isinstance(data, dict):
        raise ConfigError("config kök öğesi bir eşleme (mapping) olmalı")

    unknown = set(data) - TOP_KEYS
    if unknown:
        raise ConfigError(f"bilinmeyen anahtar(lar): {', '.join(sorted(unknown))}")

    if "targets" in data and not isinstance(data["targets"], list):
        raise ConfigError("targets bir liste olmalı")
    if "scope" in data and not isinstance(data["scope"], list):
        raise ConfigError("scope bir liste olmalı")
    if "options" in data:
        if not isinstance(data["options"], dict):
            raise ConfigError("options bir eşleme olmalı")
        bad = set(data["options"]) - OPTION_KEYS
        if bad:
            raise ConfigError(f"bilinmeyen options anahtar(ları): {', '.join(sorted(bad))}")
    return data


TEMPLATE = """\
# recon-orchestrator yapılandırması. Tüm alanlar opsiyonel; CLI bayrakları önceliklidir.

# Taranacak hedefler (yalnız yetkili olduğunuz sistemler).
targets:
  - https://example.com

# Ek izinli host'lar (varsayılan: sadece hedef host). *.domain desteklenir.
# scope:
#   - api.example.com
#   - "*.cdn.example.com"

# Çalıştırılacak modüller ("all" ya da liste).
modules: all
#   - headers
#   - cors
#   - content
#   - ports
#   - tls
#   - web

rate: 20              # aktif araçlar için istek/sn
allow_private: false  # özel/loopback adreslere izin
lang: en              # rapor dili: en | tr
output_dir: recon_runs

# CI çıkış kodu kapıları (opsiyonel):
# fail_on: high        # bu önemde+ herhangi bir bulgu -> çıkış 2
# fail_on_new: medium  # bu önemde+ YENİ bulgu -> çıkış 2

# Modül ayarları (opsiyonel):
# options:
#   top_ports: 100
#   nuclei_tags: cve,exposure,misconfig
#   nuclei_severity: low,medium,high,critical
#   wordlist: ./paths.txt
#   content_threads: 10
"""


def write_template(path: str) -> None:
    if os.path.exists(path):
        raise ConfigError(f"dosya zaten var: {path}")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(TEMPLATE)
