"""Scan engine: runs selected modules against a target and collects findings.

Kept free of argparse and file I/O so it can be driven from the CLI, tests, a
future config file, or an embedding application through one entry point.
"""
from __future__ import annotations

from typing import Callable, Iterable

from .context import ScanContext
from .dockerutil import docker_available
from .findings import ScanResult
from .modules import REGISTRY


def resolve_modules(selected: Iterable[str] | str) -> list[str]:
    """Expand 'all' and validate names. Raises ValueError on unknown names."""
    from .modules import DEFAULT_ORDER
    if selected == "all" or selected is None:
        return list(DEFAULT_ORDER)
    names = list(selected) if not isinstance(selected, str) else \
        [m.strip() for m in selected.split(",") if m.strip()]
    unknown = [m for m in names if m not in REGISTRY]
    if unknown:
        raise ValueError(f"bilinmeyen modül(ler): {', '.join(unknown)}")
    return names


def run_scan(
    target: str,
    module_names: list[str],
    ctx: ScanContext,
    *,
    docker_ok: bool | None = None,
    on_event: Callable[[str, str], None] | None = None,
) -> ScanResult:
    """Run the named modules against `target` and return a ScanResult.

    on_event(kind, message): optional progress callback. kind is
    "run" | "skip" | "error". Never raises for a single module failure.
    """
    if docker_ok is None:
        docker_ok = docker_available()
    result = ScanResult(target=target)

    def emit(kind: str, msg: str) -> None:
        if on_event:
            on_event(kind, msg)

    for name in module_names:
        spec = REGISTRY[name]
        if spec.needs_docker and not docker_ok:
            result.errors.append(f"{name}: Docker çalışmıyor, atlandı.")
            emit("skip", name)
            continue
        emit("run", name)
        try:
            mod = spec.load()
            result.add(*mod.run(target, ctx))
        except Exception as e:  # noqa: BLE001 - bir modül hatası taramayı durdurmasın
            result.errors.append(f"{name}: {e}")
            emit("error", f"{name}: {e}")
    return result
