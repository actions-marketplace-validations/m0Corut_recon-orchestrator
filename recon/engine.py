"""Scan engine: runs selected modules against a target and collects findings.

Kept free of argparse and file I/O so it can be driven from the CLI, tests, a
future config file, or an embedding application through one entry point.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Callable

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
        raise ValueError(f"unknown module(s): {', '.join(unknown)}")
    return names


def run_scan(
    target: str,
    module_names: list[str],
    ctx: ScanContext,
    *,
    docker_ok: bool | None = None,
    on_event: Callable[[str, str], None] | None = None,
    jobs: int | None = None,
    serial: bool = False,
    completed: dict[str, list] | None = None,
    on_module_done: Callable[[str, list], None] | None = None,
) -> ScanResult:
    """Run the named modules against `target` and return a ScanResult.

    on_event(kind, message): optional progress callback. kind is
    "run" | "skip" | "error". Never raises for a single module failure.
    jobs: max concurrent modules (default: all runnable). serial: force sequential.
    completed: {module: findings} from an interrupted run; those modules are not
      re-run and their findings are reused (resume).
    on_module_done(name, findings): called after each module finishes without
      raising, so a caller can checkpoint progress.
    """
    import threading
    import time
    from concurrent.futures import ThreadPoolExecutor

    if docker_ok is None:
        docker_ok = docker_available()
    result = ScanResult(target=target)
    lock = threading.Lock()

    def emit(kind: str, msg: str) -> None:
        if on_event:
            on_event(kind, msg)

    # Scope gate: refuse to scan a target that is not in the allowlist.
    scope = getattr(ctx, "scope", None)
    if scope is not None:
        from urllib.parse import urlparse
        host = urlparse(target).hostname or target
        if not scope.allows(host):
            result.errors.append(
                f"scope: target '{host}' is outside the allowlist, scan aborted.")
            emit("error", f"scope: {host} is outside the allowlist")
            return result

    runner = getattr(ctx, "runner", None)
    runnable: list[str] = []
    for name in module_names:
        spec = REGISTRY[name]
        if spec.needs_docker:
            if runner is not None:
                if not all(runner.can_run(t) for t in spec.tools):
                    result.errors.append(
                        f"{name}: required tool(s) unavailable ({runner.name}), skipped.")
                    emit("skip", name)
                    continue
            elif not docker_ok:
                result.errors.append(f"{name}: Docker not available, skipped.")
                emit("skip", name)
                continue
        runnable.append(name)

    seen_fp: set[str] = set()

    def merge(found: list) -> None:
        for f in found:
            if f.fingerprint in seen_fp:
                continue
            seen_fp.add(f.fingerprint)
            result.add(f)

    for name in list(runnable):
        if completed and name in completed:
            runnable.remove(name)
            merge(completed[name])
            emit("resume", name)

    def run_module(name: str) -> None:
        emit("run", name)
        start = time.monotonic()
        try:
            found = REGISTRY[name].load().run(target, ctx)
        except Exception as e:  # noqa: BLE001 - one module's failure must not abort the scan
            with lock:
                result.errors.append(f"{name}: {e}")
            emit("error", f"{name}: {e}")
            return
        elapsed = time.monotonic() - start
        with lock:
            merge(found)
            if on_module_done:
                on_module_done(name, found)
        emit("done", f"{name} ({elapsed:.1f}s, {len(found)})")

    if serial or jobs == 1 or len(runnable) <= 1:
        for name in runnable:
            run_module(name)
    else:
        workers = jobs or len(runnable)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(run_module, runnable))
    return result
