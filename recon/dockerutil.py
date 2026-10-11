"""Thin wrapper around `docker run` so modules can call containerised tools.

Every scanning tool (nmap, nuclei, testssl, ...) ships as a Docker image, so the
only host dependency is Docker itself. This keeps the orchestrator portable and
avoids installing a dozen security tools natively.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


class DockerUnavailable(RuntimeError):
    pass


def docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        r = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, timeout=15,
        )
        return r.returncode == 0 and bool(r.stdout.strip())
    except Exception:
        return False


@dataclass
class ToolResult:
    stdout: str
    stderr: str
    returncode: int
    timed_out: bool = False


def run(image: str, args: list[str], *, timeout: int = 600,
        volumes: dict[str, str] | None = None) -> ToolResult:
    """Run `docker run --rm [volumes] <image> <args>` and capture output.

    volumes maps host path -> container path (both absolute).
    """
    cmd = ["docker", "run", "--rm"]
    for host, cont in (volumes or {}).items():
        cmd += ["-v", f"{host}:{cont}"]
    cmd.append(image)
    cmd += args
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return ToolResult(r.stdout, r.stderr, r.returncode)
    except subprocess.TimeoutExpired as e:
        def _as_text(x: object) -> str:
            if isinstance(x, bytes):
                return x.decode("utf-8", "replace")
            return x or "" if isinstance(x, str) else ""
        return ToolResult(_as_text(e.stdout), _as_text(e.stderr), -1, timed_out=True)


def ensure_image(image: str, *, timeout: int = 600) -> bool:
    """Pull an image if it is not present locally. Returns True on success."""
    have = subprocess.run(["docker", "image", "inspect", image],
                          capture_output=True, text=True)
    if have.returncode == 0:
        return True
    pull = subprocess.run(["docker", "pull", image], capture_output=True,
                          text=True, timeout=timeout)
    return pull.returncode == 0
