"""Tool runner abstraction: run external scanners via Docker or native binaries.

Modules ask a runner to execute a logical tool ("nmap", "nuclei", "testssl")
and do not care whether it runs as a Docker image or a locally installed binary.
This lets the orchestrator run inside its own Docker image (which bundles the
tools as native binaries) without mounting the Docker socket.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

from .dockerutil import ensure_image
from .dockerutil import run as docker_run

# logical tool -> (docker image, native binary name)
# Images are pinned so scans are reproducible and a re-tagged upstream image is
# not pulled silently; bump these deliberately (keep the Dockerfile in sync).
TOOLS = {
    "nmap": ("instrumentisto/nmap:7.98", "nmap"),
    "nuclei": ("projectdiscovery/nuclei:v3.11.1", "nuclei"),
    "testssl": ("drwetter/testssl.sh:3.2", "testssl.sh"),
}

OUT_PLACEHOLDER = "{out}"


class DockerRunner:
    name = "docker"

    def can_run(self, tool: str) -> bool:
        from .dockerutil import docker_available
        return docker_available()

    def run_capture(self, tool: str, args: list[str], timeout: int) -> str:
        image = TOOLS[tool][0]
        if not ensure_image(image):
            return ""
        return docker_run(image, args, timeout=timeout).stdout

    def run_with_outfile(self, tool: str, args: list[str], timeout: int,
                         filename: str = "out.json") -> str:
        image = TOOLS[tool][0]
        if not ensure_image(image):
            return ""
        out_dir = tempfile.mkdtemp(prefix="recon-")
        try:
            cont_path = f"/out/{filename}"
            real_args = [a.replace(OUT_PLACEHOLDER, cont_path) for a in args]
            docker_run(image, real_args, timeout=timeout, volumes={out_dir: "/out"})
            host_file = os.path.join(out_dir, filename)
            if os.path.exists(host_file):
                with open(host_file, encoding="utf-8", errors="replace") as fh:
                    return fh.read()
            return ""
        finally:
            _cleanup(out_dir, filename)


class NativeRunner:
    name = "native"

    def can_run(self, tool: str) -> bool:
        return shutil.which(TOOLS[tool][1]) is not None

    def run_capture(self, tool: str, args: list[str], timeout: int) -> str:
        binary = TOOLS[tool][1]
        try:
            r = subprocess.run([binary, *args], capture_output=True, text=True,
                               timeout=timeout)
            return r.stdout
        except (subprocess.TimeoutExpired, OSError):
            return ""

    def run_with_outfile(self, tool: str, args: list[str], timeout: int,
                         filename: str = "out.json") -> str:
        binary = TOOLS[tool][1]
        out_dir = tempfile.mkdtemp(prefix="recon-")
        try:
            path = os.path.join(out_dir, filename)
            real_args = [a.replace(OUT_PLACEHOLDER, path) for a in args]
            try:
                subprocess.run([binary, *real_args], capture_output=True,
                               text=True, timeout=timeout)
            except (subprocess.TimeoutExpired, OSError):
                return ""
            if os.path.exists(path):
                with open(path, encoding="utf-8", errors="replace") as fh:
                    return fh.read()
            return ""
        finally:
            _cleanup(out_dir, filename)


def _cleanup(out_dir: str, filename: str) -> None:
    try:
        os.remove(os.path.join(out_dir, filename))
    except OSError:
        pass
    try:
        os.rmdir(out_dir)
    except OSError:
        pass


def get_runner(mode: str = "auto"):
    """mode: auto|docker|native. 'auto' prefers native binaries, else Docker."""
    if mode == "docker":
        return DockerRunner()
    if mode == "native":
        return NativeRunner()
    native = NativeRunner()
    # prefer native only if ALL tools are present; otherwise Docker is simpler
    if all(native.can_run(t) for t in TOOLS):
        return native
    return DockerRunner()
