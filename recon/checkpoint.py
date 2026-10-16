"""Checkpoints so an interrupted scan can resume (``--resume``).

nuclei and testssl can run for many minutes; losing a whole run to a Ctrl-C,
a CI timeout or a dropped connection is expensive. After each module finishes,
its findings are written to ``<output_dir>/.partial/<host>.json``. A later run
with ``--resume`` reuses finished modules (same target and module list only)
and the checkpoint is deleted once the scan completes and reports are written.
"""
from __future__ import annotations

import json
import os
import threading

from .findings import Finding

_FIELDS = ("module", "title", "severity", "detail", "evidence", "recommendation",
           "rule_id", "msg_key", "params")


def path_for(output_dir: str, host_slug: str) -> str:
    return os.path.join(output_dir, ".partial", f"{host_slug}.json")


def finding_from_dict(d: dict) -> Finding:
    return Finding(**{k: d[k] for k in _FIELDS if k in d})


class Checkpoint:
    def __init__(self, path: str, target: str, modules: list[str]) -> None:
        self.path = path
        self.target = target
        self.modules = sorted(modules)
        self.done: dict[str, list[dict]] = {}
        self._lock = threading.Lock()

    def load(self) -> dict[str, list[Finding]]:
        """Finished modules from a previous run, if it was the same scan."""
        try:
            with open(self.path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return {}
        if data.get("target") != self.target or data.get("modules") != self.modules:
            return {}      # a different scan: never mix results
        self.done = {m: list(fs) for m, fs in data.get("done", {}).items()}
        return {m: [finding_from_dict(d) for d in fs] for m, fs in self.done.items()}

    def record(self, module: str, findings: list[Finding]) -> None:
        with self._lock:
            self.done[module] = [f.to_dict() for f in findings]
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"target": self.target, "modules": self.modules,
                           "done": self.done}, fh, ensure_ascii=False)
            os.replace(tmp, self.path)       # atomic: never a half-written file

    def clear(self) -> None:
        try:
            os.remove(self.path)
        except OSError:
            pass
