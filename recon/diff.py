"""Run-to-run diff by finding fingerprint.

Lets CI gate on *new* findings only (``--fail-on-new``) instead of failing
forever on a pre-existing issue. A baseline is a prior ``report.json`` (or a run
directory containing one). Findings are matched by their stable ``fingerprint``.
"""
from __future__ import annotations

import glob
import json
import os
from dataclasses import dataclass, field

from .findings import SEVERITY_RANK, Finding, ScanResult


@dataclass
class DiffResult:
    new: list[Finding] = field(default_factory=list)
    unchanged: list[Finding] = field(default_factory=list)
    resolved: list[dict] = field(default_factory=list)  # baseline finding dicts

    @property
    def new_fingerprints(self) -> set[str]:
        return {f.fingerprint for f in self.new}

    def max_new_rank(self) -> int:
        return max((f.rank for f in self.new), default=-1)


def _report_path(baseline: str) -> str | None:
    """Accept a report.json path or a run directory containing one."""
    if os.path.isdir(baseline):
        cand = os.path.join(baseline, "report.json")
        return cand if os.path.exists(cand) else None
    return baseline if os.path.exists(baseline) else None


def fingerprints_from_report(path: str) -> dict[str, dict]:
    """Return {fingerprint: finding_dict} from a report.json."""
    rp = _report_path(path)
    if not rp:
        return {}
    try:
        with open(rp, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}
    out: dict[str, dict] = {}
    for f in data.get("findings", []):
        fp = f.get("fingerprint")
        if fp:
            out[fp] = f
    return out


def find_latest_baseline(output_dir: str, host: str,
                         exclude_dir: str | None = None) -> str | None:
    """Pick the most recent prior run's report.json for `host` in output_dir."""
    pattern = os.path.join(output_dir, f"{host}_*", "report.json")
    candidates = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
    for c in candidates:
        if exclude_dir and os.path.dirname(os.path.abspath(c)) == \
                os.path.abspath(exclude_dir):
            continue
        return c
    return None


def compute_diff(current: ScanResult, baseline: dict[str, dict]) -> DiffResult:
    """Diff current findings against a baseline {fingerprint: dict}."""
    diff = DiffResult()
    seen_now: set[str] = set()
    for f in current.findings:
        seen_now.add(f.fingerprint)
        if f.fingerprint in baseline:
            diff.unchanged.append(f)
        else:
            diff.new.append(f)
    # a finding that is still present but now suppressed is not "resolved"
    still_present = seen_now | current.suppressed_fingerprints
    for fp, fdict in baseline.items():
        if fp not in still_present:
            diff.resolved.append(fdict)
    # most severe new first
    diff.new.sort(key=lambda f: (-f.rank, f.module, f.rule_id))
    return diff


def exceeds_new_threshold(diff: DiffResult, severity: str) -> bool:
    threshold = SEVERITY_RANK.get(severity.lower())
    if threshold is None:
        return False
    return diff.max_new_rank() >= threshold
