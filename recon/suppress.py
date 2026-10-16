"""Suppression file: accepted risks that should not fail CI or clutter reports.

A baseline separates "new" from "already seen"; a suppression says "seen,
reviewed, accepted, with a reason, until a date". Suppressed findings are moved
out of ``ScanResult.findings`` (so gates and counts ignore them) into
``ScanResult.suppressed`` (so reports still show what was hidden and why).

File format (YAML list, default ``.reconignore.yml`` in the working dir)::

    - rule_id: headers.missing-csp      # required; fnmatch glob ("headers.*")
      reason: "CSP rollout tracked in JIRA-123"   # required
      expires: 2027-01-31               # optional; expired entries stop applying
      target: "https://staging.*"       # optional; fnmatch glob on the target
      fingerprint: 3f2a...              # optional; pin to one finding instance
"""
from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any

from .findings import Finding, ScanResult

DEFAULT_FILE = ".reconignore.yml"


class SuppressionError(Exception):
    pass


@dataclass(frozen=True)
class Suppression:
    rule_id: str
    reason: str
    expires: date | None = None
    target: str | None = None
    fingerprint: str | None = None

    def expired(self, today: date) -> bool:
        return self.expires is not None and today > self.expires

    def matches(self, finding: Finding, target: str) -> bool:
        if not fnmatch.fnmatchcase(finding.rule_id, self.rule_id):
            return False
        if self.target and not fnmatch.fnmatchcase(target, self.target):
            return False
        return not (self.fingerprint and finding.fingerprint != self.fingerprint)


def _parse_date(value: Any, idx: int) -> date | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value))
    except ValueError:
        raise SuppressionError(f"entry {idx}: expires must be YYYY-MM-DD, got {value!r}")


def parse_suppressions(data: Any) -> list[Suppression]:
    if data is None:
        return []
    if not isinstance(data, list):
        raise SuppressionError("the suppression file must be a YAML list")
    out: list[Suppression] = []
    for idx, entry in enumerate(data, 1):
        if not isinstance(entry, dict):
            raise SuppressionError(f"entry {idx}: must be a mapping")
        unknown = set(entry) - {"rule_id", "reason", "expires", "target", "fingerprint"}
        if unknown:
            raise SuppressionError(f"entry {idx}: unknown key(s) {', '.join(sorted(unknown))}")
        rule_id = str(entry.get("rule_id") or "").strip()
        reason = str(entry.get("reason") or "").strip()
        if not rule_id:
            raise SuppressionError(f"entry {idx}: rule_id is required")
        if not reason:
            raise SuppressionError(f"entry {idx} ({rule_id}): reason is required")
        out.append(Suppression(
            rule_id=rule_id, reason=reason,
            expires=_parse_date(entry.get("expires"), idx),
            target=(str(entry["target"]) if entry.get("target") else None),
            fingerprint=(str(entry["fingerprint"]) if entry.get("fingerprint") else None),
        ))
    return out


def load_suppressions(path: str) -> list[Suppression]:
    import yaml
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except OSError as e:
        raise SuppressionError(f"could not read {path}: {e}")
    except yaml.YAMLError as e:
        raise SuppressionError(f"could not parse {path}: {e}")
    return parse_suppressions(data)


def resolve_path(explicit: str | None) -> str | None:
    """Explicit path if given, else the default file when it exists."""
    if explicit:
        return explicit
    return DEFAULT_FILE if os.path.exists(DEFAULT_FILE) else None


def apply_suppressions(result: ScanResult, rules: list[Suppression],
                       today: date | None = None) -> list[Suppression]:
    """Move matching findings to ``result.suppressed``; return expired rules.

    Expired rules never suppress, so an accepted risk resurfaces (and can fail
    CI again) once its review date passes.
    """
    today = today or datetime.now(timezone.utc).date()
    active = [r for r in rules if not r.expired(today)]
    expired = [r for r in rules if r.expired(today)]
    kept: list[Finding] = []
    for f in result.findings:
        rule = next((r for r in active if r.matches(f, result.target)), None)
        if rule is None:
            kept.append(f)
        else:
            result.suppressed.append((f, rule.reason))
    result.findings = kept
    return expired
