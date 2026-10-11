"""Finding model and severity helpers shared across all modules."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Finding:
    """One result produced by a module.

    severity: one of info|low|medium|high|critical.
    """

    module: str
    title: str
    severity: str
    detail: str
    evidence: str = ""
    recommendation: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_RANK:
            self.severity = "info"

    @property
    def rank(self) -> int:
        return SEVERITY_RANK[self.severity]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    target: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add(self, *findings: Finding) -> None:
        self.findings.extend(findings)

    def sorted(self) -> list[Finding]:
        # most severe first, then by module for stable grouping
        return sorted(self.findings, key=lambda f: (-f.rank, f.module))

    def max_rank(self) -> int:
        return max((f.rank for f in self.findings), default=-1)

    def counts(self) -> dict[str, int]:
        c = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            c[f.severity] += 1
        return c
