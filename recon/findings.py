"""Finding model and severity helpers shared across all modules."""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Severity = Literal["info", "low", "medium", "high", "critical"]
SEVERITIES: list[Severity] = ["info", "low", "medium", "high", "critical"]
SEVERITY_RANK: dict[str, int] = {s: i for i, s in enumerate(SEVERITIES)}

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(text: str) -> str:
    """Lowercase ASCII slug used as a fallback rule_id component."""
    text = text.lower()
    # strip common Turkish/Latin diacritics to keep rule ids ASCII-stable
    trans = str.maketrans("çğıöşü", "cgiosu")
    text = text.translate(trans)
    return _SLUG_RE.sub("-", text).strip("-")


@dataclass
class Finding:
    """One result produced by a module.

    rule_id: stable, ASCII, slug-style identifier (e.g. "headers.missing-hsts").
        It is the identity used for SARIF rules, de-duplication and run diffing,
        so it must NOT depend on localized/translated title text. If left empty
        it is derived from module + slug(title) as a fallback.
    severity: one of info|low|medium|high|critical.
    """

    module: str
    title: str
    severity: Severity | str
    detail: str
    evidence: str = ""
    recommendation: str = ""
    rule_id: str = ""
    # msg_key selects the i18n catalogue entry (defaults to rule_id); params fill
    # its {placeholders}. The title/detail/recommendation above are the English
    # canonical fallback used when no catalogue entry exists for the language.
    msg_key: str = ""
    params: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_RANK:
            self.severity = "info"
        if not self.rule_id:
            self.rule_id = f"{self.module}.{slugify(self.title) or 'finding'}"
        if not self.msg_key:
            self.msg_key = self.rule_id

    @property
    def rank(self) -> int:
        return SEVERITY_RANK[self.severity]

    @property
    def fingerprint(self) -> str:
        """Stable hash identifying this specific finding instance.

        Combines the rule_id with the location/evidence key so the same issue
        at the same place keeps one identity across runs (for diffing), while
        the same rule at a different location is a distinct finding.
        """
        key = f"{self.rule_id}|{self.evidence or self.title}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["fingerprint"] = self.fingerprint
        return d


@dataclass
class ScanResult:
    target: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    # (finding, reason) pairs hidden by a suppression file; excluded from counts
    # and CI gates but still listed in reports
    suppressed: list[tuple[Finding, str]] = field(default_factory=list)

    @property
    def suppressed_fingerprints(self) -> set[str]:
        return {f.fingerprint for f, _ in self.suppressed}

    def add(self, *findings: Finding) -> None:
        self.findings.extend(findings)

    def sorted(self) -> list[Finding]:
        # most severe first, then by module for stable grouping
        return sorted(self.findings, key=lambda f: (-f.rank, f.module, f.rule_id))

    def max_rank(self) -> int:
        return max((f.rank for f in self.findings), default=-1)

    def counts(self) -> dict[str, int]:
        c: dict[str, int] = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c
