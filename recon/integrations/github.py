"""Optional GitHub issue creation from scan findings.

Strictly opt-in. Creates one issue per NEW finding at/above a severity, labelled
`recon` + `severity:<sev>`, with the fingerprint in an HTML comment so the next
run can de-duplicate. Can close issues whose fingerprints are now resolved.

Uses the REST API via requests (no gh CLI dependency). Token from GITHUB_TOKEN.
"""
from __future__ import annotations

import re

import requests

from ..findings import SEVERITY_RANK, Finding

API = "https://api.github.com"
FP_RE = re.compile(r"<!--\s*recon-fingerprint:\s*([0-9a-f]+)\s*-->")


def fingerprint_marker(fp: str) -> str:
    return f"<!-- recon-fingerprint: {fp} -->"


def extract_fingerprint(body: str) -> str | None:
    m = FP_RE.search(body or "")
    return m.group(1) if m else None


def issue_title(f: Finding) -> str:
    return f"[{f.severity.upper()}] {f.title}"


def issue_body(f: Finding, title: str, detail: str, rec: str) -> str:
    parts = [detail]
    if f.evidence:
        parts.append(f"\n**Evidence:** `{f.evidence}`")
    if rec:
        parts.append(f"\n**Recommendation:** {rec}")
    parts.append(f"\n**Rule:** `{f.rule_id}`")
    parts.append("\n" + fingerprint_marker(f.fingerprint))
    return "\n".join(parts)


def select_new(new_findings: list[Finding], min_severity: str) -> list[Finding]:
    threshold = SEVERITY_RANK.get(min_severity.lower(), 0)
    return [f for f in new_findings if f.rank >= threshold]


class GitHubClient:
    def __init__(self, repo: str, token: str):
        self.repo = repo
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        })

    def open_issue_fingerprints(self) -> dict[str, int]:
        """Return {fingerprint: issue_number} for open issues labelled recon."""
        out: dict[str, int] = {}
        url = f"{API}/repos/{self.repo}/issues?labels=recon&state=open&per_page=100"
        r = self.session.get(url, timeout=30)
        if r.status_code != 200:
            return out
        for issue in r.json():
            fp = extract_fingerprint(issue.get("body", ""))
            if fp:
                out[fp] = issue["number"]
        return out

    def create_issue(self, title: str, body: str, labels: list[str]) -> int | None:
        r = self.session.post(f"{API}/repos/{self.repo}/issues", timeout=30,
                              json={"title": title, "body": body, "labels": labels})
        return r.json().get("number") if r.status_code in (200, 201) else None

    def close_issue(self, number: int, comment: str) -> None:
        self.session.post(f"{API}/repos/{self.repo}/issues/{number}/comments",
                         timeout=30, json={"body": comment})
        self.session.patch(f"{API}/repos/{self.repo}/issues/{number}", timeout=30,
                          json={"state": "closed"})


def post_findings(repo: str, token: str, diff, localize_fn, lang: str,
                  min_severity: str = "high", close_resolved: bool = False,
                  client: GitHubClient | None = None) -> dict:
    """Create issues for new findings; optionally close resolved ones.

    localize_fn(finding, lang) -> (title, detail, rec). Returns a summary dict.
    """
    client = client or GitHubClient(repo, token)
    existing = client.open_issue_fingerprints()
    created, skipped, closed = [], [], []

    for f in select_new(list(diff.new), min_severity):
        if f.fingerprint in existing:
            skipped.append(f.fingerprint)
            continue
        title_l, detail_l, rec_l = localize_fn(f, lang)
        num = client.create_issue(
            issue_title(f),
            issue_body(f, title_l, detail_l, rec_l),
            ["recon", f"severity:{f.severity}"],
        )
        if num:
            created.append(num)

    if close_resolved:
        current_new_fps = {f.fingerprint for f in diff.new}
        current_unchanged = {f.fingerprint for f in diff.unchanged}
        live = current_new_fps | current_unchanged
        for fp, number in existing.items():
            if fp not in live:
                client.close_issue(number, "Resolved: recon no longer reports this "
                                           "finding.")
                closed.append(number)

    return {"created": created, "skipped": skipped, "closed": closed}
