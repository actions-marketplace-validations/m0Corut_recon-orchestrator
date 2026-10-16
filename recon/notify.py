"""Webhook notifications for new findings (Slack, Discord, Telegram, generic).

Scheduled scans are only useful if someone sees the result. This posts a short
summary when a scan produces NEW findings at or above a severity, so a weekly
CI run stays silent until something changes for the worse.

Privacy: messages carry the target, counts and finding titles/rule ids only,
never evidence (which can contain tokens, internal paths or response bodies).
The webhook URL itself is a secret; prefer ``--notify-env VAR`` over putting it
on the command line.

The kind is detected from the URL:
  hooks.slack.com/...            -> Slack incoming webhook  {"text": ...}
  discord.com/api/webhooks/...   -> Discord webhook         {"content": ...}
  api.telegram.org/bot<T>/sendMessage?chat_id=<ID>
                                 -> Telegram Bot API        {"chat_id", "text"}
  anything else                  -> generic JSON            (full payload)
"""
from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import requests

from .findings import SEVERITY_RANK, Finding

MAX_LISTED = 10


def detect_kind(url: str) -> str:
    p = urlparse(url)
    host = (p.hostname or "").lower()
    if host == "hooks.slack.com":
        return "slack"
    if host in ("discord.com", "discordapp.com") and p.path.startswith("/api/webhooks/"):
        return "discord"
    if host == "api.telegram.org" and p.path.endswith("/sendMessage"):
        return "telegram"
    return "generic"


def select_new(new: list[Finding], min_severity: str) -> list[Finding]:
    threshold = SEVERITY_RANK.get(min_severity.lower(), SEVERITY_RANK["medium"])
    return [f for f in new if f.rank >= threshold]


def build_text(target: str, findings: list[Finding], run_dir: str,
               localize, lang: str) -> str:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    order = sorted(counts, key=lambda s: -SEVERITY_RANK[s])
    summary = ", ".join(f"{counts[s]} {s}" for s in order)
    header = (f"recon-orchestrator: {len(findings)} new finding(s) on {target} ({summary})"
              if lang != "tr" else
              f"recon-orchestrator: {target} üzerinde {len(findings)} yeni bulgu ({summary})")
    lines = [header]
    for f in findings[:MAX_LISTED]:
        title, _, _ = localize(f, lang)
        lines.append(f"• [{f.severity.upper()}] {title} ({f.rule_id})")
    if len(findings) > MAX_LISTED:
        more = len(findings) - MAX_LISTED
        lines.append(f"… +{more} more" if lang != "tr" else f"… +{more} daha")
    lines.append(f"report: {run_dir}" if lang != "tr" else f"rapor: {run_dir}")
    return "\n".join(lines)


def build_payload(url: str, target: str, findings: list[Finding], run_dir: str,
                  localize, lang: str) -> dict:
    text = build_text(target, findings, run_dir, localize, lang)
    kind = detect_kind(url)
    if kind == "slack":
        return {"text": text}
    if kind == "discord":
        return {"content": text[:2000]}           # Discord message limit
    if kind == "telegram":
        chat_id = (parse_qs(urlparse(url).query).get("chat_id") or [""])[0]
        return {"chat_id": chat_id, "text": text[:4096]}
    return {
        "tool": "recon-orchestrator",
        "target": target,
        "run_dir": run_dir,
        "text": text,
        "new_findings": [
            {"rule_id": f.rule_id, "severity": f.severity,
             "title": localize(f, lang)[0], "module": f.module,
             "fingerprint": f.fingerprint}
            for f in findings
        ],
    }


def _endpoint(url: str) -> str:
    """Telegram takes chat_id in the body; strip it from the query we post to."""
    if detect_kind(url) == "telegram":
        p = urlparse(url)
        return p._replace(query="").geturl()
    return url


def redact(url: str) -> str:
    """Host only, for log lines: webhook paths and queries are secrets."""
    return urlparse(url).hostname or "webhook"


def send(urls: list[str], target: str, findings: list[Finding], run_dir: str,
         localize, lang: str, timeout: int = 10) -> list[str]:
    """POST to each URL; return a list of error strings (empty on success)."""
    errors: list[str] = []
    for url in urls:
        payload = build_payload(url, target, findings, run_dir, localize, lang)
        try:
            r = requests.post(_endpoint(url), json=payload, timeout=timeout)
            if r.status_code >= 400:
                errors.append(f"{redact(url)}: HTTP {r.status_code}")
        except requests.RequestException as e:
            errors.append(f"{redact(url)}: {type(e).__name__}")
    return errors
