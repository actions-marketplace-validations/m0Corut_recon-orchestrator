"""Analyst provider protocol, prompt building, and the summarize() dispatcher."""
from __future__ import annotations

from typing import Any

SYSTEM_PROMPT = (
    "You are a security analyst. Given a list of validated scan findings, write a "
    "short executive summary (3-6 sentences) and a prioritised remediation list. "
    "Be concrete and do not invent findings beyond those given. Output plain text."
)


def build_findings_view(result, lang: str, localize_fn,
                        include_evidence: bool = False) -> list[dict]:
    """Minimal, redacted representation sent to the provider."""
    view = []
    for f in result.sorted():
        title, detail, _ = localize_fn(f, lang)
        item: dict[str, Any] = {
            "rule_id": f.rule_id,
            "severity": f.severity,
            "module": f.module,
            "title": title,
            "detail": detail,
        }
        if include_evidence and f.evidence:
            item["evidence"] = f.evidence
        view.append(item)
    return view


def _prompt(view: list[dict]) -> str:
    lines = ["Findings:"]
    for v in view:
        extra = f" | evidence: {v['evidence']}" if "evidence" in v else ""
        lines.append(f"- [{v['severity'].upper()}] ({v['module']}) {v['title']}"
                     f" — {v['detail']}{extra}")
    lines.append("\nWrite the summary and remediation list now.")
    return "\n".join(lines)


def summarize(view: list[dict], provider: str, *, api_key: str,
              model: str | None = None, base_url: str | None = None,
              client=None) -> str:
    """Dispatch to a provider. `client` lets tests inject a fake."""
    prompt = _prompt(view)
    if client is not None:
        return client(SYSTEM_PROMPT, prompt, model)
    if provider == "openai":
        from .openai_compatible import call as openai_call
        return openai_call(SYSTEM_PROMPT, prompt, api_key=api_key,
                           model=model or "gpt-4o-mini",
                           base_url=base_url or "https://api.openai.com/v1")
    if provider == "anthropic":
        from .anthropic import call as anthropic_call
        return anthropic_call(SYSTEM_PROMPT, prompt, api_key=api_key,
                              model=model or "claude-sonnet-4-6")
    raise ValueError(f"unknown analyst provider: {provider}")
