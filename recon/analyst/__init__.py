"""Optional, opt-in analyst layer: summarize & prioritise findings with an LLM.

Strictly opt-in (``--analyst <provider>``), never required for detection. Sends
only minimal, redacted finding metadata (rule_id, severity, title, module, and a
redacted detail) — no evidence and no hostnames unless explicitly allowed. All
providers use plain HTTP (requests), no vendor SDKs. The trust story is
"local, free, no phone-home by default".
"""
from __future__ import annotations

from .base import build_findings_view, summarize

__all__ = ["build_findings_view", "summarize"]
