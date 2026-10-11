"""Anthropic Messages API provider (no SDK, plain HTTP)."""
from __future__ import annotations

import requests

API = "https://api.anthropic.com/v1/messages"


def call(system: str, prompt: str, *, api_key: str, model: str) -> str:
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    payload = {
        "model": model,
        "max_tokens": 1024,
        "system": system,
        "messages": [{"role": "user", "content": prompt}],
    }
    r = requests.post(API, headers=headers, json=payload, timeout=120)
    r.raise_for_status()
    data = r.json()
    parts = [b.get("text", "") for b in data.get("content", [])
             if b.get("type") == "text"]
    return "".join(parts).strip()
