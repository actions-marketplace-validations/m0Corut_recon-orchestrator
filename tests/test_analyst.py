import pytest

from recon.analyst.base import build_findings_view, summarize
from recon.findings import Finding, ScanResult


def _localize(f, lang):
    return f.title, f.detail, f.recommendation


def _result():
    r = ScanResult("https://x")
    r.add(Finding("web", "RCE", "high", "bad thing",
                  evidence="secret-cookie=abc", rule_id="web.rce"))
    return r


def test_view_redacts_evidence_by_default():
    view = build_findings_view(_result(), "en", _localize)
    assert view[0]["rule_id"] == "web.rce"
    assert "evidence" not in view[0]


def test_view_includes_evidence_when_opted_in():
    view = build_findings_view(_result(), "en", _localize, include_evidence=True)
    assert view[0]["evidence"] == "secret-cookie=abc"


def test_summarize_uses_injected_client():
    captured = {}

    def fake_client(system, prompt, model):
        captured["system"] = system
        captured["prompt"] = prompt
        return "SUMMARY TEXT"

    view = build_findings_view(_result(), "en", _localize)
    out = summarize(view, "openai", api_key="x", client=fake_client)
    assert out == "SUMMARY TEXT"
    assert "RCE" in captured["prompt"]
    # redacted: evidence must not be in the prompt
    assert "secret-cookie" not in captured["prompt"]


def test_summarize_unknown_provider():
    with pytest.raises(ValueError):
        summarize([], "bogus", api_key="x")
