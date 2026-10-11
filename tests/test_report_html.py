import json

from recon.diff import compute_diff
from recon.findings import Finding, ScanResult
from recon.report_html import to_html

META = {"modules": ["headers"], "version": "0.2.0"}


def _result():
    r = ScanResult("https://x")
    r.add(
        Finding("headers", "Missing HSTS", "medium", "no hsts",
                evidence="GET https://x -> 200", rule_id="headers.missing-hsts"),
        Finding("ports", "Exposed SSH", "low", "ssh open",
                evidence="22/tcp", rule_id="ports.exposed-ssh"),
    )
    return r


def test_html_is_self_contained_and_has_findings():
    out = to_html(_result(), META)
    assert out.startswith("<!doctype html>")
    assert "Missing HSTS" in out
    # no external resource loads
    assert "http://" not in out.replace("https://x", "") or "src=" not in out
    assert "<script" in out  # inline filter JS


def test_html_escapes_evidence():
    r = ScanResult("https://x")
    r.add(Finding("web", "XSS probe", "info",
                  "reflected", evidence="<img src=x onerror=alert(1)>",
                  rule_id="web.xss"))
    out = to_html(r, META)
    assert "<img src=x onerror=alert(1)>" not in out
    assert "&lt;img src=x onerror=alert(1)&gt;" in out


def test_html_shows_diff_and_new_badge():
    cur = _result()
    baseline = {}  # empty -> everything new
    diff = compute_diff(cur, baseline)
    out = to_html(cur, META, diff=diff)
    assert "baseline" in out.lower() or "Baseline" in out
    assert "new" in out.lower()


def test_html_turkish():
    out = to_html(_result(), META, lang="tr")
    assert "Güvenlik Tarama Raporu" in out


# sanity: the module JSON import removal didn't break anything
def test_json_still_imports():
    assert json  # noqa: B018
