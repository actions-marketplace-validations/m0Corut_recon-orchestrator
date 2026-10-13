from recon.context import ScanContext
from recon.modules.redirect import analyze_redirect, build_probe, run, select_candidates


def _rules(f):
    return {x.rule_id for x in f}


def test_select_candidates_and_dedup():
    urls = ["https://t/go?next=/a", "https://t/go?next=/b", "https://t/p?page=2",
            "https://t/r?url=/x"]
    cands = select_candidates(urls)
    params = sorted({p for _, p in cands})
    assert params == ["next", "url"]        # page ignored, next deduped


def test_build_probe():
    assert build_probe("https://t/go?next=/a&x=1", "next") == \
        "https://t/go?next=https%3A%2F%2Fexample.org%2Frecon-canary&x=1"


def test_analyze_open_redirect_header():
    f = analyze_redirect("https://t/go?next=...", 302,
                         "https://example.org/recon-canary", "")
    assert f.rule_id == "redirect.open-redirect"


def test_analyze_same_host_not_flagged():
    assert analyze_redirect("https://t/go", 302, "https://t.com/login", "") is None


def test_analyze_same_host_location_with_canary_in_query_not_flagged():
    # Location host is t.com; the canary only appears inside a query param -> NOT
    # an open redirect (the browser would navigate to t.com, not example.org).
    assert analyze_redirect(
        "https://t.com/go?next=x", 302,
        "https://t.com/login?next=https://example.org/recon-canary", "") is None


def test_analyze_meta_js_redirect():
    body = '<meta http-equiv="refresh" content="0;url=https://example.org/recon-canary">'
    assert analyze_redirect("https://t/go", 200, "", body).rule_id == "redirect.open-redirect-meta"


def test_analyze_reflected_only():
    assert analyze_redirect("https://t/go", 200, "",
                            "see https://example.org/recon-canary here").rule_id \
        == "redirect.reflected-not-redirected"


def test_run_no_candidates():
    assert "redirect.no-candidates" in _rules(run("https://t", ScanContext()))
