from recon.context import ScanContext
from recon.modules.hostinject import (
    CANARY,
    analyze_cacheability,
    analyze_reflection,
    build_variants,
    run,
)


def _rules(f):
    return {x.rule_id for x in f}


def test_build_variants():
    v = build_variants()
    assert "x-forwarded-host" in v and v["x-forwarded-host"]["X-Forwarded-Host"] == CANARY


def test_reflection_in_location():
    f = analyze_reflection("baseline", 302, f"https://{CANARY}/reset", "", {})
    assert "hostinject.reflected-in-location" in _rules(f)


def test_reflection_in_resource_url_and_cacheable_escalates():
    body = f'<link rel="canonical" href="https://{CANARY}/">'
    plain = analyze_reflection("baseline", 200, "", body, {})
    rr = "hostinject.reflected-in-resource-url"
    assert next(x for x in plain if x.rule_id == rr).severity == "medium"
    cached = analyze_reflection("baseline", 200, "", body, {"Cache-Control": "public, s-maxage=60"})
    assert next(x for x in cached if x.rule_id == rr).severity == "high"
    assert "hostinject.cacheable-response" in _rules(cached)


def test_reflection_in_body_low():
    f = analyze_reflection("baseline", 200, "", f"welcome {CANARY} user", {})
    assert "hostinject.reflected-in-body" in _rules(f)


def test_baseline_already_contains_canary_suppresses():
    assert analyze_reflection(f"home {CANARY}", 200, "", f"x {CANARY}", {}) == []


def test_findings_marked_signal():
    f = analyze_reflection("baseline", 302, f"https://{CANARY}/x", "", {})
    assert all(x.params.get("signal") for x in f)


def test_cacheability():
    assert analyze_cacheability({"Cache-Control": "public"}) is True
    assert analyze_cacheability({"Age": "10"}) is True
    assert analyze_cacheability({"X-Cache": "HIT"}) is True
    assert analyze_cacheability({"Cache-Control": "no-store"}) is False
    # a no-store response behind a CDN still reports its cache layer, but is not cacheable
    assert analyze_cacheability({"Cache-Control": "no-store", "cf-cache-status": "DYNAMIC"}) is False
    assert analyze_cacheability({"Cache-Control": "private, max-age=60"}) is False
    assert analyze_cacheability({"cf-cache-status": "DYNAMIC"}) is False
    assert analyze_cacheability({"cf-cache-status": "HIT"}) is True


def test_run_no_reflection(monkeypatch):
    import recon.modules.hostinject as hi

    class R:
        status_code = 200
        headers: dict = {}
        text = "<html>clean</html>"
    monkeypatch.setattr(hi, "scoped_get", lambda *a, **k: R())
    assert "hostinject.no-reflection" in _rules(run("https://t", ScanContext()))


def test_run_cache_buster_applied(monkeypatch):
    import recon.modules.hostinject as hi
    seen = []

    class R:
        status_code = 200
        headers: dict = {}
        text = ""
    def fake_get(url, scope, **kw):
        seen.append(url)
        return R()
    monkeypatch.setattr(hi, "scoped_get", fake_get)
    run("https://t/app", ScanContext())
    assert all("rc=" in u for u in seen) and len(seen) >= 2
