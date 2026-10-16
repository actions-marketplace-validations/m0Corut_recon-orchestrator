from recon.context import ScanContext
from recon.modules.idor import analyze_idor, id_targets, run, swap_id


def _rules(findings):
    return {f.rule_id: f for f in findings}


def test_id_targets_query_and_path_dedup():
    urls = [
        "https://t/invoice?id=1001", "https://t/invoice?id=1002",   # same template -> once
        "https://t/users/5", "https://t/users/6",                    # same template -> once
        "https://t/about", "https://t/search?q=abc",                 # no numeric id
    ]
    t = id_targets(urls)
    kinds = sorted(k for _, k, _ in t)
    assert kinds == ["path", "query:id"]


def test_swap_id_query_and_path():
    assert swap_id("https://t/invoice?id=1001&x=2", "query:id", 1000) == \
        "https://t/invoice?id=1000&x=2"
    assert swap_id("https://t/users/5", "path", 4) == "https://t/users/4"


def test_analyze_flags_distinct_object():
    f = analyze_idor("/invoice", 200, 2000, 1000, 200, 1800)
    assert f is not None and f.severity == "medium" and f.rule_id == "idor.possible"


def test_analyze_ignores_protected_or_missing():
    assert analyze_idor("/x", 200, 2000, 1, 403, 50) is None      # neighbour blocked
    assert analyze_idor("/x", 200, 2000, 1, 404, 0) is None       # neighbour absent
    assert analyze_idor("/x", 401, 10, 1, 200, 2000) is None      # base not accessible


def test_analyze_ignores_same_size_and_tiny_and_errorpage():
    assert analyze_idor("/x", 200, 2000, 1, 200, 2000) is None    # identical -> same template
    assert analyze_idor("/x", 200, 40, 1, 200, 45) is None        # tiny bodies
    assert analyze_idor("/x", 200, 5000, 1, 200, 120) is None     # ratio too different -> error page


def test_run_no_targets():
    assert "idor.no-targets" in _rules(run("https://t", ScanContext()))


def test_run_uses_auth_header_and_flags(monkeypatch):
    import recon.modules.idor as idor
    seen_headers = []

    class R:
        def __init__(self, n):
            self.status_code = 200
            self.content = b"x" * n

    def fake_get(url, scope, *, timeout, auth_headers=None, limiter=None):
        seen_headers.append(auth_headers)
        n = 2000 if url.endswith("1001") else 1700   # neighbour is a distinct object
        return R(n)
    monkeypatch.setattr(idor, "scoped_get", fake_get)
    ctx = ScanContext(auth_header="Cookie: s=1", idor_urls=["https://t/invoice/1001"])
    f = _rules(run("https://t", ctx))
    assert "idor.possible" in f
    assert {"Cookie": "s=1"} in seen_headers        # session sent


def test_run_uses_crawled_urls(monkeypatch):
    import recon.modules.idor as idor

    class R:
        status_code = 200
        content = b"y" * 1500

    def fake_get(url, scope, **kw):
        return R()
    monkeypatch.setattr(idor, "scoped_get", fake_get)
    ctx = ScanContext()
    ctx.extra["crawled_urls"] = ["https://t/item?id=7"]
    # same size both ids -> no finding, but it did test the crawled URL (clean, not no-targets)
    assert "idor.clean" in _rules(run("https://t", ctx))
