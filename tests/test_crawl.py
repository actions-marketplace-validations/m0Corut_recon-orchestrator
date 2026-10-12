from recon.context import ScanContext
from recon.crawl import crawl, parse_katana, with_params
from recon.modules.crawl import build_findings


def test_parse_katana_keeps_in_host_http_only_dedup():
    out = """https://t.com/
https://t.com/a?x=1
https://t.com/a?x=1
http://t.com/b
https://evil.com/c
ftp://t.com/d
https://sub.t.com/e
not a url
"""
    assert parse_katana(out, "t.com") == [
        "https://t.com/", "https://t.com/a?x=1", "http://t.com/b"]


def test_with_params():
    assert with_params(["https://t/", "https://t/a?x=1", "https://t/b"]) == \
        ["https://t/a?x=1"]


def test_crawl_no_runner_or_tool_returns_empty():
    class NoKatana:
        def can_run(self, tool):
            return False
    assert crawl("https://t", None) == []
    assert crawl("https://t", NoKatana()) == []


def test_crawl_invokes_katana_scoped_and_caps(monkeypatch):
    seen = {}

    class R:
        def can_run(self, tool):
            return tool == "katana"

        def run_capture(self, tool, args, timeout):
            seen["args"] = args
            return "\n".join(f"https://t.com/p{i}?id={i}" for i in range(10)) + "\n"
    urls = crawl("https://t.com/app", R(), rate=7, max_urls=4)
    assert len(urls) == 4
    a = seen["args"]
    assert a[a.index("-fs") + 1] == "fqdn"            # scoped to exact host
    assert a[a.index("-rl") + 1] == "7"               # rate wired through


def test_module_build_findings_surface():
    urls = ["https://t.com/", "https://t.com/s?q=1", "https://t.com/p?id=2"]
    f = build_findings("https://t.com", urls)[0]
    assert f.severity == "info" and f.rule_id == "crawl.surface"
    assert f.params == {"host": "t.com", "urls": 3, "params": 2}


def test_module_empty():
    assert build_findings("https://t.com", [])[0].rule_id == "crawl.empty"


def test_module_run_stores_urls_on_context(monkeypatch):
    import recon.modules.crawl as mod
    monkeypatch.setattr(mod, "crawl", lambda *a, **k: ["https://t/a?x=1"])
    ctx = ScanContext()
    mod.run("https://t", ctx)
    assert ctx.extra["crawled_urls"] == ["https://t/a?x=1"]


def test_crawl_headless_adds_browser_flags(monkeypatch):
    seen = {}

    class R:
        def can_run(self, tool):
            return tool == "katana"

        def run_capture(self, tool, args, timeout):
            seen["args"] = args
            return ""
    crawl("https://t.com", R(), headless=True)
    assert "-headless" in seen["args"] and "-nos" in seen["args"]
    # default stays non-headless
    crawl("https://t.com", R())
    assert "-headless" not in seen["args"]


def test_module_passes_headless_from_context(monkeypatch):
    import recon.modules.crawl as mod
    seen = {}
    monkeypatch.setattr(mod, "crawl", lambda *a, **k: seen.update(k) or [])
    mod.run("https://t", ScanContext(crawl_headless=True))
    assert seen["headless"] is True
