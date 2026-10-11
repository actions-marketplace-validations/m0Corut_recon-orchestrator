import pytest

from recon.context import ScanContext
from recon.engine import resolve_modules, run_scan
from recon.findings import Finding


def test_resolve_all_expands_to_default_order():
    from recon.modules import DEFAULT_ORDER
    assert resolve_modules("all") == DEFAULT_ORDER


def test_resolve_csv():
    assert resolve_modules("headers,cors") == ["headers", "cors"]


def test_resolve_unknown_raises():
    with pytest.raises(ValueError):
        resolve_modules("headers,nope")


def test_context_get_typed_and_extra():
    ctx = ScanContext(rate=5)
    assert ctx.get("rate") == 5
    assert ctx.get("http_timeout") == 15
    ctx.extra["custom"] = "x"
    assert ctx.get("custom") == "x"
    assert ctx.get("missing", "def") == "def"


def test_run_scan_skips_docker_when_unavailable():
    ctx = ScanContext()
    events = []
    result = run_scan("https://example.com", ["ports", "tls"], ctx,
                      docker_ok=False, on_event=lambda k, m: events.append((k, m)))
    # both are docker modules -> skipped, recorded as errors, no crash
    assert any("ports" in e for e in result.errors)
    assert ("skip", "ports") in events


def test_run_scan_module_exception_isolated(monkeypatch):
    # a module that raises should be caught and recorded, not propagate
    import recon.modules.headers as headers
    monkeypatch.setattr(headers, "run",
                        lambda t, c: (_ for _ in ()).throw(RuntimeError("boom")))
    ctx = ScanContext()
    result = run_scan("https://example.com", ["headers"], ctx, docker_ok=True)
    assert any("boom" in e for e in result.errors)
