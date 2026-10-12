import pytest

from recon.context import ScanContext
from recon.engine import run_scan
from recon.scope import Scope, ScopeViolation


def test_exact_host_allowed():
    s = Scope.for_target("https://example.com")
    assert s.allows("example.com")
    assert not s.allows("evil.com")
    assert not s.allows("example.com.evil.com")


def test_wildcard():
    s = Scope(["*.example.com"])
    assert s.allows("api.example.com")
    assert s.allows("example.com")        # apex matches *.example.com
    assert not s.allows("example.org")
    assert not s.allows("notexample.com")


def test_extra_hosts():
    s = Scope.for_target("https://example.com", extra=["api.other.com"])
    assert s.allows("example.com")
    assert s.allows("api.other.com")
    assert not s.allows("www.other.com")


def test_allow_all():
    s = Scope.allow_all()
    assert s.allows("anything.com")
    assert s.allows("10.0.0.1")


def test_check_raises():
    s = Scope.for_target("https://example.com")
    s.check("https://example.com/path")          # ok
    with pytest.raises(ScopeViolation):
        s.check("https://evil.com/")


def test_none_host_denied():
    assert not Scope(["example.com"]).allows(None)


def test_engine_aborts_out_of_scope_target():
    # scope only allows example.com, but we scan evil.com
    ctx = ScanContext(scope=Scope(["example.com"]))
    result = run_scan("https://evil.com", ["headers"], ctx, docker_ok=False)
    assert result.findings == []
    assert any("scope" in e for e in result.errors)


# --- private-address handling -------------------------------------------------

def _fake_resolve(mapping):
    return lambda host: mapping.get(host, [])


def test_wildcard_denies_private_ip_literal():
    s = Scope(["*.example.com", "10.0.0.5"])
    assert s.allows("10.0.0.5")                       # named exactly -> allowed
    assert not Scope(["*.example.com"]).allows("10.0.0.5")


def test_wildcard_host_resolving_private_is_blocked(monkeypatch):
    import recon.scope as scope_mod
    monkeypatch.setattr(scope_mod, "_resolve", _fake_resolve({
        "internal.example.com": ["10.0.0.5"],
        "meta.example.com": ["169.254.169.254"],
        "www.example.com": ["93.184.216.34"],
    }))
    s = Scope(["*.example.com"])
    s.check("https://www.example.com/")
    with pytest.raises(ScopeViolation):
        s.check("https://internal.example.com/")
    with pytest.raises(ScopeViolation):
        s.check("http://meta.example.com/latest/meta-data/")


def test_allow_private_opts_in(monkeypatch):
    import recon.scope as scope_mod
    monkeypatch.setattr(scope_mod, "_resolve",
                        _fake_resolve({"internal.example.com": ["10.0.0.5"]}))
    Scope(["*.example.com"], allow_private=True).check("https://internal.example.com/")


def test_exact_target_skips_resolution(monkeypatch):
    # scanning a local dev server must keep working without --allow-private
    import recon.scope as scope_mod

    def boom(host):
        raise AssertionError("exact host must not be resolved")
    monkeypatch.setattr(scope_mod, "_resolve", boom)
    Scope.for_target("http://localhost:8000").check("http://localhost:8000/x")


# --- credential headers on redirects ----------------------------------------------

class _Resp:
    def __init__(self, status, location=None):
        self.status_code = status
        self.headers = {"Location": location} if location else {}


def _record_gets(monkeypatch, responses):
    import recon.scope as scope_mod
    sent = []

    def fake_get(url, timeout, headers, allow_redirects):
        sent.append((url, dict(headers or {})))
        return responses.pop(0)
    monkeypatch.setattr(scope_mod.requests, "get", fake_get)
    monkeypatch.setattr(scope_mod, "_resolve", lambda h: ["93.184.216.34"])
    return sent


def test_auth_headers_dropped_on_cross_host_redirect(monkeypatch):
    from recon.scope import scoped_get
    sent = _record_gets(monkeypatch, [
        _Resp(302, "https://cdn.example.com/app"), _Resp(200)])
    scoped_get("https://app.example.com/app", Scope(["*.example.com"]),
               auth_headers={"Cookie": "session=secret"})
    assert sent[0][1] == {"Cookie": "session=secret"}
    assert "Cookie" not in sent[1][1]


def test_auth_headers_dropped_on_https_downgrade(monkeypatch):
    from recon.scope import scoped_get
    sent = _record_gets(monkeypatch, [
        _Resp(301, "http://example.com/app"), _Resp(200)])
    scoped_get("https://example.com/app", Scope(["example.com"]),
               auth_headers={"Authorization": "Bearer t"})
    assert "Authorization" not in sent[1][1]


def test_auth_headers_kept_on_same_origin_redirect(monkeypatch):
    from recon.scope import scoped_get
    sent = _record_gets(monkeypatch, [_Resp(302, "/dashboard"), _Resp(200)])
    scoped_get("https://example.com/app", Scope(["example.com"]),
               auth_headers={"Cookie": "s=1"})
    assert sent[1] == ("https://example.com/dashboard", {"Cookie": "s=1"})
