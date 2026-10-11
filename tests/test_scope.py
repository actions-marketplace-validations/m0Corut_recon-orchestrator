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
