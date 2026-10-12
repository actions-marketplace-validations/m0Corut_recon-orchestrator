from recon.context import ScanContext
from recon.modules.authz import _parse_header, analyze_pair, run


def _rules(findings):
    return {f.rule_id: f for f in findings}


def test_parse_header():
    assert _parse_header("Cookie: session=abc") == {"Cookie": "session=abc"}
    assert _parse_header("") == {}
    assert _parse_header("no-colon") == {}


def test_access_control_gap_detected():
    # protected page returns 200 both with and without creds, similar size -> gap
    f = _rules(analyze_pair("/app", 200, 1000, 200, 980))
    assert f["authz.missing-access-control"].severity == "high"


def test_no_gap_when_anon_blocked():
    # unauthenticated returns 401 -> properly protected
    assert analyze_pair("/app", 200, 1000, 401, 50) == []


def test_no_gap_when_sizes_differ():
    # anon 200 but tiny body (e.g. login redirect page) -> not flagged
    assert analyze_pair("/app", 200, 5000, 200, 200) == []


def test_run_without_credentials_is_info():
    ctx = ScanContext()
    f = _rules(run("https://x", ctx))
    assert "authz.no-credentials" in f


def test_run_without_pages_is_info():
    ctx = ScanContext(auth_header="Cookie: s=1")
    f = _rules(run("https://x", ctx))
    assert "authz.no-pages" in f


def test_unreachable_page_is_reported_not_clean(monkeypatch):
    import requests

    import recon.modules.authz as authz

    def fail(*a, **kw):
        raise requests.ConnectionError("down")
    monkeypatch.setattr(authz, "scoped_get", fail)
    ctx = ScanContext(auth_header="Cookie: s=1", auth_pages=["/admin"])
    f = _rules(run("https://x", ctx))
    assert "authz.page-not-checked" in f
    assert "authz.clean" not in f
    assert "s=1" not in f["authz.page-not-checked"].evidence


def test_out_of_scope_page_is_reported(monkeypatch):
    import recon.modules.authz as authz
    from recon.scope import ScopeViolation

    def deny(*a, **kw):
        raise ScopeViolation("evil.com")
    monkeypatch.setattr(authz, "scoped_get", deny)
    ctx = ScanContext(auth_header="Cookie: s=1", auth_pages=["/admin"])
    f = _rules(run("https://x", ctx))
    assert "out of scope" in f["authz.page-not-checked"].evidence
