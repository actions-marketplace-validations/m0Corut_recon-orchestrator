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
