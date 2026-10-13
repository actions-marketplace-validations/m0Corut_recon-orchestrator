from recon.context import ScanContext
from recon.modules._pages import parse_html
from recon.modules.csrf import analyze_forms, classify_form, run


def _rules(findings):
    return {f.rule_id for f in findings}


def _forms(html):
    return parse_html(html).forms


def test_classify():
    f = _forms('<form method=post action=/pay><input name=amt></form>')[0]
    assert classify_form(f, "t.com") == "state-changing"
    lf = _forms('<form method=post><input type=password name=pw></form>')[0]
    assert classify_form(lf, "t.com") == "login"
    sf = _forms('<form method=get><input name=q></form>')[0]
    assert classify_form(sf, "t.com") == "search"
    off = _forms('<form method=post action="https://other.com/x"><input name=a></form>')[0]
    assert classify_form(off, "t.com") == "ignored"
    # protocol-relative //host points off-host, must be ignored (not same-host)
    proto = _forms('<form method=post action="//other.com/x"><input name=a></form>')[0]
    assert classify_form(proto, "t.com") == "ignored"
    # protocol-relative to the SAME host is still state-changing
    same = _forms('<form method=post action="//t.com/pay"><input name=a></form>')[0]
    assert classify_form(same, "t.com") == "state-changing"


def test_state_changing_without_token_medium():
    forms = _forms('<form method=post action=/pay><input name=amt></form>')
    r = _rules(analyze_forms("https://t.com/", forms, False, False, "t.com"))
    assert "csrf.form-without-token" in r


def test_token_field_makes_it_clean():
    forms = _forms('<form method=post action=/pay><input name=amt>'
                   '<input type=hidden name=_token value=x></form>')
    assert analyze_forms("https://t.com/", forms, False, False, "t.com") == []


def test_meta_token_counts_as_protection():
    forms = _forms('<form method=post action=/pay><input name=amt></form>')
    assert analyze_forms("https://t.com/", forms, True, False, "t.com") == []


def test_samesite_only_downgrades_to_low():
    forms = _forms('<form method=post action=/pay><input name=amt></form>')
    r = _rules(analyze_forms("https://t.com/", forms, False, True, "t.com"))
    assert "csrf.form-without-token-samesite-only" in r


def test_login_form_without_token_info():
    forms = _forms('<form method=post action=/login><input type=password name=pw></form>')
    r = _rules(analyze_forms("https://t.com/", forms, False, False, "t.com"))
    assert "csrf.login-form-without-token" in r


def test_run_no_forms(monkeypatch):
    import recon.modules.csrf as csrf
    monkeypatch.setattr(csrf, "scoped_get", lambda *a, **k: type(
        "R", (), {"headers": {}, "raw": None, "status_code": 200})())
    monkeypatch.setattr(csrf, "fetch_pages",
                        lambda *a, **k: iter([("https://t.com/", 200, {}, "<html>hi</html>")]))
    assert "csrf.no-forms-found" in _rules(run("https://t.com", ScanContext()))
