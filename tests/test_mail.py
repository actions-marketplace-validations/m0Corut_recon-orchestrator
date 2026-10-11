from recon.modules.mail import (
    _domain,
    analyze_mta_sts,
    analyze_starttls,
    analyze_tlsrpt,
)


def _rules(findings):
    return {f.rule_id: f for f in findings}


def test_domain():
    assert _domain("https://takip.ajansay.com") == "ajansay.com"


def test_starttls_missing_is_medium():
    r = _rules(analyze_starttls("mx.example.com", {"size", "8bitmime"}))
    assert r["mail.no-starttls"].severity == "medium"


def test_starttls_present_clean():
    assert analyze_starttls("mx.example.com", {"STARTTLS", "size"}) == []
    # case-insensitive
    assert analyze_starttls("mx.example.com", {"starttls"}) == []


def test_mta_sts_missing():
    assert "mail.no-mta-sts" in _rules(analyze_mta_sts(False, False))


def test_mta_sts_txt_without_policy():
    assert "mail.mta-sts-no-policy" in _rules(analyze_mta_sts(True, False))


def test_mta_sts_full_clean():
    assert analyze_mta_sts(True, True) == []


def test_tlsrpt_missing():
    assert "mail.no-tlsrpt" in _rules(analyze_tlsrpt(False))


def test_tlsrpt_present_clean():
    assert analyze_tlsrpt(True) == []
