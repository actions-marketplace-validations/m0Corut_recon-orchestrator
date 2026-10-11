from recon.modules.dns import (
    _domain,
    analyze_caa,
    analyze_dkim,
    analyze_dmarc,
    analyze_spf,
)


def _rules(findings):
    return {f.rule_id: f for f in findings}


def test_domain_extraction():
    assert _domain("https://takip.ajansay.com") == "ajansay.com"
    assert _domain("example.com") == "example.com"


# SPF
def test_spf_missing_with_mx():
    r = _rules(analyze_spf([], has_mx=True))
    assert r["dns.spf-missing"].severity == "medium"


def test_spf_missing_without_mx_is_silent():
    assert analyze_spf([], has_mx=False) == []


def test_spf_allow_all_is_high():
    r = _rules(analyze_spf(["v=spf1 +all"], has_mx=True))
    assert r["dns.spf-allow-all"].severity == "high"


def test_spf_softfail_is_low():
    r = _rules(analyze_spf(["v=spf1 include:_spf.google.com ~all"], has_mx=True))
    assert r["dns.spf-softfail"].severity == "low"


def test_spf_hardfail_is_clean():
    assert analyze_spf(["v=spf1 -all"], has_mx=True) == []


# DMARC
def test_dmarc_missing():
    r = _rules(analyze_dmarc([]))
    assert r["dns.dmarc-missing"].severity == "medium"


def test_dmarc_policy_none_and_no_rua():
    r = _rules(analyze_dmarc(["v=DMARC1; p=none"]))
    assert "dns.dmarc-policy-none" in r
    assert "dns.dmarc-no-rua" in r


def test_dmarc_reject_with_rua_clean():
    assert analyze_dmarc(["v=DMARC1; p=reject; rua=mailto:x@y.com"]) == []


# CAA
def test_caa_missing():
    assert _rules(analyze_caa(False))["dns.caa-missing"].severity == "info"


def test_caa_present_clean():
    assert analyze_caa(True) == []


# DKIM
def test_dkim_present():
    assert "dns.dkim-present" in _rules(analyze_dkim(["google"]))


def test_dkim_none():
    assert "dns.dkim-none" in _rules(analyze_dkim([]))
