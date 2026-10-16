import base64
import json

from recon.modules._pages import parse_html
from recon.modules.passive import (
    analyze_cross_domain_js,
    analyze_internal_disclosure,
    analyze_jwt,
    analyze_mixed_content,
    analyze_robots,
    analyze_security_txt,
    analyze_session_in_url,
    analyze_sri,
)


def _rules(f):
    return {x.rule_id for x in f}


def _jwt(header, payload):
    def b(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
    return f"{b(header)}.{b(payload)}.sig"


def test_jwt_alg_none_and_no_exp():
    r = _rules(analyze_jwt(_jwt({"alg": "none"}, {"sub": 1}), "cookie"))
    assert "passive.jwt-alg-none" in r and "passive.jwt-no-exp" in r


def test_jwt_sensitive_claims_and_long_lived():
    tok = _jwt({"alg": "HS256"}, {"email": "a@b.com", "iat": 0, "exp": 9999999})
    r = _rules(analyze_jwt(tok, "body"))
    assert "passive.jwt-sensitive-claims" in r and "passive.jwt-long-lived" in r


def test_jwt_clean_and_garbage():
    tok = _jwt({"alg": "HS256"}, {"sub": 1, "iat": 0, "exp": 100})
    assert analyze_jwt(tok, "x") == []
    assert analyze_jwt("eyJnot.a.jwt", "x") == []
    assert analyze_jwt("not-a-jwt", "x") == []


def test_jwt_in_url():
    tok = _jwt({"alg": "HS256"}, {"sub": 1, "iat": 0, "exp": 100})
    assert "passive.jwt-in-url" in _rules(analyze_jwt(tok, "https://t/x", in_url=True))


def test_sri_missing_third_party_only():
    scripts = parse_html('<script src="https://cdn.other/a.js"></script>'
                         '<script src="https://cdn.other/b.js" integrity="sha384-x"></script>'
                         '<script src="https://t.com/local.js"></script>').scripts
    r = analyze_sri(scripts, [], "t.com", "https://t.com/")
    srcs = {f.params["src"] for f in r}
    assert srcs == {"https://cdn.other/a.js"}


def test_cross_domain_js():
    scripts = parse_html('<script src="https://cdn.a/x.js"></script>'
                         '<script src="https://t.com/y.js"></script>').scripts
    r = analyze_cross_domain_js(scripts, "t.com", "https://t.com/")
    assert {f.params["host"] for f in r} == {"cdn.a"}


def test_session_in_url():
    r = _rules(analyze_session_in_url(["https://t/p?PHPSESSID=abc", "https://t/q?page=2"]))
    assert "passive.session-id-in-url" in r


def test_internal_disclosure():
    r = _rules(analyze_internal_disclosure(
        "err at /var/www/app, host db.internal, ip 10.0.0.5 "
        "Traceback (most recent call last):", "https://t/"))
    assert {"passive.private-ip-disclosure", "passive.internal-hostname-disclosure",
            "passive.absolute-path-disclosure", "passive.stack-trace"} <= r
    # public IP not flagged
    assert "passive.private-ip-disclosure" not in _rules(
        analyze_internal_disclosure("ip 8.8.8.8", "https://t/"))


def test_mixed_content():
    scripts = parse_html('<script src="http://cdn/x.js"></script>').scripts
    assert "passive.mixed-content-active" in _rules(
        analyze_mixed_content(scripts, [], "https", "https://t/"))
    assert analyze_mixed_content(scripts, [], "http", "http://t/") == []


def test_robots_and_security_txt():
    assert "passive.robots-reveals-paths" in _rules(
        analyze_robots(200, "User-agent: *\nDisallow: /admin/\nDisallow: /public/"))
    assert "passive.robots-missing" in _rules(analyze_robots(404, ""))
    assert "passive.security-txt-missing" in _rules(analyze_security_txt(404, ""))
    assert "passive.security-txt-expired" in _rules(
        analyze_security_txt(200, "Contact: mailto:a@b.com\nExpires: 2020-01-01T00:00:00Z"))
    # date-only Expires is naive -> must not crash, still flagged expired
    assert "passive.security-txt-expired" in _rules(
        analyze_security_txt(200, "Contact: mailto:a@b.com\nExpires: 2020-01-01"))
    # non-ISO / garbage Expires -> no crash, no expired finding
    assert "passive.security-txt-expired" not in _rules(
        analyze_security_txt(200, "Contact: mailto:a@b.com\nExpires: Wed, 01 Jan 2020 00:00:00 GMT"))
    # future Expires -> not flagged
    assert "passive.security-txt-expired" not in _rules(
        analyze_security_txt(200, "Contact: mailto:a@b.com\nExpires: 2999-01-01T00:00:00Z"))


def test_html_comment_sensitive_and_passive_mixed():
    r = _rules(analyze_internal_disclosure("<!-- TODO: remove debug password -->", "https://t/"))
    assert "passive.html-comment-sensitive" in r
    assert analyze_internal_disclosure("<!-- harmless note -->", "https://t/") == []
    links = parse_html('<link rel="stylesheet" href="http://cdn/x.css">').links
    assert "passive.mixed-content-passive" in _rules(
        analyze_mixed_content([], links, "https", "https://t/"))
