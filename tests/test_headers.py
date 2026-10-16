from recon.modules.headers import analyze


def _rules(findings):
    return {f.rule_id for f in findings}


def test_all_headers_present_is_clean():
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    assert analyze(headers, 200, "https://x") == []


def test_missing_headers_flagged():
    rules = _rules(analyze({}, 200, "https://x"))
    assert "headers.missing-hsts" in rules
    assert "headers.missing-csp" in rules
    assert "headers.missing-nosniff" in rules


def test_tech_disclosure():
    rules = _rules(analyze({"Server": "nginx/1.25"}, 200, "https://x"))
    assert "headers.tech-disclosure-server" in rules


def test_cookie_flags_missing():
    rules = _rules(analyze({"Set-Cookie": "sid=abc; Path=/"}, 200, "https://x"))
    assert "headers.cookie-flags" in rules


def test_cookie_flags_ok():
    hdrs = {"Set-Cookie": "sid=abc; Secure; HttpOnly; SameSite=Lax"}
    rules = _rules(analyze(hdrs, 200, "https://x"))
    assert "headers.cookie-flags" not in rules


# --- M1: CSP / HSTS / cookie quality ---------------------------------------------

from recon.modules.headers import analyze_cookies, analyze_csp, analyze_hsts  # noqa: E402


def _r(findings):
    return {f.rule_id for f in findings}


def test_csp_strict_is_clean():
    pol = ("default-src 'none'; script-src 'nonce-abc' 'strict-dynamic'; "
           "object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
    assert analyze_csp(pol, False, "https://x") == []


def test_csp_unsafe_inline_flagged_unless_nonce_strict_dynamic():
    assert "headers.csp-unsafe-inline" in _r(
        analyze_csp("script-src 'self' 'unsafe-inline'", False, "https://x"))
    assert "headers.csp-unsafe-inline" not in _r(
        analyze_csp("script-src 'nonce-x' 'strict-dynamic' 'unsafe-inline'",
                    False, "https://x"))


def test_csp_wildcard_via_default_src_fallback():
    assert "headers.csp-wildcard-source" in _r(
        analyze_csp("default-src *", False, "https://x"))


def test_csp_unsafe_eval_and_missing_base_uri():
    rules = _r(analyze_csp("default-src 'self'; script-src 'self' 'unsafe-eval'",
                           False, "https://x"))
    assert "headers.csp-unsafe-eval" in rules
    assert "headers.csp-missing-base-uri" in rules


def test_csp_report_only_flag():
    assert "headers.csp-report-only" in _r(
        analyze_csp("default-src 'self'; base-uri 'none'; object-src 'none'",
                    True, "https://x"))


def test_csp_unparseable():
    assert "headers.csp-unparseable" in _r(analyze_csp("   ", False, "https://x"))


def test_report_only_does_not_double_report_missing_csp():
    hdrs = {"Content-Security-Policy-Report-Only": "default-src 'self'; "
            "object-src 'none'; base-uri 'none'"}
    rules = _r(analyze(hdrs, 200, "https://x"))
    assert "headers.missing-csp" not in rules
    assert "headers.csp-report-only" in rules


def test_frame_ancestors_suppresses_missing_xfo():
    hdrs = {"Content-Security-Policy": "default-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'"}
    assert "headers.missing-xfo" not in _r(analyze(hdrs, 200, "https://x"))


def test_report_only_frame_ancestors_does_not_suppress_missing_xfo():
    # Report-Only is never enforced, so its frame-ancestors does not protect
    # against framing; missing X-Frame-Options must still be reported.
    hdrs = {"Content-Security-Policy-Report-Only": "default-src 'self'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"}
    assert "headers.missing-xfo" in _r(analyze(hdrs, 200, "https://x"))


def test_hsts_quality():
    assert "headers.hsts-short-max-age" in _r(analyze_hsts("max-age=300", "https://x"))
    assert analyze_hsts("max-age=63072000; includeSubDomains; preload", "https://x") == []


def test_cookie_samesite_none_insecure_and_session_over_http():
    r1 = _r(analyze_cookies(["sid=a; SameSite=None; HttpOnly"], "https", "x.com"))
    assert "headers.cookie-samesite-none-insecure" in r1
    r2 = _r(analyze_cookies(["sessionid=a; Secure; HttpOnly; SameSite=Lax"], "http", "x.com"))
    assert "headers.cookie-session-over-http" in r2


def test_cookie_broad_domain_and_two_cookies_distinct():
    findings = analyze_cookies(
        ["sid=a; Secure; HttpOnly; SameSite=Lax; Domain=example.com",
         "pref=b; Secure; HttpOnly; SameSite=Lax"], "https", "app.example.com")
    rules = _r(findings)
    assert "headers.cookie-broad-domain" in rules
    # two cookies -> distinct fingerprints
    fps = {f.fingerprint for f in findings}
    assert len(fps) == len(findings)
