from recon.modules.headers import analyze


def _rules(findings):
    return {f.rule_id for f in findings}


def test_all_headers_present_is_clean():
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
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
