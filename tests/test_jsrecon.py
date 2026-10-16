from recon.context import ScanContext
from recon.modules.jsrecon import (
    analyze_sourcemap,
    detect_libraries,
    evaluate_libraries,
    mask,
    run,
    scan_secrets,
    sourcemap_url,
)

DB = {"jquery": [{"below": "3.5.0", "severity": "medium", "note": "XSS"}],
      "angularjs": [{"below": "1.999.0", "severity": "low", "note": "end-of-life"}],
      "lodash": [{"below": "4.17.21", "severity": "high", "note": "proto pollution"}]}


def _rules(f):
    return {x.rule_id for x in f}


def test_mask_hides_value():
    assert mask("AKIAIOSFODNN7EXAMPLE") == "AKIA****PLE"
    assert "IOSFODNN7" not in mask("AKIAIOSFODNN7EXAMPLE")


def test_scan_secrets_masks_and_flags():
    js = 'var k="AKIAIOSFODNN7EXAMPLE"; var g="AIza' + "a" * 35 + '";'
    f = scan_secrets(js, "https://t/app.js")
    rules = _rules(f)
    assert "jsrecon.secret-aws-access-key" in rules
    assert "jsrecon.secret-google-api-key" in rules
    # raw value never in any finding dict
    for finding in f:
        assert "IOSFODNN7EXAMPLE" not in str(finding.to_dict())


def test_jwt_and_generic_entropy_gate():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEFghiJKLmno"
    assert "jsrecon.secret-jwt" in _rules(scan_secrets(f'var t="{jwt}";', "https://t/a.js"))
    # low-entropy placeholder not flagged
    assert scan_secrets('const api_key = "xxxxxxxxxxxxxxxxxxxxxx";', "https://t/a.js") == []


def test_firebase_config_info():
    js = 'const c={"apiKey":"x","databaseURL":"https://x.firebaseio.com"};'
    assert "jsrecon.firebase-config" in _rules(scan_secrets(js, "https://t/a.js"))


def test_detect_libraries_filename_and_comment():
    assert ("jquery", "1.12.4", "filename") in detect_libraries("", "https://t/jquery-1.12.4.min.js")
    libs = detect_libraries("/*! jQuery v3.7.1 */", "https://t/bundle.js")
    assert ("jquery", "3.7.1", "content") in libs


def test_evaluate_libraries_vulnerable_and_clean_and_eol():
    assert "jsrecon.vulnerable-library-jquery" in _rules(
        evaluate_libraries([("jquery", "1.12.4", "filename")], DB, "https://t/a.js"))
    assert evaluate_libraries([("jquery", "3.7.1", "filename")], DB, "https://t/a.js") == []
    assert "jsrecon.eol-library" in _rules(
        evaluate_libraries([("angularjs", "1.8.2", "content")], DB, "https://t/a.js"))


def test_version_comparison_edge_cases():
    # exact fixed version (fewer components) must NOT be flagged (3.5 == 3.5.0)
    assert evaluate_libraries([("jquery", "3.5", "filename")], DB, "https://t/a.js") == []
    assert evaluate_libraries([("jquery", "3.5.0", "filename")], DB, "https://t/a.js") == []
    # pre-release / odd strings must not crash and compare numerically
    assert "jsrecon.vulnerable-library-jquery" in _rules(
        evaluate_libraries([("jquery", "3.4.9-beta", "content")], DB, "https://t/a.js"))
    assert evaluate_libraries([("jquery", "10.0.0", "content")], DB, "https://t/a.js") == []


def test_no_raw_secret_in_any_field():
    secret = "sk_live_" + "A1b2C3d4E5f6G7h8I9j0K1l2"
    js = f'const stripe = "{secret}";'
    for finding in scan_secrets(js, "https://t/pay.js"):
        blob = str(finding.to_dict())
        assert secret not in blob
        assert secret[8:] not in blob


def test_sourcemap():
    assert sourcemap_url("https://t/a.js", "x") == "https://t/a.js.map"
    assert sourcemap_url("https://t/a.js", "//# sourceMappingURL=a.js.map") == "https://t/a.js.map"
    assert analyze_sourcemap("https://t/a.js.map", 200,
                             '{"version":3,"sources":["a.ts"]}') is not None
    assert analyze_sourcemap("https://t/a.js.map", 200, "<html>404</html>") is None
    assert analyze_sourcemap("https://t/a.js.map", 404, "") is None


def test_run_no_scripts(monkeypatch):
    import recon.modules.jsrecon as js
    monkeypatch.setattr(js, "scoped_get", lambda *a, **k: type(
        "R", (), {"text": "<html>no scripts</html>", "status_code": 200})())
    assert "jsrecon.no-scripts" in _rules(run("https://t", ScanContext()))
