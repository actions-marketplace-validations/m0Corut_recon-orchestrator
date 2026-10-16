from recon.context import ScanContext
from recon.modules.cms import analyze_wordpress, detect_cms, run


def _rules(findings):
    return {f.rule_id: f for f in findings}


def test_detect_wordpress_from_generator_and_version():
    html = '<meta name="generator" content="WordPress 6.4.2" />'
    assert detect_cms(html, {}) == ("WordPress", "6.4.2")


def test_detect_wordpress_from_paths_without_version():
    assert detect_cms('<link href="/wp-content/themes/x/style.css">', {}) == \
        ("WordPress", "")


def test_detect_from_header_link():
    cms, _ = detect_cms("", {"Link": "<https://s/wp-json/>; rel=\"https://api.w.org/\""})
    assert cms == "WordPress"


def test_detect_joomla_and_drupal():
    assert detect_cms('<meta name="generator" content="Joomla! 4.2">', {})[0] == "Joomla"
    assert detect_cms('<meta name="generator" content="Drupal 10">', {})[0] == "Drupal"


def test_detect_none():
    assert detect_cms("<html><body>plain</body></html>", {}) is None


def test_wordpress_user_enum_and_debug_and_xmlrpc_and_readme():
    probe = {
        "wp-json/wp/v2/users": (200, '[{"id":1,"name":"admin","slug":"admin"}]'),
        "wp-content/debug.log": (200, "[12-Oct-2026] PHP Notice: ..."),
        "xmlrpc.php": (405, ""),
        "readme.html": (200, "<h1>WordPress</h1> Version 6.4.2"),
    }
    f = _rules(analyze_wordpress(probe))
    assert f["cms.wp-user-enum"].severity == "medium"
    assert f["cms.wp-debug-log"].severity == "high"
    assert f["cms.wp-xmlrpc"].severity == "low"
    assert f["cms.wp-readme"].severity == "low"


def test_wordpress_clean_when_paths_absent_or_404():
    probe = {"wp-json/wp/v2/users": (401, ""), "wp-content/debug.log": (404, ""),
             "xmlrpc.php": (404, ""), "readme.html": (404, "")}
    assert analyze_wordpress(probe) == []


def test_run_reports_detection_and_probes(monkeypatch):
    import recon.modules.cms as cms

    responses = {
        "https://wp.test": (200, '<meta name="generator" content="WordPress 6.4">', {}),
        "https://wp.test/wp-json/wp/v2/users": (200, '[{"slug":"admin"}]', {}),
        "https://wp.test/wp-content/debug.log": (404, "", {}),
        "https://wp.test/xmlrpc.php": (405, "", {}),
        "https://wp.test/readme.html": (404, "", {}),
    }

    class R:
        def __init__(self, t):
            self.status_code, self.text, self.headers = t[0], t[1], t[2]

    def fake_get(url, scope, **kw):
        return R(responses[url])
    monkeypatch.setattr(cms, "scoped_get", fake_get)
    f = _rules(run("https://wp.test", ScanContext()))
    assert "cms.detected" in f and "cms.wp-user-enum" in f


def test_run_no_cms(monkeypatch):
    import recon.modules.cms as cms

    class R:
        status_code = 200
        text = "<html>nothing</html>"
        headers: dict = {}
    monkeypatch.setattr(cms, "scoped_get", lambda *a, **k: R())
    assert "cms.none" in _rules(run("https://x", ScanContext()))
