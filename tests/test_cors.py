from recon.context import ScanContext
from recon.modules.cors import analyze_cors, run


def _rules(f):
    return {x.rule_id for x in f}


def test_reflects_origin_with_credentials():
    f = analyze_cors("https://evil.example.com", "https://evil.example.com", "true")
    assert f.rule_id == "cors.reflects-origin-with-credentials" and f.severity == "high"


def test_permissive_wildcard():
    f = analyze_cors("https://evil.example.com", "*", "")
    assert f.rule_id == "cors.permissive-acao" and f.severity == "medium"


def test_reflected_without_credentials_is_medium():
    f = analyze_cors("https://evil.example.com", "https://evil.example.com", "")
    assert f.rule_id == "cors.permissive-acao"


def test_no_acao_or_unrelated_not_flagged():
    assert analyze_cors("https://evil.example.com", None, "") is None
    assert analyze_cors("https://evil.example.com", "https://trusted.site", "") is None


def test_run_clean(monkeypatch):
    import recon.modules.cors as cors

    class R:
        headers: dict = {}
    monkeypatch.setattr(cors, "scoped_get", lambda *a, **k: R())
    assert "cors.clean" in _rules(run("https://t", ScanContext()))
