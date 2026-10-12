from recon.findings import Finding
from recon.i18n import localize
from recon.notify import build_payload, detect_kind, redact, select_new, send

SLACK = "https://hooks.slack.com/services/T0/B0/secret"
DISCORD = "https://discord.com/api/webhooks/1/secret"
TG = "https://api.telegram.org/bot123:ABC/sendMessage?chat_id=-100"


def _findings():
    return [Finding("ports", "Redis open", "high", "d", evidence="SECRET-EVIDENCE",
                    rule_id="ports.notable"),
            Finding("headers", "Missing CSP", "medium", "d", rule_id="headers.missing-csp"),
            Finding("headers", "Server banner", "info", "d", rule_id="headers.banner")]


def test_detect_kind():
    assert detect_kind(SLACK) == "slack"
    assert detect_kind(DISCORD) == "discord"
    assert detect_kind(TG) == "telegram"
    assert detect_kind("https://example.com/hook") == "generic"
    assert detect_kind("https://discord.com/other") == "generic"


def test_select_new_threshold():
    assert [f.rule_id for f in select_new(_findings(), "medium")] == \
        ["ports.notable", "headers.missing-csp"]
    assert len(select_new(_findings(), "info")) == 3


def test_payload_shapes_and_no_evidence():
    fs = _findings()
    slack = build_payload(SLACK, "https://x", fs, "runs/x", localize, "en")
    assert "Redis open" in slack["text"] and "SECRET-EVIDENCE" not in slack["text"]
    assert "content" in build_payload(DISCORD, "https://x", fs, "r", localize, "en")
    tg = build_payload(TG, "https://x", fs, "r", localize, "en")
    assert tg["chat_id"] == "-100"
    generic = build_payload("https://ex.com/h", "https://x", fs, "r", localize, "en")
    assert generic["new_findings"][0]["rule_id"] == "ports.notable"
    assert "SECRET-EVIDENCE" not in str(generic)


def test_turkish_text():
    p = build_payload(SLACK, "https://x", _findings(), "r", localize, "tr")
    assert "yeni bulgu" in p["text"]


def test_send_posts_and_reports_errors_without_secrets(monkeypatch):
    import recon.notify as notify
    calls = []

    class R:
        def __init__(self, code):
            self.status_code = code

    def fake_post(url, json, timeout):
        calls.append((url, json))
        return R(200 if "slack" in url else 500)
    monkeypatch.setattr(notify.requests, "post", fake_post)
    errs = send([SLACK, TG], "https://x", _findings(), "r", localize, "en")
    assert calls[1][0] == "https://api.telegram.org/bot123:ABC/sendMessage"
    assert errs == ["api.telegram.org: HTTP 500"]
    assert "secret" not in redact(SLACK)


def test_cli_suppress_and_notify_end_to_end(tmp_path, monkeypatch):
    import recon.cli as cli
    import recon.notify as notify
    from recon.findings import ScanResult

    def fake_scan(target, mods, ctx, **kw):
        r = ScanResult(target=target)
        r.add(*_findings())
        return r
    monkeypatch.setattr(cli, "run_scan", fake_scan)
    posted = []
    monkeypatch.setattr(notify.requests, "post",
                        lambda url, json, timeout: posted.append(json) or
                        type("R", (), {"status_code": 200})())
    ignore = tmp_path / "ignore.yml"
    ignore.write_text("- rule_id: ports.notable\n  reason: firewalled\n", encoding="utf-8")
    monkeypatch.setenv("HOOK", SLACK)

    rc = cli.main(["https://example.com", "--authorized", "-q", "-m", "headers",
                   "-o", str(tmp_path / "runs"), "--suppress-file", str(ignore),
                   "--notify-env", "HOOK", "--fail-on", "high"])
    # the only high finding is suppressed -> gate passes
    assert rc == 0
    assert len(posted) == 1
    assert "Missing CSP" in posted[0]["text"]
    assert "Redis open" not in posted[0]["text"]

    # second run: nothing new -> no notification
    cli.main(["https://example.com", "--authorized", "-q", "-m", "headers",
              "-o", str(tmp_path / "runs"), "--suppress-file", str(ignore),
              "--notify-env", "HOOK"])
    assert len(posted) == 1
