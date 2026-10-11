from recon.findings import Finding
from recon.i18n import localize, ui


def test_english_falls_back_to_authored_text():
    f = Finding("ports", "Exposed service: 22/ssh", "low", "reachable",
                rule_id="ports.exposed-ssh", msg_key="ports.exposed",
                params={"port": 22, "service": "ssh"})
    title, detail, rec = localize(f, "en")
    # no English catalogue entry -> authored English text is used
    assert title == "Exposed service: 22/ssh"


def test_turkish_uses_catalogue_with_params():
    f = Finding("ports", "Exposed service: 22/ssh", "low", "reachable",
                rule_id="ports.exposed-ssh", msg_key="ports.exposed",
                params={"port": 22, "service": "ssh"})
    title, detail, rec = localize(f, "tr")
    assert title == "Açık servis: 22/ssh"
    assert "internetten erişilebilir" in detail


def test_unknown_key_falls_back():
    f = Finding("x", "Some title", "info", "some detail", rule_id="x.unknown")
    assert localize(f, "tr") == ("Some title", "some detail", "")


def test_missing_param_falls_back_gracefully():
    # template references {header} but params lacks it -> fallback to authored
    f = Finding("headers", "Technology disclosure: Server", "info", "Server: nginx",
                rule_id="headers.tech-disclosure-server",
                msg_key="headers.tech-disclosure", params={})
    title, _, _ = localize(f, "tr")
    assert title == "Technology disclosure: Server"


def test_ui_defaults_to_english():
    assert ui("xx")["report_title"] == "Security Scan Report"
    assert ui("tr")["report_title"] == "Güvenlik Tarama Raporu"
