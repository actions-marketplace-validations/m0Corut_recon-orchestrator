import json

import recon.modules.discover as disc
from recon.context import ScanContext
from recon.modules.discover import (
    classify,
    host_findings,
    parse_certspotter,
    parse_crtsh,
    parse_subfinder,
)

PUBLIC = ["93.184.216.34"]


def _rules(findings):
    return {f.rule_id: f for f in findings}


def test_parse_crtsh_filters_and_normalizes():
    rows = [{"name_value": "*.example.com\nwww.example.com"},
            {"name_value": "API.example.com."},
            {"name_value": "evil-example.com"},
            {"name_value": "admin@example.com"}]
    assert parse_crtsh(json.dumps(rows), "example.com") == \
        {"example.com", "www.example.com", "api.example.com"}
    assert parse_crtsh("not json", "example.com") == set()


def test_parse_subfinder_plain_and_json():
    out = 'a.example.com\n{"host":"b.example.com"}\nother.org\n'
    assert parse_subfinder(out, "example.com") == {"a.example.com", "b.example.com"}


def test_classify_third_party_and_private():
    h = classify("shop.example.com", "example.com", PUBLIC, ["shops.myshopify.com"], False)
    assert h.third_party and not h.private
    h2 = classify("int.example.com", "example.com", ["10.0.0.5"], [], False)
    assert h2.private
    h3 = classify("cdn.example.com", "example.com", PUBLIC, ["edge.example.com"], False)
    assert not h3.third_party


def test_takeover_vs_dangling():
    known = classify("old.example.com", "example.com", [], ["gone.herokuapp.com"], True)
    assert _rules(host_findings(known))["discover.takeover"].severity == "high"
    other = classify("x.example.com", "example.com", [], ["x.someprovider.net"], True)
    assert _rules(host_findings(other))["discover.dangling-cname"].severity == "medium"


def test_live_host_finding_evidence_is_hostname_for_stable_diff():
    h = classify("www.example.com", "example.com", PUBLIC, [], False)
    h.url, h.status = "https://www.example.com", 200
    f = _rules(host_findings(h))["discover.host"]
    assert f.evidence == "www.example.com" and f.severity == "info"


def _fake_env(monkeypatch, names, dns, live):
    monkeypatch.setattr(disc, "from_ct", lambda d, t: (set(names), "crt.sh", None))
    monkeypatch.setattr(disc, "from_subfinder", lambda d, r, t: set())
    monkeypatch.setattr(disc, "resolve", lambda n: dns.get(n, ([], [], False)))
    probed = []

    def fake_probe(h, scope, timeout, limiter):
        probed.append(h.name)
        if h.name in live:
            h.url, h.status = f"https://{h.name}", 200
    monkeypatch.setattr(disc, "probe", fake_probe)
    return probed


def test_run_probes_only_in_house_public_hosts(monkeypatch):
    names = ["www.example.com", "shop.example.com", "int.example.com",
             "old.example.com", "nx.example.com"]
    dns = {
        "example.com": (PUBLIC, [], False),
        "www.example.com": (PUBLIC, [], False),
        "shop.example.com": (PUBLIC, ["shops.myshopify.com"], False),
        "int.example.com": (["10.0.0.5"], [], False),
        "old.example.com": ([], ["gone.github.io"], True),
    }
    probed = _fake_env(monkeypatch, names, dns, live={"www.example.com", "example.com"})
    ctx = ScanContext()
    rules = {f.rule_id for f in disc.run("https://example.com", ctx)}
    assert sorted(probed) == ["example.com", "www.example.com"]
    assert {"discover.host", "discover.takeover", "discover.summary"} <= rules
    # apex is the scanned target already, so only the subdomain is handed on
    assert ctx.extra["discovered_urls"] == ["https://www.example.com"]


def test_allow_private_probes_private_hosts(monkeypatch):
    from recon.scope import Scope
    dns = {"int.example.com": (["10.0.0.5"], [], False)}
    probed = _fake_env(monkeypatch, ["int.example.com"], dns, live=set())
    disc.run("https://example.com",
             ScanContext(scope=Scope(["example.com"], allow_private=True)))
    assert "int.example.com" in probed


def test_ct_failure_is_reported(monkeypatch):
    monkeypatch.setattr(disc, "from_ct", lambda d, t: (set(), None, "crt.sh: Timeout"))
    monkeypatch.setattr(disc, "from_subfinder", lambda d, r, t: set())
    monkeypatch.setattr(disc, "resolve", lambda n: ([], [], False))
    rules = {f.rule_id for f in disc.run("https://example.com", ScanContext())}
    assert "discover.ct-unavailable" in rules


def test_host_limit(monkeypatch):
    names = [f"h{i}.example.com" for i in range(10)]
    dns = {n: (PUBLIC, [], False) for n in names + ["example.com"]}
    _fake_env(monkeypatch, names, dns, live=set())
    ctx = ScanContext(discover_max_hosts=3)
    f = _rules(disc.run("https://example.com", ctx))["discover.summary"]
    assert "limit" in f.detail


# --- CLI flow -------------------------------------------------------------------

def _patch_scan(monkeypatch, discovered):
    import recon.cli as cli
    from recon.findings import ScanResult
    seen = []

    def fake_scan(target, mods, ctx, **kw):
        seen.append((target, list(mods)))
        if "discover" in mods:
            ctx.extra["discovered_urls"] = discovered
        return ScanResult(target=target)
    monkeypatch.setattr(cli, "run_scan", fake_scan)
    return cli, seen


def test_cli_scan_discovered_requires_discover():
    from recon.cli import main
    assert main(["https://example.com", "--authorized", "--scan-discovered"]) == 1


def test_cli_discover_lists_but_does_not_scan(tmp_path, monkeypatch, capsys):
    cli, seen = _patch_scan(monkeypatch, ["https://www.example.com"])
    cli.main(["example.com", "--authorized", "--discover", "-m", "headers",
              "-o", str(tmp_path)])
    assert seen == [("https://example.com", ["headers", "discover"])]
    assert "--scan-discovered" in capsys.readouterr().err


def test_cli_scan_discovered_scans_each_host_without_discover(tmp_path, monkeypatch):
    cli, seen = _patch_scan(monkeypatch, ["https://www.example.com",
                                          "https://api.example.com"])
    cli.main(["example.com", "--authorized", "--discover", "--scan-discovered",
              "-m", "headers", "-q", "-o", str(tmp_path)])
    assert seen[1:] == [("https://www.example.com", ["headers"]),
                        ("https://api.example.com", ["headers"])]


def test_parse_certspotter():
    rows = [{"dns_names": ["example.com", "*.example.com", "mail.example.com",
                           "example.edu"]}]
    assert parse_certspotter(json.dumps(rows), "example.com") ==         {"example.com", "mail.example.com"}


def test_from_ct_falls_back_to_certspotter(monkeypatch):
    calls = []

    class R:
        def __init__(self, code, text):
            self.status_code, self.text = code, text

    def fake_get(url, params, timeout, headers):
        calls.append(url)
        if "crt.sh" in url:
            return R(502, "bad gateway")
        return R(200, json.dumps([{"dns_names": ["a.example.com"]}]))
    monkeypatch.setattr(disc.requests, "get", fake_get)
    names, source, err = disc.from_ct("example.com", 5)
    assert source == "certspotter" and names == {"a.example.com"} and err is None
    assert len(calls) == 2
