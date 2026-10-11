import json

from recon.findings import Finding, ScanResult
from recon.report import to_json, to_markdown, to_sarif

META = {"modules": ["headers"], "version": "0.1.0"}


def _result():
    r = ScanResult("https://x")
    r.add(
        Finding("headers", "Missing HSTS", "medium", "no hsts",
                evidence="GET https://x -> 200", rule_id="headers.missing-hsts"),
        Finding("ports", "Exposed SSH", "low", "ssh open",
                evidence="22/tcp", rule_id="ports.exposed-ssh"),
    )
    return r


def test_markdown_has_table_and_details():
    md = to_markdown(_result(), META)
    assert "| Önem | Modül | Başlık |" in md
    assert "MEDIUM" in md and "Missing HSTS" in md


def test_json_roundtrips_with_fingerprints():
    data = json.loads(to_json(_result(), META))
    assert data["target"] == "https://x"
    assert data["counts"]["medium"] == 1
    assert all("fingerprint" in f for f in data["findings"])


def test_sarif_uses_rule_id_and_fingerprints():
    sarif = json.loads(to_sarif(_result(), META))
    run = sarif["runs"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "headers.missing-hsts" in rule_ids
    assert run["tool"]["driver"]["informationUri"].startswith("https://github.com/")
    for res in run["results"]:
        assert "reconFingerprint/v1" in res["partialFingerprints"]
