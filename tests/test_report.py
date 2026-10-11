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


def test_markdown_english_by_default():
    md = to_markdown(_result(), META)
    assert "| Severity | Module | Title |" in md
    assert "MEDIUM" in md and "Missing HSTS" in md
    assert "Security Scan Report" in md


def test_markdown_turkish_when_requested():
    md = to_markdown(_result(), META, lang="tr")
    assert "| Önem | Modül | Başlık |" in md
    # headers.missing-hsts has a Turkish catalogue entry
    assert "Strict-Transport-Security" in md
    assert "Güvenlik Tarama Raporu" in md


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


_VALID_LEVELS = {"none", "note", "warning", "error"}


def test_sarif_structure_is_valid():
    """Dependency-free structural validation of the SARIF we emit."""
    meta = {**META, "started_at": "2026-01-01T00:00:00+00:00",
            "ended_at": "2026-01-01T00:01:00+00:00"}
    sarif = json.loads(to_sarif(_result(), meta))
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-schema-2.1.0.json")
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]

    driver = run["tool"]["driver"]
    assert driver["name"] and driver["version"]
    declared = {r["id"] for r in driver["rules"]}
    # every rule has help + fullDescription + helpUri
    for r in driver["rules"]:
        assert r["help"]["text"]
        assert r["fullDescription"]["text"]
        assert r["helpUri"].startswith("https://")

    # every result references a declared rule, a valid level, a fingerprint
    for res in run["results"]:
        assert res["ruleId"] in declared
        assert res["level"] in _VALID_LEVELS
        assert res["message"]["text"]
        assert res["partialFingerprints"]["reconFingerprint/v1"]
        assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]

    inv = run["invocations"][0]
    assert inv["executionSuccessful"] is True
    assert inv["startTimeUtc"] and inv["endTimeUtc"]


def test_sarif_invocation_reports_errors():
    r = _result()
    r.errors.append("web: Docker unavailable")
    run = json.loads(to_sarif(r, META))["runs"][0]
    inv = run["invocations"][0]
    assert inv["executionSuccessful"] is False
    assert inv["toolExecutionNotifications"][0]["message"]["text"] == "web: Docker unavailable"
