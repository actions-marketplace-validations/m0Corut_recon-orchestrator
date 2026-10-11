from recon.findings import Finding, ScanResult, slugify


def test_slugify_ascii_and_turkish():
    assert slugify("Missing HSTS") == "missing-hsts"
    assert slugify("Güvenlik başlığı") == "guvenlik-basligi"
    assert slugify("  A/B  C ") == "a-b-c"


def test_rule_id_explicit_is_kept():
    f = Finding("headers", "x", "low", "d", rule_id="headers.missing-hsts")
    assert f.rule_id == "headers.missing-hsts"


def test_rule_id_derived_when_empty():
    f = Finding("headers", "Güvenlik başlığı eksik: HSTS", "low", "d")
    assert f.rule_id == "headers.guvenlik-basligi-eksik-hsts"


def test_fingerprint_stable_and_location_sensitive():
    a = Finding("ports", "Açık servis", "low", "d", evidence="22/tcp",
                rule_id="ports.exposed-ssh")
    b = Finding("ports", "Açık servis", "low", "d", evidence="22/tcp",
                rule_id="ports.exposed-ssh")
    c = Finding("ports", "Açık servis", "low", "d", evidence="3306/tcp",
                rule_id="ports.exposed-mysql")
    assert a.fingerprint == b.fingerprint       # same issue, same place
    assert a.fingerprint != c.fingerprint       # different place/rule
    assert len(a.fingerprint) == 16


def test_invalid_severity_clamped_to_info():
    assert Finding("m", "t", "banana", "d").severity == "info"


def test_to_dict_includes_fingerprint():
    d = Finding("m", "t", "low", "d", rule_id="m.x").to_dict()
    assert d["rule_id"] == "m.x"
    assert "fingerprint" in d and len(d["fingerprint"]) == 16


def test_scanresult_sorted_and_counts():
    r = ScanResult("https://x")
    r.add(
        Finding("a", "t", "low", "d", rule_id="a.x"),
        Finding("b", "t", "critical", "d", rule_id="b.x"),
        Finding("c", "t", "info", "d", rule_id="c.x"),
    )
    assert [f.severity for f in r.sorted()] == ["critical", "low", "info"]
    assert r.counts()["critical"] == 1
    assert r.max_rank() == 4
