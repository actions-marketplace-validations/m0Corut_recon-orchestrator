import json
import os

from recon.diff import (
    compute_diff,
    exceeds_new_threshold,
    find_latest_baseline,
    fingerprints_from_report,
)
from recon.findings import Finding, ScanResult


def _result(*findings):
    r = ScanResult("https://x")
    r.add(*findings)
    return r


def test_compute_diff_new_unchanged_resolved():
    old = Finding("headers", "a", "low", "d", evidence="e1", rule_id="headers.a")
    gone = Finding("ports", "b", "high", "d", evidence="e2", rule_id="ports.b")
    baseline = {old.fingerprint: old.to_dict(), gone.fingerprint: gone.to_dict()}

    still = Finding("headers", "a", "low", "d", evidence="e1", rule_id="headers.a")
    fresh = Finding("web", "c", "medium", "d", evidence="e3", rule_id="web.c")
    cur = _result(still, fresh)

    diff = compute_diff(cur, baseline)
    assert [f.rule_id for f in diff.new] == ["web.c"]
    assert [f.rule_id for f in diff.unchanged] == ["headers.a"]
    assert len(diff.resolved) == 1 and diff.resolved[0]["rule_id"] == "ports.b"


def test_exceeds_new_threshold():
    high = Finding("web", "c", "high", "d", rule_id="web.c")
    diff = compute_diff(_result(high), {})   # empty baseline -> all new
    assert exceeds_new_threshold(diff, "high") is True
    assert exceeds_new_threshold(diff, "critical") is False


def test_no_new_does_not_exceed():
    f = Finding("web", "c", "high", "d", evidence="e", rule_id="web.c")
    baseline = {f.fingerprint: f.to_dict()}
    same = Finding("web", "c", "high", "d", evidence="e", rule_id="web.c")
    diff = compute_diff(_result(same), baseline)
    assert diff.new == []
    assert exceeds_new_threshold(diff, "low") is False


def test_fingerprints_from_report(tmp_path):
    report = {"findings": [
        {"rule_id": "x.a", "fingerprint": "aaa", "title": "t"},
        {"rule_id": "x.b", "fingerprint": "bbb", "title": "t2"},
    ]}
    p = tmp_path / "report.json"
    p.write_text(json.dumps(report), encoding="utf-8")
    fps = fingerprints_from_report(str(p))
    assert set(fps) == {"aaa", "bbb"}
    # also accept a run directory containing report.json
    assert set(fingerprints_from_report(str(tmp_path))) == {"aaa", "bbb"}


def test_fingerprints_from_missing():
    assert fingerprints_from_report("/no/such/path.json") == {}


def test_find_latest_baseline(tmp_path):
    host = "x"
    d1 = tmp_path / f"{host}_20260101-000000"
    d2 = tmp_path / f"{host}_20260102-000000"
    for d in (d1, d2):
        d.mkdir()
        (d / "report.json").write_text('{"findings": []}', encoding="utf-8")
    # make d2 newer
    os.utime(d2 / "report.json", (10**9 + 100, 10**9 + 100))
    os.utime(d1 / "report.json", (10**9, 10**9))
    latest = find_latest_baseline(str(tmp_path), host)
    assert latest and "20260102" in latest
