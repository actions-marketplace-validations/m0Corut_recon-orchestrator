from datetime import date

import pytest

from recon.diff import compute_diff
from recon.findings import Finding, ScanResult
from recon.report import to_json, to_markdown
from recon.suppress import (
    SuppressionError,
    apply_suppressions,
    load_suppressions,
    parse_suppressions,
)


def _result():
    r = ScanResult(target="https://example.com")
    r.add(Finding("headers", "Missing CSP", "medium", "d", rule_id="headers.missing-csp"),
          Finding("headers", "Missing HSTS", "high", "d", rule_id="headers.missing-hsts"),
          Finding("ports", "Redis open", "high", "d", evidence="6379/tcp",
                  rule_id="ports.notable"))
    return r


def test_suppressed_finding_leaves_counts_and_gates():
    r = _result()
    rules = parse_suppressions([{"rule_id": "headers.missing-csp", "reason": "JIRA-1"}])
    apply_suppressions(r, rules, today=date(2026, 1, 1))
    assert {f.rule_id for f in r.findings} == {"headers.missing-hsts", "ports.notable"}
    assert r.counts()["medium"] == 0
    assert r.suppressed[0][1] == "JIRA-1"


def test_glob_and_target_filter():
    r = _result()
    rules = parse_suppressions([
        {"rule_id": "headers.*", "reason": "staging only", "target": "https://staging.*"}])
    apply_suppressions(r, rules, today=date(2026, 1, 1))
    assert r.suppressed == []              # target does not match


def test_fingerprint_pins_one_instance():
    r = _result()
    fp = next(f.fingerprint for f in r.findings if f.rule_id == "ports.notable")
    r.add(Finding("ports", "Redis open", "high", "d", evidence="6380/tcp",
                  rule_id="ports.notable"))
    rules = parse_suppressions([{"rule_id": "ports.notable", "reason": "r",
                                 "fingerprint": fp}])
    apply_suppressions(r, rules, today=date(2026, 1, 1))
    assert len(r.suppressed) == 1
    assert any(f.evidence == "6380/tcp" for f in r.findings)


def test_expired_rule_does_not_apply_and_is_returned():
    r = _result()
    rules = parse_suppressions([{"rule_id": "headers.missing-csp", "reason": "r",
                                 "expires": "2026-01-01"}])
    expired = apply_suppressions(r, rules, today=date(2026, 1, 2))
    assert [e.rule_id for e in expired] == ["headers.missing-csp"]
    assert r.suppressed == []
    # still valid on the expiry day itself
    r2 = _result()
    assert apply_suppressions(r2, rules, today=date(2026, 1, 1)) == []
    assert len(r2.suppressed) == 1


@pytest.mark.parametrize("data, msg", [
    ({"rule_id": "x"}, "list"),
    ([{"reason": "r"}], "rule_id"),
    ([{"rule_id": "x"}], "reason"),
    ([{"rule_id": "x", "reason": "r", "expires": "soon"}], "YYYY-MM-DD"),
    ([{"rule_id": "x", "reason": "r", "typo": 1}], "unknown"),
])
def test_validation_errors(data, msg):
    with pytest.raises(SuppressionError, match=msg):
        parse_suppressions(data)


def test_load_from_yaml(tmp_path):
    p = tmp_path / ".reconignore.yml"
    p.write_text("- rule_id: headers.*\n  reason: accepted\n  expires: 2027-01-31\n",
                 encoding="utf-8")
    rules = load_suppressions(str(p))
    assert rules[0].expires == date(2027, 1, 31)


def test_suppressed_is_not_reported_resolved():
    r = _result()
    baseline = {f.fingerprint: f.to_dict() for f in r.findings}
    apply_suppressions(r, parse_suppressions(
        [{"rule_id": "headers.missing-csp", "reason": "r"}]), today=date(2026, 1, 1))
    diff = compute_diff(r, baseline)
    assert diff.resolved == []


def test_reports_list_suppressed():
    r = _result()
    apply_suppressions(r, parse_suppressions(
        [{"rule_id": "headers.missing-csp", "reason": "JIRA-1"}]), today=date(2026, 1, 1))
    import json
    data = json.loads(to_json(r, {}))
    assert data["suppressed"][0]["reason"] == "JIRA-1"
    assert "JIRA-1" in to_markdown(r, {})
