from recon.diff import DiffResult
from recon.findings import Finding
from recon.integrations.github import (
    extract_fingerprint,
    fingerprint_marker,
    issue_body,
    issue_title,
    post_findings,
    select_new,
)


def test_fingerprint_roundtrip():
    body = "some text\n" + fingerprint_marker("abc123") + "\nmore"
    assert extract_fingerprint(body) == "abc123"


def test_extract_none_when_absent():
    assert extract_fingerprint("no marker here") is None


def test_select_new_filters_severity():
    findings = [
        Finding("m", "a", "low", "d", rule_id="m.a"),
        Finding("m", "b", "high", "d", rule_id="m.b"),
        Finding("m", "c", "critical", "d", rule_id="m.c"),
    ]
    picked = select_new(findings, "high")
    assert {f.rule_id for f in picked} == {"m.b", "m.c"}


def test_issue_title_and_body_contain_marker():
    f = Finding("web", "RCE", "high", "bad", evidence="x", rule_id="web.rce")
    assert issue_title(f).startswith("[HIGH]")
    body = issue_body(f, "RCE", "bad", "patch it")
    assert "web.rce" in body
    assert extract_fingerprint(body) == f.fingerprint


class FakeClient:
    def __init__(self):
        self.created = []
        self.closed = []
        self._existing = {}

    def open_issue_fingerprints(self):
        return dict(self._existing)

    def create_issue(self, title, body, labels):
        self.created.append((title, labels))
        return len(self.created)

    def close_issue(self, number, comment):
        self.closed.append(number)


def _localize(f, lang):
    return f.title, f.detail, f.recommendation


def test_post_findings_creates_for_new_high():
    new = [Finding("web", "RCE", "high", "d", evidence="e", rule_id="web.rce")]
    diff = DiffResult(new=new, unchanged=[], resolved=[])
    client = FakeClient()
    summary = post_findings("o/r", "tok", diff, _localize, "en",
                            min_severity="high", client=client)
    assert len(summary["created"]) == 1
    assert client.created[0][1] == ["recon", "severity:high"]


def test_post_findings_skips_existing():
    f = Finding("web", "RCE", "high", "d", evidence="e", rule_id="web.rce")
    diff = DiffResult(new=[f], unchanged=[], resolved=[])
    client = FakeClient()
    client._existing = {f.fingerprint: 7}
    summary = post_findings("o/r", "tok", diff, _localize, "en", client=client)
    assert summary["created"] == []
    assert f.fingerprint in summary["skipped"]


def test_post_findings_closes_resolved():
    diff = DiffResult(new=[], unchanged=[], resolved=[])
    client = FakeClient()
    client._existing = {"deadbeef": 9}   # an old issue no longer present
    summary = post_findings("o/r", "tok", diff, _localize, "en",
                            close_resolved=True, client=client)
    assert summary["closed"] == [9]
