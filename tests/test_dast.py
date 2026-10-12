import json

from recon.context import ScanContext
from recon.modules import web
from recon.modules.web import build_dast_spec

OAS3 = {
    "openapi": "3.0.0",
    "servers": [{"url": "https://prod.internal.example.org/v1"}],
    "paths": {
        "/users": {"get": {}, "post": {}, "parameters": []},
        "/users/{id}": {"delete": {}, "put": {}},
        "/health": {"get": {}, "servers": [{"url": "https://elsewhere.test"}]},
    },
}


def test_only_get_operations_survive():
    out = build_dast_spec(OAS3, "https://staging.example.com")
    assert set(out["paths"]) == {"/users", "/health"}
    assert set(out["paths"]["/users"]) == {"get", "parameters"}
    assert "servers" not in out["paths"]["/health"]
    assert OAS3["paths"]["/users"].get("post") == {}      # input not mutated


def test_servers_rewritten_to_target_keeping_path():
    out = build_dast_spec(OAS3, "https://staging.example.com:8443")
    assert out["servers"] == [{"url": "https://staging.example.com:8443/v1"}]


def test_swagger2_host_rewritten():
    spec = {"swagger": "2.0", "host": "prod.example.org", "basePath": "/api",
            "schemes": ["http"], "paths": {"/a": {"get": {}}}}
    out = build_dast_spec(spec, "https://staging.example.com")
    assert (out["host"], out["schemes"], out["basePath"]) == \
        ("staging.example.com", ["https"], "/api")


def test_no_get_operations_returns_none():
    assert build_dast_spec({"openapi": "3.0.0", "paths": {"/x": {"post": {}}}},
                           "https://t") is None
    assert build_dast_spec({"no": "paths"}, "https://t") is None


class FakeRunner:
    name = "fake"

    def __init__(self):
        self.calls = []

    def can_run(self, tool):
        return True

    def run_capture(self, tool, args, timeout):
        self.calls.append(("capture", args, None))
        return ""

    def run_capture_with_input(self, tool, args, timeout, content, filename):
        self.calls.append(("input", args, json.loads(content)))
        rec = {"template-id": "sqli-error-based", "matched-at": "https://t/users?id=1",
               "info": {"name": "SQLi", "severity": "high"}}
        return json.dumps(rec) + "\n"


def test_dast_runs_only_with_flag(monkeypatch):
    monkeypatch.setattr("recon.modules.openapi._load_spec",
                        lambda *a, **k: ("https://t/openapi.json", OAS3))
    r = FakeRunner()
    web.run("https://t", ScanContext(runner=r))
    assert [c[0] for c in r.calls] == ["capture"]

    r2 = FakeRunner()
    found = web.run("https://t", ScanContext(runner=r2, dast=True))
    kind, args, sent = r2.calls[1]
    assert kind == "input" and args[args.index("-im") + 1] == "openapi"
    assert "-dast" in args
    assert set(sent["paths"]) == {"/users", "/health"}       # GET-only copy sent
    rules = {f.rule_id for f in found}
    assert {"web.nuclei.sqli-error-based", "web.dast-ran"} <= rules


def test_dast_without_spec_is_reported(monkeypatch):
    monkeypatch.setattr("recon.modules.openapi._load_spec", lambda *a, **k: (None, None))
    found = web.run("https://t", ScanContext(runner=FakeRunner(), dast=True))
    assert "web.dast-no-spec" in {f.rule_id for f in found}
