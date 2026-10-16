import json
import os

from recon.cli import (
    _run_doctor_command,
    _run_modules_command,
    main,
)
from recon.report import to_json


def test_modules_command_runs(capsys):
    assert _run_modules_command("en") == 0
    out = capsys.readouterr().out
    assert "headers" in out and "dns" in out and "mail" in out


def test_modules_command_turkish(capsys):
    assert _run_modules_command("tr") == 0
    out = capsys.readouterr().out
    assert "Mevcut modüller" in out


def test_doctor_command_runs(capsys):
    assert _run_doctor_command("en") == 0
    out = capsys.readouterr().out
    assert "Docker" in out and "nmap" in out


def test_doctor_tool_status_column_is_aligned(capsys):
    from recon.runner import TOOLS
    _run_doctor_command("en")
    lines = [ln for ln in capsys.readouterr().out.splitlines()
             if any(ln.strip().startswith(f"{tool} (") for tool in TOOLS)]
    assert len(lines) == len(TOOLS)
    assert len({ln.index(" : ") for ln in lines}) == 1


def test_report_schema_is_valid_json():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(here, "docs", "report.schema.json"), encoding="utf-8") as fh:
        schema = json.load(fh)
    assert schema["title"].startswith("recon-orchestrator")
    assert "findings" in schema["properties"]


def test_report_json_matches_schema_required_keys():
    from recon.findings import Finding, ScanResult
    r = ScanResult("https://x")
    r.add(Finding("web", "t", "high", "d", evidence="e", rule_id="web.t"))
    data = json.loads(to_json(r, {"version": "1.0.0"}))
    # top-level required keys from the schema
    for key in ("target", "generated_at", "meta", "counts", "findings", "errors"):
        assert key in data
    # finding required keys
    for key in ("module", "title", "severity", "detail", "rule_id", "fingerprint"):
        assert key in data["findings"][0]


def test_main_requires_authorization():
    # no --authorized -> exit 1, no scan
    assert main(["https://example.com"]) == 1
