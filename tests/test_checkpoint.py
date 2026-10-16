from recon.checkpoint import Checkpoint
from recon.context import ScanContext
from recon.engine import run_scan
from recon.findings import Finding


def _f(module, title, sev="low"):
    return Finding(module, title, sev, "d", rule_id=f"{module}.{title}",
                   params={"k": 1})


def test_roundtrip_preserves_findings(tmp_path):
    cp = Checkpoint(str(tmp_path / ".partial" / "h.json"), "https://h", ["a", "b"])
    cp.record("a", [_f("a", "x", "high")])
    loaded = Checkpoint(cp.path, "https://h", ["b", "a"]).load()
    f = loaded["a"][0]
    assert (f.rule_id, f.severity, f.params) == ("a.x", "high", {"k": 1})
    assert f.fingerprint == _f("a", "x", "high").fingerprint


def test_mismatched_scan_is_ignored(tmp_path):
    cp = Checkpoint(str(tmp_path / "h.json"), "https://h", ["a"])
    cp.record("a", [_f("a", "x")])
    assert Checkpoint(cp.path, "https://other", ["a"]).load() == {}
    assert Checkpoint(cp.path, "https://h", ["a", "b"]).load() == {}


def test_clear_and_missing_file(tmp_path):
    cp = Checkpoint(str(tmp_path / "h.json"), "https://h", ["a"])
    assert cp.load() == {}
    cp.record("a", [])
    cp.clear()
    assert cp.load() == {}
    cp.clear()           # idempotent


def test_engine_skips_completed_and_reports_done(monkeypatch):
    import recon.engine as engine
    from recon.modules import ModuleSpec

    ran = []

    class Mod:
        def __init__(self, name):
            self.name = name

        def run(self, target, ctx):
            ran.append(self.name)
            return [_f(self.name, "fresh")]

    reg = {n: ModuleSpec(n, "x", False, True, "d") for n in ("a", "b")}
    monkeypatch.setattr(engine, "REGISTRY", reg)
    monkeypatch.setattr(ModuleSpec, "load", lambda self: Mod(self.name))
    done = []
    res = run_scan("https://h", ["a", "b"], ScanContext(), docker_ok=True, serial=True,
                   completed={"a": [_f("a", "old")]},
                   on_module_done=lambda n, fs: done.append(n))
    assert ran == ["b"] and done == ["b"]
    assert {f.rule_id for f in res.findings} == {"a.old", "b.fresh"}


def test_cli_resume_flow(tmp_path, monkeypatch):
    """First run dies in module b; --resume reuses a and only re-runs b."""
    import recon.cli as cli
    import recon.engine as engine
    from recon.modules import ModuleSpec

    calls = []
    fail = {"b": True}

    class Mod:
        def __init__(self, name):
            self.name = name

        def run(self, target, ctx):
            calls.append(self.name)
            if fail.get(self.name):
                raise KeyboardInterrupt
            return [_f(self.name, "x")]

    reg = {n: ModuleSpec(n, "x", False, True, "d") for n in ("a", "b")}
    monkeypatch.setattr(engine, "REGISTRY", reg)
    monkeypatch.setattr("recon.engine.resolve_modules", lambda sel: ["a", "b"])
    monkeypatch.setattr(cli, "resolve_modules", lambda sel: ["a", "b"])
    monkeypatch.setattr(ModuleSpec, "load", lambda self: Mod(self.name))
    args = ["https://h.example", "--authorized", "-q", "--serial", "-o", str(tmp_path)]

    try:
        cli.main(args)
    except KeyboardInterrupt:
        pass
    assert calls == ["a", "b"]
    assert (tmp_path / ".partial" / "h.example.json").exists()

    fail["b"] = False
    calls.clear()
    assert cli.main(args + ["--resume"]) == 0
    assert calls == ["b"]
    assert not (tmp_path / ".partial" / "h.example.json").exists()
