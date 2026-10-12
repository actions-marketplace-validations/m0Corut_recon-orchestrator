import sys
import types

import recon.modules as modules


class EP:
    def __init__(self, name, value):
        self.name, self.value = name, value


def _install(monkeypatch, eps, mods):
    for name, mod in mods.items():
        monkeypatch.setitem(sys.modules, name, mod)
    monkeypatch.setattr(modules, "_entry_points", lambda: eps)
    monkeypatch.setattr(modules, "_plugins_loaded", False)
    monkeypatch.setattr(modules, "REGISTRY", dict(modules.REGISTRY))


def _plugin(name="mycheck", **attrs):
    m = types.ModuleType(f"plug_{name}")
    m.NAME = name
    m.run = lambda target, ctx: []
    for k, v in attrs.items():
        setattr(m, k, v)
    return m


def test_plugin_registered_but_not_default(monkeypatch):
    _install(monkeypatch, [EP("mycheck", "plug_mycheck:run")],
             {"plug_mycheck": _plugin(DESCRIPTION="My check", ACTIVE=False)})
    assert modules.load_plugins() == []
    spec = modules.REGISTRY["mycheck"]
    assert (spec.import_path, spec.active, spec.description) == \
        ("plug_mycheck", False, "My check")
    assert "mycheck" not in modules.DEFAULT_ORDER
    assert spec.load().NAME == "mycheck"


def test_plugin_cannot_shadow_builtin(monkeypatch):
    _install(monkeypatch, [EP("evil", "plug_headers")],
             {"plug_headers": _plugin("headers")})
    warnings = modules.load_plugins()
    assert "taken" in warnings[0]
    assert modules.REGISTRY["headers"].import_path == "recon.modules.headers"


def test_broken_plugins_are_reported_not_raised(monkeypatch):
    norun = types.ModuleType("plug_norun")
    norun.NAME = "norun"
    _install(monkeypatch, [EP("missing", "does_not_exist_xyz"), EP("norun", "plug_norun")],
             {"plug_norun": norun})
    warnings = modules.load_plugins()
    assert any("import failed" in w for w in warnings)
    assert any("no run" in w for w in warnings)


def test_load_is_idempotent(monkeypatch):
    _install(monkeypatch, [EP("mycheck", "plug_mycheck")], {"plug_mycheck": _plugin()})
    modules.load_plugins()
    assert modules.load_plugins() == []
