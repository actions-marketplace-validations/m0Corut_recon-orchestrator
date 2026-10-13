from __future__ import annotations

"""Guard against findings that silently fall back to English in --lang tr.

Statically scans each module for the localization key each finding uses
(msg_key if set on that Finding, else its rule_id) and asserts a Turkish
CATALOG entry exists. Dynamic keys (f-strings with an expression in the slug)
can't be resolved statically and are skipped — they are the minority and each
sets an explicit static msg_key that IS checked.
"""
import ast
import pathlib

from recon.i18n import CATALOG

MODULES = pathlib.Path("recon/modules")


def _module_name(tree: ast.Module) -> str | None:
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "NAME" for t in node.targets):
            if isinstance(node.value, ast.Constant):
                return node.value.value
    return None


def _static_key(node: ast.keyword, name: str) -> str | None:
    """Resolve a rule_id=/msg_key= value to a static 'name.slug' key, or None."""
    v = node.value
    if isinstance(v, ast.Constant) and isinstance(v.value, str):
        return v.value if "." in v.value else f"{name}.{v.value}"
    # f"{NAME}.slug" with a single literal slug part
    if isinstance(v, ast.JoinedStr) and len(v.values) == 2:
        first, second = v.values
        is_name = (isinstance(first, ast.FormattedValue)
                   and isinstance(first.value, ast.Name) and first.value.id == "NAME")
        if is_name and isinstance(second, ast.Constant) and isinstance(second.value, str):
            return f"{name}{second.value}"   # second is ".slug"
    return None


def _collect(path: pathlib.Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    name = _module_name(tree)
    if not name:
        return []
    keys = []
    for call in ast.walk(tree):
        if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                and call.func.id == "Finding"):
            continue
        kw = {k.arg: k for k in call.keywords if k.arg}
        chosen = kw.get("msg_key") or kw.get("rule_id")
        if chosen is None:
            continue
        key = _static_key(chosen, name)
        if key is not None:
            keys.append(key)
    return keys


def test_every_static_finding_key_has_turkish_entry():
    missing = []
    for path in sorted(MODULES.glob("*.py")):
        if path.name == "__init__.py":
            continue
        for key in _collect(path):
            if key not in CATALOG or "tr" not in CATALOG[key]:
                missing.append(key)
    assert not missing, f"findings with no Turkish catalogue entry: {sorted(set(missing))}"
