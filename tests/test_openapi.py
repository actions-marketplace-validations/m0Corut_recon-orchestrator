from recon.modules.openapi import analyze_response, extract_operations

SWAGGER2 = {
    "swagger": "2.0",
    "security": [{"apiKey": []}],       # global security
    "paths": {
        "/users": {"get": {}},                       # inherits global -> secured
        "/public": {"get": {"security": []}},        # explicitly open
        "/users/{id}": {"get": {}},                  # path param -> skipped
        "/create": {"post": {}},                     # not GET/HEAD -> skipped
    },
}

OPENAPI3_NOSEC = {
    "openapi": "3.0.0",
    "paths": {"/items": {"get": {}}},   # no global, no op security -> not secured
}


def _by_path(ops):
    return {(o["path"], o["method"]): o for o in ops}


def test_extract_skips_path_params_and_non_get():
    ops = _by_path(extract_operations(SWAGGER2))
    assert ("/users", "get") in ops
    assert ("/public", "get") in ops
    assert ("/users/{id}", "get") not in ops
    assert ("/create", "post") not in ops


def test_global_security_inherited():
    ops = _by_path(extract_operations(SWAGGER2))
    assert ops[("/users", "get")]["secured"] is True
    assert ops[("/public", "get")]["secured"] is False


def test_no_security_anywhere():
    ops = _by_path(extract_operations(OPENAPI3_NOSEC))
    assert ops[("/items", "get")]["secured"] is False


def test_extract_handles_garbage():
    assert extract_operations({}) == []
    assert extract_operations({"paths": "nope"}) == []


def test_analyze_secured_200_is_high():
    f = analyze_response("/users", True, 200)
    assert f and f[0].rule_id == "openapi.missing-auth-enforcement"
    assert f[0].severity == "high"


def test_analyze_secured_401_clean():
    assert analyze_response("/users", True, 401) == []


def test_analyze_public_200_is_info():
    f = analyze_response("/public", False, 200)
    assert f and f[0].severity == "info"
