from recon.context import ScanContext
from recon.modules.graphql import (
    analyze_graphql_errors,
    analyze_introspection,
    analyze_panel,
    candidate_endpoints,
    run,
)


def _rules(f):
    return {x.rule_id for x in f}


def test_candidate_endpoints():
    c = candidate_endpoints("https://t.com", ["https://t.com/svc/graphql?x=1"])
    assert "https://t.com/graphql" in c
    assert any("svc/graphql" in u for u in c)


def test_introspection_enabled_vs_endpoint_only():
    on = analyze_introspection("https://t/graphql", 200,
                               '{"data":{"__schema":{"queryType":{"name":"Query"}}}}')
    assert on.rule_id == "graphql.introspection-enabled"
    off = analyze_introspection("https://t/graphql", 200,
                                '{"errors":[{"message":"introspection disabled"}]}')
    assert off.rule_id == "graphql.endpoint-found"
    assert analyze_introspection("https://t/graphql", 200, "<html>no</html>") is None


def test_debug_errors_and_panel():
    e = analyze_graphql_errors("https://t/graphql",
                               '{"errors":[{"extensions":{"exception":{"stacktrace":["x"]}}}]}')
    assert e.rule_id == "graphql.debug-errors"
    p = analyze_panel("https://t/graphiql", 200, "<title>GraphiQL</title>")
    assert p.rule_id == "graphql.ide-exposed"
    assert analyze_panel("https://t/graphiql", 404, "") is None


def test_debug_errors_no_false_positive_on_exception_word():
    # The word "exception" in a plain message is not debug mode; only a real
    # stack trace inside extensions should flag.
    assert analyze_graphql_errors(
        "https://t/graphql",
        '{"errors":[{"message":"a NullPointerException occurred"}]}') is None


def test_panel_detected_by_marker_regardless_of_status():
    p = analyze_panel("https://t/playground", 403, "<div>GraphQL Playground</div>")
    assert p.rule_id == "graphql.ide-exposed"


def test_run_none_found(monkeypatch):
    import recon.modules.graphql as g

    def boom(*a, **k):
        raise RuntimeError("no")
    monkeypatch.setattr(g, "scoped_post", boom)
    monkeypatch.setattr(g, "scoped_get", boom)
    assert "graphql.none-found" in _rules(run("https://t", ScanContext()))
