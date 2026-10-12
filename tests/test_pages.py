from recon.context import ScanContext
from recon.modules._pages import fetch_pages, parse_html


def test_parse_forms_with_inputs():
    html = """
    <form action="/pay" method="POST">
      <input name="amount" type="number">
      <input name="_token" type="hidden" value="x">
      <button name="go">Pay</button>
    </form>"""
    page = parse_html(html)
    assert len(page.forms) == 1
    f = page.forms[0]
    assert f.action == "/pay" and f.method == "post"
    assert ("amount", "number") in f.inputs and ("_token", "hidden") in f.inputs


def test_parse_scripts_links_meta_anchors():
    html = """
    <script src="https://cdn.test/a.js" integrity="sha384-x"></script>
    <script src="/local.js"></script>
    <link rel="stylesheet" href="https://cdn.test/s.css">
    <meta http-equiv="refresh" content="0; url=https://evil.test/next">
    <a href="/about">about</a>"""
    page = parse_html(html)
    assert [s.attrs.get("src") for s in page.scripts] == \
        ["https://cdn.test/a.js", "/local.js"]
    assert page.scripts[0].attrs.get("integrity") == "sha384-x"
    assert page.links[0].attrs.get("href") == "https://cdn.test/s.css"
    assert page.meta_refresh == "https://evil.test/next"
    assert page.anchors == ["/about"]


def test_parse_malformed_and_unclosed_form():
    page = parse_html("<form method=post><input name=x <div><p>oops")
    assert len(page.forms) == 1 and page.forms[0].method == "post"


def test_parse_empty():
    page = parse_html("")
    assert page.forms == [] and page.scripts == []


def test_parse_uppercase_tags_and_attrs():
    page = parse_html('<FORM ACTION="/X" METHOD="POST"><INPUT NAME="q" TYPE="TEXT"></FORM>')
    assert len(page.forms) == 1
    f = page.forms[0]
    assert f.action == "/X" and f.method == "post"
    assert f.inputs == [("q", "text")]


def test_parse_attribute_without_value():
    # `disabled`/`checked` have no value; they must not crash or shadow name/type.
    page = parse_html("<form><input disabled name=z type=checkbox checked></form>")
    assert page.forms[0].inputs == [("z", "checkbox")]


def test_parse_duplicate_attributes_keep_first():
    # Browsers honour the FIRST occurrence of a repeated attribute.
    page = parse_html("<form action=/a action=/b><input name=x name=y></form>")
    assert page.forms[0].action == "/a"
    assert page.forms[0].inputs == [("x", "text")]


def test_parse_multiple_forms():
    page = parse_html(
        '<form action="/a"><input name="x"></form>'
        '<form action="/b" method="post"><input name="y"></form>')
    assert [f.action for f in page.forms] == ["/a", "/b"]
    assert [f.method for f in page.forms] == ["get", "post"]


def test_parse_nested_forms_keep_both():
    # Nested <form> is invalid HTML; the outer form must not be lost.
    page = parse_html(
        '<form action="/outer"><input name="a">'
        '<form action="/inner"><input name="b"></form></form>')
    assert [f.action for f in page.forms] == ["/outer", "/inner"]


def test_parse_self_closing_script_and_input():
    page = parse_html('<form><input name=q /></form><script src="/a.js" />')
    assert page.forms[0].inputs == [("q", "text")]
    assert [s.attrs.get("src") for s in page.scripts] == ["/a.js"]


def test_fetch_pages_same_host_only_and_capped(monkeypatch):
    import recon.modules._pages as pages

    class R:
        def __init__(self, url):
            self.status_code = 200
            self.headers = {"X-U": url}
            self.text = f"<html>{url}</html>"
            self.url = url

    def fake_get(url, scope, **kw):
        return R(url)
    monkeypatch.setattr(pages, "scoped_get", fake_get)
    ctx = ScanContext()
    ctx.extra["crawled_urls"] = [
        "https://t.com/a", "https://other.com/b", "https://t.com/c"]
    got = list(fetch_pages("https://t.com/", ctx, limit=10))
    urls = [u for u, _, _, _ in got]
    assert urls == ["https://t.com/", "https://t.com/a", "https://t.com/c"]  # other.com dropped
