"""Shared, dependency-light HTML parsing and page fetching for detection modules.

Several modules (csrf, jsrecon, hostinject, passive) need to look at a page's
forms, scripts, links and meta tags. This centralises that so each module stays
pure: `parse_html` turns a response body into a small typed model with stdlib
`html.parser` only (no BeautifulSoup), and `fetch_pages` fetches the target plus
a capped set of already-crawled same-host URLs through `scoped_get` + the shared
rate limit. Everything here is read-only GET.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlparse

from ..scope import Scope, ScopeViolation, scoped_get

MAX_PAGES = 15
BODY_CAP = 2_000_000          # bytes of HTML parsed per page


@dataclass
class Form:
    action: str = ""
    method: str = "get"
    inputs: list[tuple[str, str]] = field(default_factory=list)   # (name, type)


@dataclass
class Tag:
    name: str                 # "script" | "link"
    attrs: dict[str, str] = field(default_factory=dict)


@dataclass
class PageModel:
    forms: list[Form] = field(default_factory=list)
    scripts: list[Tag] = field(default_factory=list)      # <script src=...>
    links: list[Tag] = field(default_factory=list)        # <link ...>
    meta_refresh: str | None = None                       # URL from <meta http-equiv=refresh>
    anchors: list[str] = field(default_factory=list)      # <a href>


class _Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.page = PageModel()
        self._form: Form | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # Browsers keep the FIRST occurrence of a duplicated attribute; a plain
        # dict comprehension would keep the last, so use setdefault.
        a: dict[str, str] = {}
        for k, v in attrs:
            a.setdefault(k.lower(), v or "")
        if tag == "form":
            # Nested <form> is invalid HTML; browsers ignore the inner tag but
            # keep the outer form. Flush the current form before starting a new
            # one so a page with stray/nested <form> tags never loses a form.
            if self._form is not None:
                self.page.forms.append(self._form)
            self._form = Form(action=a.get("action", ""),
                              method=(a.get("method", "get") or "get").lower())
        elif tag == "input" and self._form is not None:
            self._form.inputs.append((a.get("name", ""), (a.get("type", "text") or "text").lower()))
        elif tag in ("button", "textarea", "select") and self._form is not None:
            self._form.inputs.append((a.get("name", ""), tag))
        elif tag == "script" and "src" in a:
            self.page.scripts.append(Tag("script", a))
        elif tag == "link":
            self.page.links.append(Tag("link", a))
        elif tag == "a" and "href" in a:
            self.page.anchors.append(a["href"])
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            content = a.get("content", "")
            if "url=" in content.lower():
                self.page.meta_refresh = content[content.lower().index("url=") + 4:].strip()

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.page.forms.append(self._form)
            self._form = None


def parse_html(body: str) -> PageModel:
    """Pure: parse an HTML body into a PageModel. Never raises on bad markup."""
    p = _Parser()
    try:
        p.feed(body or "")
    except Exception:  # noqa: BLE001 - malformed HTML must not abort a scan
        pass
    if p._form is not None:          # unclosed <form>
        p.page.forms.append(p._form)
    return p.page


def fetch_pages(target: str, ctx, limit: int = MAX_PAGES):
    """Fetch the target + up to `limit`-1 same-host crawled URLs (read-only GET).

    Yields (url, status, headers_dict, body) tuples. Bodies are capped. Pages
    that fail or fall outside scope are skipped silently.
    """
    scope = ctx.get("scope") or Scope.allow_all()
    limiter = ctx.get("limiter")
    timeout = ctx.get("http_timeout", 15)
    host = (urlparse(target).hostname or "").lower()

    urls = [target]
    for u in (ctx.get("crawled_urls") or []):
        if (urlparse(u).hostname or "").lower() == host and u not in urls:
            urls.append(u)
        if len(urls) >= limit:
            break

    for url in urls[:limit]:
        try:
            r = scoped_get(url, scope, timeout=timeout, limiter=limiter)
        except (ScopeViolation, Exception):  # noqa: BLE001
            continue
        yield url, r.status_code, dict(r.headers), (r.text or "")[:BODY_CAP]
