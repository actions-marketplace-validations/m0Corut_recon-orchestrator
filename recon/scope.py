"""Scope enforcement: keep traffic on hosts the user is authorized to test.

The ``--authorized`` flag is a checkbox; this is the control. A Scope is an
allowlist of hostnames (exact or ``*.example.com`` wildcard). HTTP modules send
requests through ``scoped_get`` which checks the host before every request AND
before following any redirect, so a redirect cannot bounce a probe onto a
third-party host. Default scope is the target host only.

Hosts named exactly in the allowlist are trusted as given (that is how a local
dev server like ``http://localhost:8000`` is scanned). A host that only matches
a wildcard must also resolve to public addresses unless ``allow_private`` is
set, so ``*.example.com`` cannot be used to reach ``internal.example.com ->
10.0.0.5`` or a cloud metadata address. This check happens before each request;
it does not pin the address, so a DNS answer that changes between the check and
the connect (rebinding) is not covered.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import requests


class ScopeViolation(Exception):
    """Raised when a request/redirect targets a host outside the allowlist."""


def _resolve(host: str) -> list[str]:
    """Return the addresses `host` resolves to; empty if resolution fails."""
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    return list({str(info[4][0]) for info in infos})


def _is_public_ip(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr.split("%", 1)[0]).is_global
    except ValueError:
        return False


class Scope:
    def __init__(self, patterns: list[str], allow_private: bool = False) -> None:
        self.patterns = [p.lower().strip() for p in patterns if p.strip()]
        self.allow_private = allow_private

    @classmethod
    def allow_all(cls) -> Scope:
        s = cls([])
        s._all = True  # type: ignore[attr-defined]
        return s

    @classmethod
    def for_target(cls, target: str, extra: list[str] | None = None,
                   allow_private: bool = False) -> Scope:
        host = urlparse(target).hostname or target
        patterns = [host] + list(extra or [])
        return cls(patterns, allow_private=allow_private)

    def _is_private_name(self, host: str) -> bool:
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
            return True
        try:
            return not ipaddress.ip_address(host).is_global
        except ValueError:
            return False

    def _named_exactly(self, host: str) -> bool:
        return host in self.patterns

    def allows(self, host: str | None) -> bool:
        """Allowlist match only (no DNS). See ``check`` for the address check."""
        if not host:
            return False
        if getattr(self, "_all", False):
            return True
        host = host.lower()
        if self._named_exactly(host):
            return True
        for pat in self.patterns:
            if pat.startswith("*.") and (host == pat[2:] or host.endswith(pat[1:])):
                # a wildcard never grants a private name/IP literal on its own
                return self.allow_private or not self._is_private_name(host)
        return False

    def check(self, url: str) -> None:
        """Raise ScopeViolation unless `url` may be requested.

        Beyond ``allows``, a wildcard-matched host must resolve only to public
        addresses unless ``allow_private`` is set.
        """
        host = (urlparse(url).hostname or "").lower()
        if not self.allows(host):
            raise ScopeViolation(host or url)
        if getattr(self, "_all", False) or self.allow_private or self._named_exactly(host):
            return
        private = [a for a in _resolve(host) if not _is_public_ip(a)]
        if private:
            raise ScopeViolation(f"{host} resolves to non-public address {private[0]}")


def _origin(url: str) -> tuple[str, str, int | None]:
    p = urlparse(url)
    port = p.port or {"http": 80, "https": 443}.get(p.scheme)
    return p.scheme, (p.hostname or "").lower(), port


def scoped_get(url: str, scope: Scope, *, timeout: int = 15,
               headers: dict | None = None, auth_headers: dict | None = None,
               max_redirects: int = 5, limiter=None):
    """GET that enforces scope before the initial request and every redirect.

    Returns the final ``requests.Response``. Raises ScopeViolation if any hop
    (including a redirect Location) points outside the allowlist. If a limiter is
    given, a token is acquired before every request (aggregate rate ceiling).

    ``auth_headers`` (cookies, tokens) are sent only while the request stays on
    the original origin (scheme, host, port): a redirect to another in-scope
    host, or from https down to http, drops them.
    """
    current = url
    origin = _origin(url)
    resp = None
    for _ in range(max_redirects + 1):
        scope.check(current)
        if limiter is not None:
            limiter.acquire()
        hop_headers = dict(headers or {})
        if auth_headers and _origin(current) == origin:
            hop_headers.update(auth_headers)
        resp = requests.get(current, timeout=timeout, headers=hop_headers or None,
                            allow_redirects=False)
        if limiter is not None and hasattr(limiter, "observe"):
            limiter.observe(resp.status_code, resp.headers.get("Retry-After"))
        if resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get("Location")
            if not loc:
                return resp
            current = urljoin(current, loc)
            continue
        return resp
    return resp


def scoped_post(url: str, scope: Scope, *, json=None, data=None,
                headers: dict | None = None, timeout: int = 15, limiter=None):
    """POST that enforces scope before sending. Does not follow redirects.

    Used by probe modules (e.g. a single GraphQL introspection query). Scope is
    checked on the target URL; a token is acquired from the limiter and the
    response status is observed, like ``scoped_get``.
    """
    scope.check(url)
    if limiter is not None:
        limiter.acquire()
    resp = requests.post(url, json=json, data=data, headers=headers or None,
                         timeout=timeout, allow_redirects=False)
    if limiter is not None and hasattr(limiter, "observe"):
        limiter.observe(resp.status_code, resp.headers.get("Retry-After"))
    return resp
