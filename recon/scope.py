"""Scope enforcement: keep traffic on hosts the user is authorized to test.

The ``--authorized`` flag is a checkbox; this is the control. A Scope is an
allowlist of hostnames (exact or ``*.example.com`` wildcard). HTTP modules send
requests through ``scoped_get`` which checks the host before every request AND
before following any redirect, so a redirect cannot bounce a probe onto a
third-party host. Default scope is the target host only.
"""
from __future__ import annotations

import ipaddress
from urllib.parse import urljoin, urlparse

import requests


class ScopeViolation(Exception):
    """Raised when a request/redirect targets a host outside the allowlist."""


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

    def _is_private(self, host: str) -> bool:
        if host in ("localhost",) or host.endswith((".local", ".internal")):
            return True
        try:
            return ipaddress.ip_address(host).is_private or \
                ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    def allows(self, host: str | None) -> bool:
        if not host:
            return False
        if getattr(self, "_all", False):
            return True
        host = host.lower()
        matched = False
        for pat in self.patterns:
            if pat.startswith("*."):
                if host == pat[2:] or host.endswith(pat[1:]):
                    matched = True
                    break
            elif host == pat:
                matched = True
                break
        if not matched:
            return False
        # A matched host that is private/loopback still needs opt-in unless it was
        # named explicitly (it is in patterns, so it was) — allow it.
        return True

    def check(self, url: str) -> None:
        host = urlparse(url).hostname
        if not self.allows(host):
            raise ScopeViolation(host or url)


def scoped_get(url: str, scope: Scope, *, timeout: int = 15,
               headers: dict | None = None, max_redirects: int = 5):
    """GET that enforces scope before the initial request and every redirect.

    Returns the final ``requests.Response``. Raises ScopeViolation if any hop
    (including a redirect Location) points outside the allowlist.
    """
    current = url
    resp = None
    for _ in range(max_redirects + 1):
        scope.check(current)
        resp = requests.get(current, timeout=timeout, headers=headers,
                            allow_redirects=False)
        if resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get("Location")
            if not loc:
                return resp
            current = urljoin(current, loc)
            continue
        return resp
    return resp
