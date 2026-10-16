"""IDOR / broken object-level authorization probe (read-only, heuristic).

Objects addressed by a guessable id (``/invoice/1001``, ``?order=42``) are an
IDOR risk when the server returns someone else's object without an ownership
check. This module finds id-bearing URLs (from a crawl, or ``--idor-url``),
fetches the given id as a baseline, then fetches a neighbouring id and compares:
two different, real objects both returned 200 is a signal that object-level
authorization may be missing.

It is a signal, not proof — sequential ids can be legitimately public — so
findings are medium and say "verify manually". Strictly read-only: GET only,
never writes, and response bodies are never put in the report (only status and
size). Send the tester's session with ``--auth-header`` to test authenticated
objects. Opt-in (``-m idor``); not in the default set.
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..findings import Finding
from ..scope import Scope, ScopeViolation, scoped_get

NAME = "idor"
NEEDS_DOCKER = False

MAX_TARGETS = 10
MIN_BODY = 64            # ignore tiny bodies (errors/redirch stubs)


def _neighbour(n: int) -> int:
    return n - 1 if n > 1 else n + 1


def id_targets(urls: list[str]) -> list[tuple[str, str, int]]:
    """Pure: URLs carrying a numeric id -> (url, kind, id).

    kind is "query:<param>" for ?id=5 or "path" for a trailing /123 segment.
    De-duplicated by (kind, template) so /u/1 and /u/2 count once.
    """
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str, int]] = []
    for url in urls:
        p = urlparse(url)
        for key, val in parse_qsl(p.query):
            if val.isdigit():
                tmpl = f"{p.scheme}|{p.netloc}|{p.path}|{key}"
                if ("query", tmpl) not in seen:
                    seen.add(("query", tmpl))
                    out.append((url, f"query:{key}", int(val)))
        segs = p.path.rstrip("/").split("/")
        if segs and segs[-1].isdigit():
            tmpl = f"{p.scheme}|{p.netloc}|{'/'.join(segs[:-1])}"
            if ("path", tmpl) not in seen:
                seen.add(("path", tmpl))
                out.append((url, "path", int(segs[-1])))
    return out


def swap_id(url: str, kind: str, new_id: int) -> str:
    """Pure: return `url` with its id replaced by new_id."""
    p = urlparse(url)
    if kind.startswith("query:"):
        param = kind.split(":", 1)[1]
        q = [(k, str(new_id) if k == param else v) for k, v in parse_qsl(p.query)]
        return urlunparse(p._replace(query=urlencode(q)))
    segs = p.path.rstrip("/").split("/")
    segs[-1] = str(new_id)
    return urlunparse(p._replace(path="/".join(segs)))


def analyze_idor(location: str, base_status: int, base_len: int,
                 nb_id: int, nb_status: int, nb_len: int) -> Finding | None:
    """Pure: compare a baseline object with a neighbouring id."""
    if base_status != 200 or nb_status != 200:
        return None
    if base_len < MIN_BODY or nb_len < MIN_BODY:
        return None
    if nb_len == base_len:              # same size -> likely the same template, not a new object
        return None
    ratio = min(base_len, nb_len) / max(base_len, nb_len)
    if ratio < 0.3:                     # wildly different -> probably an error page, not an object
        return None
    return Finding(
        NAME, f"Possible IDOR: {location}", "medium",
        "A neighbouring object id returned a different object with status 200, "
        "which suggests object-level authorization may be missing. Verify "
        "manually whether this object should be reachable by this user.",
        evidence=f"{location}: base=200/{base_len}B, id={nb_id}=200/{nb_len}B",
        recommendation="Enforce per-object ownership checks on this endpoint.",
        rule_id=f"{NAME}.possible", msg_key=f"{NAME}.possible",
        params={"location": location, "nb_id": nb_id})


def _header(line: str | None) -> dict[str, str]:
    if not line or ":" not in line:
        return {}
    name, _, value = line.partition(":")
    return {name.strip(): value.strip()}


def run(target: str, ctx) -> list[Finding]:
    scope = ctx.get("scope") or Scope.allow_all()
    limiter = ctx.get("limiter")
    timeout = ctx.get("http_timeout", 15)
    auth = _header(ctx.get("auth_header"))

    urls = list(ctx.get("idor_urls") or [])
    if isinstance(getattr(ctx, "extra", None), dict):
        urls += ctx.extra.get("crawled_urls") or []
    targets = id_targets(urls)[:MAX_TARGETS]
    if not targets:
        return [Finding(
            NAME, "No id-bearing URLs to test", "info",
            "Provide --idor-url with a numeric id, or run with the crawl module "
            "so URLs like ?id=123 or /items/5 are discovered.",
            rule_id=f"{NAME}.no-targets")]

    findings: list[Finding] = []
    for url, kind, cur in targets:
        nb_id = _neighbour(cur)
        nb_url = swap_id(url, kind, nb_id)
        try:
            base = scoped_get(url, scope, timeout=timeout, auth_headers=auth,
                              limiter=limiter)
            nb = scoped_get(nb_url, scope, timeout=timeout, auth_headers=auth,
                            limiter=limiter)
        except (ScopeViolation, Exception):  # noqa: BLE001
            continue
        loc = f"{urlparse(url).path}?{kind}" if kind.startswith("query") \
            else urlparse(url).path
        f = analyze_idor(loc, base.status_code, len(base.content),
                         nb_id, nb.status_code, len(nb.content))
        if f:
            findings.append(f)

    if not findings:
        findings.append(Finding(
            NAME, "No IDOR signal found", "info",
            f"Tested {len(targets)} id-bearing endpoint(s); neighbouring ids did "
            "not return distinct objects.",
            rule_id=f"{NAME}.clean", params={"tested": len(targets)}))
    return findings
