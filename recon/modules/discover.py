"""Subdomain discovery: turn one domain into an inventory of live web hosts.

Sources (passive first):
  - Certificate Transparency via crt.sh, falling back to Cert Spotter (no key,
    no Docker). crt.sh retired ``?output=json`` in 2026; ``/json?q=`` is used.
  - subfinder, when the runner can execute it (many passive sources)

Each candidate is resolved, its CNAME chain inspected, and in-house hosts are
probed for a live HTTP(S) service. Every live host becomes an info finding
(``discover.host``) so the regular baseline diff reports NEW subdomains on the
next run without any extra machinery.

Safety, because "*.example.com" is not the same as "everything I may test":
  - Discovered hosts are only listed. Scanning them is a separate opt-in
    (``--scan-discovered`` on the CLI).
  - A host whose CNAME chain ends outside the domain (shop -> myshopify.com) is
    third-party: it is never probed or scanned, only checked in DNS for a
    dangling CNAME (subdomain takeover risk).
  - Hosts resolving to private/loopback addresses are skipped unless
    ``allow_private`` is set, like the scope rule for wildcards.
  - Probing goes through ``scoped_get`` with a ``*.<domain>`` scope and the
    shared rate limiter.
"""
from __future__ import annotations

import concurrent.futures as cf
import json
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests

from ..findings import Finding
from ..scope import Scope, ScopeViolation, _is_public_ip, scoped_get

NAME = "discover"
NEEDS_DOCKER = False

CRT_SH = "https://crt.sh/json"
CERTSPOTTER = "https://api.certspotter.com/v1/issuances"
DEFAULT_MAX_HOSTS = 200

# CNAME suffixes of services where a dangling record can usually be claimed by
# anyone (see can-i-take-over-xyz). Matching is a hint, not proof.
TAKEOVER_SUFFIXES = (
    ".github.io", ".herokuapp.com", ".herokudns.com", ".s3.amazonaws.com",
    ".s3-website.amazonaws.com", ".azurewebsites.net", ".cloudapp.net",
    ".cloudapp.azure.com", ".trafficmanager.net", ".blob.core.windows.net",
    ".azureedge.net", ".azure-api.net", ".netlify.app", ".netlify.com",
    ".surge.sh", ".bitbucket.io", ".ghost.io", ".myshopify.com",
    ".pantheonsite.io", ".readme.io", ".helpscoutdocs.com", ".zendesk.com",
    ".unbouncepages.com", ".wordpress.com", ".fly.dev", ".vercel.app",
)


@dataclass
class Host:
    name: str
    addresses: list[str] = field(default_factory=list)
    cname_chain: list[str] = field(default_factory=list)
    nxdomain_cname: bool = False      # CNAME target does not resolve
    third_party: bool = False         # CNAME chain ends outside the domain
    private: bool = False
    url: str | None = None            # live base URL, if any
    status: int | None = None


# ---- candidate sources --------------------------------------------------------

def parse_crtsh(text: str, domain: str) -> set[str]:
    """Pure parser for crt.sh JSON output -> hostnames under `domain`."""
    try:
        rows = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return set()
    names: set[str] = set()
    for row in rows if isinstance(rows, list) else []:
        for name in str(row.get("name_value", "")).splitlines():
            name = name.strip().lower().rstrip(".")
            if name.startswith("*."):
                name = name[2:]
            if name and _under(name, domain) and " " not in name and "@" not in name:
                names.add(name)
    return names


def parse_certspotter(text: str, domain: str) -> set[str]:
    """Pure parser for Cert Spotter issuances (expand=dns_names)."""
    try:
        rows = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return set()
    names: set[str] = set()
    for row in rows if isinstance(rows, list) else []:
        for name in row.get("dns_names", []) or []:
            name = str(name).strip().lower().rstrip(".")
            if name.startswith("*."):
                name = name[2:]
            if name and _under(name, domain):
                names.add(name)
    return names


def parse_subfinder(stdout: str, domain: str) -> set[str]:
    names = set()
    for line in stdout.splitlines():
        line = line.strip().lower().rstrip(".")
        if line.startswith("{"):
            try:
                line = str(json.loads(line).get("host", "")).lower()
            except json.JSONDecodeError:
                continue
        if line and _under(line, domain):
            names.add(line)
    return names


def _under(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


_CT_SOURCES = (
    ("crt.sh", CRT_SH, lambda d: {"q": f"%.{d}"}, parse_crtsh),
    ("certspotter", CERTSPOTTER,
     lambda d: {"domain": d, "include_subdomains": "true", "expand": "dns_names"},
     parse_certspotter),
)


def from_ct(domain: str, timeout: int) -> tuple[set[str], str | None, str | None]:
    """Query CT sources in order; return (names, source used, error summary).

    The first source that answers 200 wins. Both are free public services that
    rate-limit and go down, so a failure here is reported, not fatal.
    """
    errors = []
    for label, url, params, parse in _CT_SOURCES:
        try:
            r = requests.get(url, params=params(domain), timeout=timeout,
                             headers={"User-Agent": "recon-orchestrator"})
        except requests.RequestException as e:
            errors.append(f"{label}: {type(e).__name__}")
            continue
        if r.status_code != 200:
            errors.append(f"{label}: HTTP {r.status_code}")
            continue
        return parse(r.text, domain), label, None
    return set(), None, "; ".join(errors)


def from_subfinder(domain: str, runner, timeout: int) -> set[str]:
    if runner is None or not runner.can_run("subfinder"):
        return set()
    out = runner.run_capture("subfinder", ["-d", domain, "-silent", "-all"], timeout)
    return parse_subfinder(out, domain)


# ---- DNS -----------------------------------------------------------------------

def _resolve_dnspython(name: str) -> tuple[list[str], list[str], bool]:
    """(addresses, cname_chain, cname_target_nxdomain) using dnspython."""
    import dns.resolver

    chain: list[str] = []
    current = name
    for _ in range(8):                         # follow at most 8 CNAME hops
        try:
            ans = dns.resolver.resolve(current, "CNAME", lifetime=5)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            break
        current = str(ans[0].target).rstrip(".").lower()
        chain.append(current)
    addrs: list[str] = []
    nx = False
    for rtype in ("A", "AAAA"):
        try:
            addrs += [r.to_text() for r in dns.resolver.resolve(current, rtype, lifetime=5)]
        except dns.resolver.NXDOMAIN:
            nx = bool(chain)
            break
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
    return addrs, chain, nx


def _resolve_socket(name: str) -> tuple[list[str], list[str], bool]:
    try:
        infos = socket.getaddrinfo(name, None)
    except (socket.gaierror, UnicodeError, OSError):
        return [], [], False
    return sorted({str(i[4][0]) for i in infos}), [], False


def resolve(name: str) -> tuple[list[str], list[str], bool]:
    try:
        import dns.resolver  # noqa: F401
    except ImportError:
        return _resolve_socket(name)
    return _resolve_dnspython(name)


def classify(name: str, domain: str, addresses: list[str], chain: list[str],
             nxdomain_cname: bool) -> Host:
    """Pure: build a Host from resolution results."""
    h = Host(name, addresses=addresses, cname_chain=chain, nxdomain_cname=nxdomain_cname)
    h.third_party = bool(chain) and not _under(chain[-1], domain)
    h.private = bool(addresses) and not all(_is_public_ip(a) for a in addresses)
    return h


# ---- findings ------------------------------------------------------------------

def host_findings(h: Host) -> list[Finding]:
    """Pure: findings for one classified host."""
    out: list[Finding] = []
    if h.nxdomain_cname and h.cname_chain:
        target = h.cname_chain[-1]
        known = target.endswith(TAKEOVER_SUFFIXES)
        out.append(Finding(
            NAME,
            f"{'Possible subdomain takeover' if known else 'Dangling CNAME'}: {h.name}",
            "high" if known else "medium",
            f"{h.name} is a CNAME to {target}, which does not resolve. "
            + ("This provider usually lets anyone claim the name, so an attacker "
               "could serve content on your subdomain." if known else
               "If the name can be registered by someone else, they control "
               "this subdomain."),
            evidence=f"{h.name} -> {' -> '.join(h.cname_chain)} (NXDOMAIN)",
            recommendation="Remove the DNS record or re-claim the resource it points to.",
            rule_id=f"{NAME}.{'takeover' if known else 'dangling-cname'}",
            msg_key=f"{NAME}.{'takeover' if known else 'dangling-cname'}",
            params={"host": h.name, "target": target},
        ))
    if h.url:
        extra = f" (CNAME -> {h.cname_chain[-1]})" if h.cname_chain else ""
        out.append(Finding(
            NAME, f"Live host: {h.name}", "info",
            f"{h.url} answers HTTP {h.status}{extra}.",
            evidence=h.name,
            rule_id=f"{NAME}.host", msg_key=f"{NAME}.host",
            params={"host": h.name, "url": h.url, "status": h.status},
        ))
    return out


def summary_finding(domain: str, hosts: list[Host], live: int,
                    sources: list[str], limited: bool) -> Finding:
    third = sum(1 for h in hosts if h.third_party)
    private = sum(1 for h in hosts if h.private)
    detail = (f"{len(hosts)} name(s) resolved under {domain} from {', '.join(sources)}; "
              f"{live} live in-house web host(s), {third} third-party (not probed), "
              f"{private} private (skipped).")
    if limited:
        detail += " The host limit was reached; raise discover_max_hosts to see more."
    return Finding(NAME, f"Discovery summary for {domain}", "info", detail,
                   evidence=f"{domain}: {len(hosts)} resolved / {live} live",
                   rule_id=f"{NAME}.summary", msg_key=f"{NAME}.summary",
                   params={"domain": domain, "resolved": len(hosts), "live": live,
                           "third": third, "private": private,
                           "sources": ", ".join(sources)})


# ---- probing -------------------------------------------------------------------

def probe(h: Host, scope: Scope, timeout: int, limiter) -> None:
    for scheme in ("https", "http"):
        url = f"{scheme}://{h.name}"
        try:
            r = scoped_get(url, scope, timeout=timeout, limiter=limiter, max_redirects=0)
        except (ScopeViolation, requests.RequestException):
            continue
        h.url, h.status = url, r.status_code
        return


def run(target: str, ctx) -> list[Finding]:
    domain = (urlparse(target).hostname or target).lower()
    timeout = ctx.get("http_timeout", 15)
    allow_private = bool(getattr(ctx.get("scope"), "allow_private", False))
    max_hosts = int(ctx.get("discover_max_hosts") or DEFAULT_MAX_HOSTS)

    names: set[str] = set()
    sources: list[str] = []
    findings: list[Finding] = []
    ct, ct_source, ct_err = from_ct(domain, max(timeout, 30))
    if ct_source:
        sources.append(ct_source)
        names |= ct
    else:
        findings.append(Finding(
            NAME, "Certificate Transparency lookup failed", "info",
            f"No CT source could be queried ({ct_err}); results may be incomplete.",
            rule_id=f"{NAME}.ct-unavailable"))
    sf = from_subfinder(domain, ctx.get("runner"), ctx.get("discover_timeout", 300))
    if sf:
        sources.append("subfinder")
        names |= sf
    names.add(domain)

    ordered = sorted(names)
    limited = len(ordered) > max_hosts
    ordered = ordered[:max_hosts]

    with cf.ThreadPoolExecutor(max_workers=10) as ex:
        resolved = list(ex.map(resolve, ordered))
    hosts = [classify(n, domain, *res) for n, res in zip(ordered, resolved)
             if res[0] or res[2]]          # resolves, or dangling CNAME

    scope = Scope([f"*.{domain}"], allow_private=allow_private)
    probe_list = [h for h in hosts
                  if h.addresses and not h.third_party and (allow_private or not h.private)]
    limiter = ctx.get("limiter")
    with cf.ThreadPoolExecutor(max_workers=10) as ex:
        list(ex.map(lambda h: probe(h, scope, timeout, limiter), probe_list))

    for h in hosts:
        findings += host_findings(h)
    live = [h for h in hosts if h.url]
    findings.append(summary_finding(domain, hosts, len(live), sources or ["dns"], limited))

    # hand the in-house live hosts to the CLI for --scan-discovered
    if isinstance(getattr(ctx, "extra", None), dict):
        ctx.extra["discovered_urls"] = [h.url for h in live if h.name != domain]
    return findings
