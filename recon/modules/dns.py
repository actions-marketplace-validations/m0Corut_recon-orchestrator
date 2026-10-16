"""DNS & email-security checks: SPF, DMARC, DKIM, CAA, MX.

Highest-signal, lowest-risk module: entirely passive (DNS queries only, no
traffic to the target web app), finishes in seconds. Email-spoofing
misconfiguration is one of the most common real-world gaps.

Requires dnspython (``pip install recon-orchestrator[dns]``). Analysis is split
into pure functions that take record strings, so they are unit-tested without
any DNS resolution.
"""
from __future__ import annotations

from urllib.parse import urlparse

from ..findings import Finding

NAME = "dns"
NEEDS_DOCKER = False

COMMON_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "mail", "dkim", "s1", "s2",
]


def _domain(target: str) -> str:
    host = urlparse(target).hostname or target
    parts = host.split(".")
    # naive registrable domain: last two labels (good enough for most TLDs)
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


# ---- pure analysis -------------------------------------------------------

def analyze_spf(txt_records: list[str], has_mx: bool) -> list[Finding]:
    spf = next((r for r in txt_records if r.lower().startswith("v=spf1")), None)
    if not spf:
        if has_mx:
            return [Finding(NAME, "No SPF record", "medium",
                            "Domain sends mail (MX present) but has no SPF record.",
                            recommendation="Publish an SPF record ending in -all.",
                            rule_id=f"{NAME}.spf-missing")]
        return []
    low = spf.lower()
    if "+all" in low:
        return [Finding(NAME, "SPF allows any sender (+all)", "high",
                        "SPF '+all' lets anyone send as this domain.",
                        evidence=spf, recommendation="Use -all.",
                        rule_id=f"{NAME}.spf-allow-all")]
    if "~all" in low:
        return [Finding(NAME, "SPF softfail (~all)", "low",
                        "SPF ends with ~all (softfail); spoofed mail may still pass.",
                        evidence=spf, recommendation="Tighten to -all once validated.",
                        rule_id=f"{NAME}.spf-softfail")]
    if "-all" not in low:
        return [Finding(NAME, "SPF has no all qualifier", "low",
                        "SPF record does not end with an 'all' mechanism.",
                        evidence=spf, recommendation="Add -all.",
                        rule_id=f"{NAME}.spf-no-all")]
    return []


def analyze_dmarc(txt_records: list[str]) -> list[Finding]:
    rec = next((r for r in txt_records if r.lower().startswith("v=dmarc1")), None)
    if not rec:
        return [Finding(NAME, "No DMARC record", "medium",
                        "No DMARC policy at _dmarc; spoofing is harder to prevent.",
                        recommendation="Publish a DMARC record (start p=none, rua=).",
                        rule_id=f"{NAME}.dmarc-missing")]
    low = rec.lower().replace(" ", "")
    findings = []
    if "p=none" in low:
        findings.append(Finding(NAME, "DMARC policy is none", "low",
                        "DMARC p=none only monitors; it does not block spoofing.",
                        evidence=rec, recommendation="Move to p=quarantine or reject.",
                        rule_id=f"{NAME}.dmarc-policy-none"))
    if "rua=" not in low:
        findings.append(Finding(NAME, "DMARC without aggregate reporting", "info",
                        "No rua= address; you won't receive DMARC reports.",
                        evidence=rec, recommendation="Add a rua= mailbox.",
                        rule_id=f"{NAME}.dmarc-no-rua"))
    return findings


def analyze_caa(has_caa: bool) -> list[Finding]:
    if not has_caa:
        return [Finding(NAME, "No CAA record", "info",
                        "No CAA record; any CA may issue certificates for this domain.",
                        recommendation="Publish a CAA record for your CA.",
                        rule_id=f"{NAME}.caa-missing")]
    return []


def analyze_dkim(found_selectors: list[str]) -> list[Finding]:
    if found_selectors:
        return [Finding(NAME, "DKIM present", "info",
                        "DKIM key(s) found: " + ", ".join(found_selectors),
                        rule_id=f"{NAME}.dkim-present")]
    return [Finding(NAME, "No DKIM on common selectors", "info",
                    "No DKIM key on common selectors (may use a custom selector).",
                    rule_id=f"{NAME}.dkim-none")]


# ---- live runner ---------------------------------------------------------

def run(target: str, ctx: dict) -> list[Finding]:
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        return [Finding(NAME, "dnspython not installed", "info",
                        "Install the dns extra: pip install recon-orchestrator[dns]",
                        rule_id=f"{NAME}.extra-missing")]

    domain = _domain(target)
    # DNS queries should be snappy; many DKIM selectors are probed, so cap low.
    per_query = min(ctx.get("http_timeout", 15), 4)
    resolver = dns.resolver.Resolver()
    resolver.timeout = per_query
    resolver.lifetime = per_query

    # "absent" (NXDOMAIN/NoAnswer) means the resolver works and the record is not
    # published; a resolver error (timeout/no nameservers) means we cannot tell,
    # so we must not report SPF/DMARC/CAA as "missing" off an unreachable resolver.
    state = {"reachable": False, "errored": False}

    def _query(name: str, rtype: str):
        try:
            ans = resolver.resolve(name, rtype)
            state["reachable"] = True
            return ans
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            state["reachable"] = True
            return None
        except Exception:
            state["errored"] = True
            return None

    def txt(name: str) -> list[str]:
        answers = _query(name, "TXT")
        if answers is None:
            return []
        out = []
        for a in answers:
            out.append(b"".join(a.strings).decode("utf-8", "replace")
                       if hasattr(a, "strings") else str(a).strip('"'))
        return out

    def has(name: str, rtype: str) -> bool:
        return _query(name, rtype) is not None

    findings: list[Finding] = []
    has_mx = has(domain, "MX")
    spf_txt = txt(domain)
    if not state["reachable"] and state["errored"]:
        return [Finding(NAME, "DNS lookups unreliable", "info",
                        "The resolver did not answer (timeout / no nameservers), so "
                        "SPF/DMARC/CAA could not be checked; results would be guesses.",
                        rule_id=f"{NAME}.lookup-unreliable")]
    findings += analyze_spf(spf_txt, has_mx)
    findings += analyze_dmarc(txt(f"_dmarc.{domain}"))
    findings += analyze_caa(has(domain, "CAA"))

    found = [sel for sel in COMMON_DKIM_SELECTORS
             if txt(f"{sel}._domainkey.{domain}")]
    findings += analyze_dkim(found)
    return findings
