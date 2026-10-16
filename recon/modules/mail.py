"""SMTP / mail transport security checks: STARTTLS, MTA-STS, TLS-RPT.

Read-only: EHLO + STARTTLS probe + QUIT only, never MAIL FROM. MX hosts are
often third-party providers, so a host is only probed if it is in scope
(``--scope``); out-of-scope MX hosts are reported as skipped, not scanned.

Requires dnspython for MX lookup (``[dns]`` extra).
"""
from __future__ import annotations

from urllib.parse import urlparse

from ..findings import Finding
from ..scope import Scope, ScopeViolation, scoped_get

NAME = "mail"
NEEDS_DOCKER = False


def _domain(target: str) -> str:
    host = urlparse(target).hostname or target
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


# ---- pure analysis -------------------------------------------------------

def analyze_starttls(mx_host: str, features: set[str]) -> list[Finding]:
    if "starttls" not in {f.lower() for f in features}:
        return [Finding(NAME, f"MX without STARTTLS: {mx_host}", "medium",
                        "Mail server does not advertise STARTTLS; mail may be sent "
                        "in cleartext.",
                        evidence=f"{mx_host}: EHLO features without STARTTLS",
                        recommendation="Enable STARTTLS on the mail server.",
                        rule_id=f"{NAME}.no-starttls")]
    return []


def analyze_mta_sts(has_txt: bool, has_policy: bool) -> list[Finding]:
    if not has_txt and not has_policy:
        return [Finding(NAME, "No MTA-STS", "low",
                        "No MTA-STS record/policy; downgrade attacks on mail are "
                        "easier.",
                        recommendation="Publish an MTA-STS record and policy.",
                        rule_id=f"{NAME}.no-mta-sts")]
    if has_txt and not has_policy:
        return [Finding(NAME, "MTA-STS record without policy", "low",
                        "MTA-STS TXT exists but the policy file is unreachable.",
                        recommendation="Serve /.well-known/mta-sts.txt over HTTPS.",
                        rule_id=f"{NAME}.mta-sts-no-policy")]
    return []


def analyze_tlsrpt(has: bool) -> list[Finding]:
    if not has:
        return [Finding(NAME, "No TLS-RPT", "info",
                        "No SMTP TLS reporting (_smtp._tls); you won't get TLS "
                        "failure reports.",
                        recommendation="Publish a TLS-RPT record.",
                        rule_id=f"{NAME}.no-tlsrpt")]
    return []


# ---- live runner ---------------------------------------------------------

def run(target: str, ctx: dict) -> list[Finding]:
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        return [Finding(NAME, "dnspython not installed", "info",
                        "Install the dns extra: pip install recon-orchestrator[dns]",
                        rule_id=f"{NAME}.extra-missing")]
    import smtplib

    domain = _domain(target)
    scope = ctx.get("scope") or Scope.allow_all()
    limiter = ctx.get("limiter")
    timeout = min(ctx.get("http_timeout", 15), 10)

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    try:
        mx_records = sorted(
            ((r.preference, str(r.exchange).rstrip(".")) for r in
             resolver.resolve(domain, "MX")), key=lambda x: x[0])
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        mx_records = []           # resolver works; the domain simply has no MX
    except Exception:
        return [Finding(NAME, "MX lookup unreliable", "info",
                        f"The resolver did not answer for {domain} (timeout / no "
                        "nameservers); mail security could not be checked.",
                        rule_id=f"{NAME}.lookup-unreliable")]

    findings: list[Finding] = []
    if not mx_records:
        findings.append(Finding(NAME, "No MX records", "info",
                        f"{domain} has no MX records (no mail service?).",
                        rule_id=f"{NAME}.no-mx"))

    for _pref, mx_host in mx_records:
        if not scope.allows(mx_host):
            findings.append(Finding(
                NAME, f"MX out of scope (not probed): {mx_host}", "info",
                "MX host is outside the allowlist; add it to --scope to test it.",
                evidence=mx_host, rule_id=f"{NAME}.mx-out-of-scope"))
            continue
        try:
            smtp = smtplib.SMTP(mx_host, 587, timeout=timeout)
            try:
                smtp.ehlo()
                features = set(smtp.esmtp_features.keys())
                findings += analyze_starttls(mx_host, features)
            finally:
                try:
                    smtp.quit()
                except Exception:
                    pass
        except Exception as e:  # noqa: BLE001
            findings.append(Finding(
                NAME, f"MX unreachable on 587: {mx_host}", "info",
                f"Could not connect/EHLO: {e}", evidence=mx_host,
                rule_id=f"{NAME}.mx-unreachable"))

    # MTA-STS
    def txt(name: str) -> bool:
        try:
            resolver.resolve(name, "TXT")
            return True
        except Exception:
            return False

    has_sts_txt = txt(f"_mta-sts.{domain}")
    has_policy = False
    try:
        policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        if scope.allows(f"mta-sts.{domain}"):
            r = scoped_get(policy_url, scope, timeout=timeout, limiter=limiter)
            has_policy = r.status_code == 200 and "version" in r.text.lower()
    except (ScopeViolation, Exception):
        has_policy = False
    findings += analyze_mta_sts(has_sts_txt, has_policy)
    findings += analyze_tlsrpt(txt(f"_smtp._tls.{domain}"))
    return findings
