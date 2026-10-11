"""Parser tests — exercise the Docker modules' pure parse functions with
captured fixture output, so no Docker or network is needed."""
from recon.modules.ports import parse_nmap
from recon.modules.tls import parse_testssl
from recon.modules.web import parse_nuclei

NMAP_OUT = """\
Starting Nmap
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.9p1 Ubuntu
80/tcp  open  http     Caddy httpd
3306/tcp open mysql    MySQL 8.0
Nmap done
"""

NUCLEI_OUT = """\
[tech-detect:caddy] [http] [info] https://x/login
[ssh-sha1-hmac-algo] [javascript] [low] x:22
[some-cve-2024-1234] [http] [high] https://x/api
"""

TESTSSL_BAD = """\
 SSLv3      offered (NOT ok)
 TLS 1      offered
 TLS 1.2    offered (OK)
"""

TESTSSL_GOOD = """\
 SSLv2      not offered (OK)
 TLS 1.2    offered (OK)
 TLS 1.3    offered (OK): final
"""


def _by_rule(findings):
    return {f.rule_id: f for f in findings}


def test_parse_nmap_flags_db_and_ssh():
    rules = _by_rule(parse_nmap(NMAP_OUT))
    assert rules["ports.exposed-ssh"].severity == "low"
    assert rules["ports.exposed-mysql"].severity == "high"
    assert "22/ssh" in rules["ports.open-ports"].evidence


def test_parse_nmap_empty():
    assert parse_nmap("no ports here") == []


def test_parse_nuclei_severities_and_ids():
    rules = _by_rule(parse_nuclei(NUCLEI_OUT))
    assert rules["web.nuclei.some-cve-2024-1234"].severity == "high"
    assert rules["web.nuclei.ssh-sha1-hmac-algo"].severity == "low"
    assert rules["web.nuclei.tech-detect:caddy"].severity == "info"


def test_parse_nuclei_no_match():
    rules = _by_rule(parse_nuclei(""))
    assert "web.nuclei.no-match" in rules


def test_parse_testssl_flags_old_protocols():
    rules = _by_rule(parse_testssl(TESTSSL_BAD))
    assert rules["tls.sslv3-enabled"].severity == "high"
    assert rules["tls.tls10-enabled"].severity == "medium"


def test_parse_testssl_clean():
    rules = _by_rule(parse_testssl(TESTSSL_GOOD))
    assert "tls.config-ok" in rules
