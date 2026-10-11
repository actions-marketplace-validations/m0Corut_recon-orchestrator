"""Parser tests — exercise the Docker modules' pure parse functions with
captured structured fixture output, so no Docker or network is needed."""
from recon.modules.ports import parse_nmap_xml
from recon.modules.tls import parse_testssl_json
from recon.modules.web import parse_nuclei_jsonl

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
 <host>
  <ports>
   <port protocol="tcp" portid="22">
     <state state="open"/>
     <service name="ssh" product="OpenSSH" version="8.9p1"/>
   </port>
   <port protocol="tcp" portid="80">
     <state state="open"/>
     <service name="http" product="Caddy"/>
   </port>
   <port protocol="tcp" portid="3306">
     <state state="open"/>
     <service name="mysql" product="MySQL" version="8.0"/>
   </port>
   <port protocol="tcp" portid="23">
     <state state="closed"/>
     <service name="telnet"/>
   </port>
  </ports>
 </host>
</nmaprun>"""

NUCLEI_JSONL = """\
{"template-id":"tech-detect","info":{"name":"Caddy","severity":"info"},"matched-at":"https://x"}
{"template-id":"CVE-2024-1234","info":{"name":"Example RCE","severity":"high","classification":{"cve-id":["CVE-2024-1234"],"cvss-score":9.8}},"matched-at":"https://x/api"}
not-json-line
{"template-id":"weak-ssh","info":{"name":"Weak SSH HMAC","severity":"low"},"matched-at":"x:22"}
"""

TESTSSL_JSON = """[
  {"id":"SSLv3","severity":"HIGH","finding":"SSLv3 is offered"},
  {"id":"TLS1","severity":"MEDIUM","finding":"TLS 1.0 offered"},
  {"id":"cipher_order","severity":"OK","finding":"server sets order"},
  {"id":"TLS1_3","severity":"INFO","finding":"TLS 1.3 offered"}
]"""

TESTSSL_JSON_CLEAN = """[
  {"id":"TLS1_2","severity":"OK","finding":"offered"},
  {"id":"TLS1_3","severity":"OK","finding":"offered"}
]"""


def _by_rule(findings):
    return {f.rule_id: f for f in findings}


# --- nmap XML ---
def test_parse_nmap_flags_db_and_ssh_closed_ignored():
    rules = _by_rule(parse_nmap_xml(NMAP_XML))
    assert rules["ports.exposed-ssh"].severity == "low"
    assert rules["ports.exposed-mysql"].severity == "high"
    assert "ports.exposed-telnet" not in rules  # closed port ignored
    assert "22/ssh" in rules["ports.open-ports"].evidence
    assert "OpenSSH 8.9p1" in rules["ports.exposed-ssh"].evidence


def test_parse_nmap_malformed_xml():
    assert parse_nmap_xml("not xml at all") == []


NMAP_XML_TCPWRAPPED = """<?xml version="1.0"?>
<nmaprun><host><ports>
 <port protocol="tcp" portid="3306"><state state="open"/>
   <service name="tcpwrapped"/></port>
</ports></host></nmaprun>"""


def test_parse_nmap_tcpwrapped_not_claimed_as_db():
    # a firewall answering 3306 as tcpwrapped must NOT be reported as MySQL-high
    rules = _by_rule(parse_nmap_xml(NMAP_XML_TCPWRAPPED))
    assert "ports.exposed-mysql" not in rules
    assert rules["ports.open-unconfirmed"].severity == "info"


# --- nuclei JSONL ---
def test_parse_nuclei_severity_and_cve_enrichment():
    rules = _by_rule(parse_nuclei_jsonl(NUCLEI_JSONL))
    assert rules["web.nuclei.CVE-2024-1234"].severity == "high"
    assert "CVE-2024-1234" in rules["web.nuclei.CVE-2024-1234"].detail
    assert "CVSS: 9.8" in rules["web.nuclei.CVE-2024-1234"].detail
    assert rules["web.nuclei.weak-ssh"].severity == "low"
    assert rules["web.nuclei.tech-detect"].severity == "info"


def test_parse_nuclei_no_match():
    assert "web.nuclei.no-match" in _by_rule(parse_nuclei_jsonl(""))


# --- testssl JSON ---
def test_parse_testssl_flags_old_protocols_skips_ok():
    rules = _by_rule(parse_testssl_json(TESTSSL_JSON))
    assert rules["tls.sslv3"].severity == "high"
    assert rules["tls.tls1"].severity == "medium"
    assert "tls.cipher_order" not in rules  # OK severity skipped


def test_parse_testssl_clean():
    assert "tls.config-ok" in _by_rule(parse_testssl_json(TESTSSL_JSON_CLEAN))


def test_parse_testssl_malformed():
    assert parse_testssl_json("{bad json") == []
