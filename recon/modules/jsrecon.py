"""Client-side JS review: leaked secrets, outdated libraries, exposed source maps.

Fetches the same-origin JavaScript the pages reference and, read-only:
- scans for hard-coded provider keys / private keys / JWTs (the value is ALWAYS
  masked in evidence and never validated against the provider — detection only),
- fingerprints library versions and matches them to a vendored vulnerable-version
  DB (retire.js-style),
- flags reachable `.js.map` source maps (full source leak).

Pure analysis (`scan_secrets`, `detect_libraries`, `evaluate_libraries`,
`analyze_sourcemap`) is split from `run()` so it unit-tests without the network.
Opt-in (`-m jsrecon`); not in the default set.
"""
from __future__ import annotations

import json
import math
import re
from importlib import resources
from urllib.parse import urljoin, urlparse

from ..findings import Finding
from ..scope import Scope, ScopeViolation, scoped_get
from ._pages import parse_html

NAME = "jsrecon"
NEEDS_DOCKER = False

JS_MAX_FILES = 50
JS_MAX_BYTES = 2_000_000

# family -> (regex, severity). Values are masked before they reach a Finding.
SECRET_PATTERNS = {
    "aws-access-key": (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high"),
    "google-api-key": (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high"),
    "stripe-secret-key": (re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"), "high"),
    "slack-token": (re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "high"),
    "github-token": (re.compile(r"\b(?:ghp|gho|ghu|ghs)_[0-9A-Za-z]{36}\b"), "high"),
    "private-key": (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "high"),
    "jwt": (re.compile(
        r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "medium"),
}
_GENERIC_SECRET = re.compile(
    r"""(?i)(?:api[_-]?key|secret|passwd|password|access[_-]?token)\s*[:=]\s*['"]([A-Za-z0-9+/_\-]{20,})['"]""")


def mask(value: str) -> str:
    if len(value) <= 8:
        return value[:1] + "****"
    return f"{value[:4]}****{value[-3:]}"


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in counts.values())


def scan_secrets(js_text: str, source_url: str) -> list[Finding]:
    """Pure: secrets in one JS file. Evidence masks the value; it is never stored raw."""
    out: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    def add(family: str, sev: str, value: str):
        key = (family, value)
        if key in seen:
            return
        seen.add(key)
        out.append(Finding(
            NAME, f"Possible {family} in JavaScript", sev,
            f"A {family}-shaped secret is hard-coded in client-side JS.",
            evidence=f"{source_url}: {mask(value)}",
            recommendation="Move the secret server-side and rotate it.",
            rule_id=f"{NAME}.secret-{family}", msg_key=f"{NAME}.secret",
            params={"family": family, "source": source_url}))

    for family, (rx, sev) in SECRET_PATTERNS.items():
        for m in rx.finditer(js_text):
            add(family, sev, m.group(0))
    for m in _GENERIC_SECRET.finditer(js_text):
        val = m.group(1)
        if _entropy(val) >= 3.5:            # gate: skip low-entropy placeholders
            add("generic-secret", "medium", val)

    if '"apiKey"' in js_text and '"databaseURL"' in js_text:
        out.append(Finding(
            NAME, "Firebase web config in JavaScript", "info",
            "A Firebase client config is present. This is normally public; verify "
            "your Firebase security rules are not relying on it being secret.",
            evidence=source_url, rule_id=f"{NAME}.firebase-config",
            params={"source": source_url}))
    return out


# ---- libraries ----------------------------------------------------------------

_FILENAME_RE = re.compile(r"([a-z][a-z0-9\-]*?)[.\-]v?(\d+\.\d+(?:\.\d+)?)", re.I)
_COMMENT_RES = [
    re.compile(r"(?i)(jquery)\s+(?:javascript library\s+)?v?(\d+\.\d+\.\d+)"),
    re.compile(r"(?i)(bootstrap)\s+v?(\d+\.\d+\.\d+)"),
    re.compile(r"(?i)(lodash)[^0-9]{0,20}(\d+\.\d+\.\d+)"),
    re.compile(r"(?i)(moment\.js|moment)[^0-9]{0,20}(\d+\.\d+\.\d+)"),
    re.compile(r"(?i)(angularjs|angular)[^0-9]{0,20}v?(\d+\.\d+\.\d+)"),
    re.compile(r"(?i)(dompurify)[^0-9]{0,20}(\d+\.\d+\.\d+)"),
    re.compile(r"(?i)(handlebars)[^0-9]{0,20}(\d+\.\d+\.\d+)"),
    re.compile(r"(?i)(vue)[^0-9]{0,8}(\d+\.\d+\.\d+)"),
]


def _norm_lib(name: str) -> str:
    name = name.lower().replace(".js", "")
    return "angularjs" if name == "angular" else name


def detect_libraries(js_text: str, source_url: str) -> list[tuple[str, str, str]]:
    """Pure: [(lib, version, how)] from filename then content/comment."""
    found: dict[str, tuple[str, str]] = {}
    fname = urlparse(source_url).path.rsplit("/", 1)[-1]
    fm = _FILENAME_RE.search(fname)
    if fm:
        found[_norm_lib(fm.group(1))] = (fm.group(2), "filename")
    head = js_text[:2000]
    for rx in _COMMENT_RES:
        m = rx.search(head)
        if m:
            lib = _norm_lib(m.group(1))
            found.setdefault(lib, (m.group(2), "content"))
    return [(lib, ver, how) for lib, (ver, how) in found.items()]


def _vtuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4])


def _version_lt(a: str, b: str) -> bool:
    """True if version `a` is strictly below `b`, tolerant of odd strings.

    Pads both to equal length with zeros so "3.5" compares equal to "3.5.0"
    (otherwise the shorter tuple would sort as less and be a false positive).
    Non-numeric / pre-release junk is dropped by _vtuple and never crashes.
    """
    ta, tb = _vtuple(a), _vtuple(b)
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return ta < tb


def evaluate_libraries(detected: list[tuple[str, str, str]], db: dict,
                       source_url: str) -> list[Finding]:
    out: list[Finding] = []
    for lib, version, how in detected:
        entries = db.get(lib)
        if not entries:
            continue
        for e in entries:
            if _version_lt(version, e["below"]):
                eol = e["severity"] == "low" and "end-of-life" in e.get("note", "")
                out.append(Finding(
                    NAME, f"Outdated JS library: {lib} {version}", e["severity"],
                    f"{lib} {version} < {e['below']}: {e.get('note', '')}",
                    evidence=f"{source_url} ({how}): {lib} {version}",
                    recommendation=f"Upgrade {lib} to {e['below']} or later.",
                    rule_id=f"{NAME}.{'eol-library' if eol else 'vulnerable-library-' + lib}",
                    msg_key=f"{NAME}.vulnerable-library",
                    params={"lib": lib, "version": version, "fixed": e["below"]}))
                break
    return out


# ---- source maps --------------------------------------------------------------

def sourcemap_url(js_url: str, js_text: str) -> str | None:
    m = re.search(r"//[#@]\s*sourceMappingURL=(\S+)", js_text)
    if m and not m.group(1).startswith("data:"):
        return urljoin(js_url, m.group(1))
    return js_url + ".map"


def analyze_sourcemap(map_url: str, status: int, body_head: str) -> Finding | None:
    """Pure: flag a reachable, real source map (not a soft-404)."""
    if status == 200 and '"version"' in body_head and '"sources"' in body_head:
        return Finding(
            NAME, "JavaScript source map exposed", "medium",
            "A .js.map is reachable; it reveals the original (pre-minified) source.",
            evidence=map_url, recommendation="Do not deploy source maps to production.",
            rule_id=f"{NAME}.sourcemap-exposed", params={"map": map_url})
    return None


# ---- run ----------------------------------------------------------------------

def _load_db() -> dict:
    try:
        with resources.files("recon.data").joinpath("js_libs.json").open(encoding="utf-8") as fh:
            return {k: v for k, v in json.load(fh).items() if not k.startswith("_")}
    except Exception:  # noqa: BLE001
        return {}


def _script_urls(target: str, ctx, scope, limiter, timeout, host) -> list[str]:
    urls: list[str] = []
    try:
        r = scoped_get(target, scope, timeout=timeout, limiter=limiter)
        for tag in parse_html(r.text or "").scripts:
            src = urljoin(target, tag.attrs.get("src", ""))
            if (urlparse(src).hostname or "").lower() == host and src not in urls:
                urls.append(src)
    except (ScopeViolation, Exception):  # noqa: BLE001
        pass
    for u in (ctx.get("crawled_urls") or []):
        if u.split("?")[0].endswith(".js") and (urlparse(u).hostname or "").lower() == host \
                and u not in urls:
            urls.append(u)
    return urls[:JS_MAX_FILES]


def run(target: str, ctx) -> list[Finding]:
    scope = ctx.get("scope") or Scope.allow_all()
    limiter = ctx.get("limiter")
    timeout = ctx.get("http_timeout", 15)
    host = (urlparse(target).hostname or "").lower()
    db = _load_db()

    script_urls = _script_urls(target, ctx, scope, limiter, timeout, host)
    if not script_urls:
        return [Finding(NAME, "No same-origin JavaScript found", "info",
                        "Nothing to inspect (no same-host <script src> or .js URLs).",
                        rule_id=f"{NAME}.no-scripts")]

    findings: list[Finding] = []
    inventory: list[str] = []
    for url in script_urls:
        try:
            r = scoped_get(url, scope, timeout=timeout, limiter=limiter,
                           max_bytes=JS_MAX_BYTES)
        except (ScopeViolation, Exception):  # noqa: BLE001
            continue
        text = r.text or ""
        findings += scan_secrets(text, url)
        libs = detect_libraries(text, url)
        inventory += [f"{lib} {ver}" for lib, ver, _ in libs]
        findings += evaluate_libraries(libs, db, url)
        map_url = sourcemap_url(url, text)
        if map_url:
            try:
                mr = scoped_get(map_url, scope, timeout=timeout, limiter=limiter,
                                max_bytes=4096)
                sm = analyze_sourcemap(map_url, mr.status_code, mr.text or "")
                if sm:
                    findings.append(sm)
            except (ScopeViolation, Exception):  # noqa: BLE001
                pass

    if inventory:
        findings.append(Finding(
            NAME, "JavaScript library inventory", "info",
            "Detected: " + ", ".join(sorted(set(inventory))),
            evidence=f"{len(script_urls)} script(s) inspected",
            rule_id=f"{NAME}.library-inventory"))
    return findings
