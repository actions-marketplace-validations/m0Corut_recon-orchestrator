"""Web vulnerability & tech scan via nuclei (Docker), parsing JSONL output.

Using nuclei's ``-jsonl`` instead of the coloured text lines gives a stable,
machine-readable record per finding and brings template name, description, CVE
ids and CVSS score along for free.
"""
from __future__ import annotations

import copy
import json
from urllib.parse import urlparse

from ..findings import Finding
from ..runner import DockerRunner

NAME = "web"
NEEDS_DOCKER = True

VALID_SEV = {"info", "low", "medium", "high", "critical"}


def parse_nuclei_jsonl(stdout: str, severities: str = "") -> list[Finding]:
    """Pure parser for `nuclei -jsonl` output; testable without Docker."""
    findings: list[Finding] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        template = rec.get("template-id") or rec.get("templateID") or "unknown"
        info = rec.get("info", {}) or {}
        sev = str(info.get("severity", "info")).lower()
        if sev not in VALID_SEV:
            sev = "info"
        name = info.get("name") or template
        matched = rec.get("matched-at") or rec.get("matched") or rec.get("host", "")

        # enrich detail with CVE / CVSS when present
        classification = info.get("classification") or {}
        cves = classification.get("cve-id") or []
        if isinstance(cves, str):
            cves = [cves]
        cvss = classification.get("cvss-score")
        extra = []
        if cves:
            extra.append("CVE: " + ", ".join(cves))
        if cvss:
            extra.append(f"CVSS: {cvss}")
        detail = name + (" (" + "; ".join(extra) + ")" if extra else "")

        findings.append(Finding(
            NAME, f"nuclei: {template}", sev, detail,
            evidence=f"{template} -> {matched}",
            rule_id=f"{NAME}.nuclei.{template}",
        ))
    if not findings:
        findings.append(Finding(
            NAME, "nuclei: no matches", "info",
            f"No findings at {severities or 'selected'} severity.",
            rule_id=f"{NAME}.nuclei.no-match",
            params={"severities": severities or "selected"},
        ))
    return findings


SAFE_METHODS = {"get"}


def build_dast_spec(spec: dict, target: str) -> dict | None:
    """Pure: a copy of `spec` that is safe to hand to nuclei's DAST mode.

    - only GET operations are kept, so fuzzing never hits POST/PUT/PATCH/DELETE
      handlers that change data
    - every server address is rewritten to the target's scheme and host (its
      path is kept), so a spec that points at production or a third-party host
      cannot steer the fuzzer out of scope
    Returns None when no GET operation is left.
    """
    if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict):
        return None
    out = copy.deepcopy(spec)
    t = urlparse(target)
    paths: dict = {}
    for path, item in out["paths"].items():
        if not isinstance(item, dict):
            continue
        kept = {k: v for k, v in item.items()
                if k.lower() in SAFE_METHODS or k in ("parameters", "summary",
                                                       "description", "servers")}
        if any(k.lower() in SAFE_METHODS for k in kept):
            kept.pop("servers", None)          # path-level servers: use the global one
            paths[path] = kept
    if not paths:
        return None
    out["paths"] = paths
    if "swagger" in out:                       # Swagger 2.0
        out["host"] = t.netloc
        out["schemes"] = [t.scheme or "https"]
    else:                                      # OpenAPI 3.x
        servers = out.get("servers") or [{"url": "/"}]
        rewritten = []
        for srv in servers:
            sp = urlparse(str(srv.get("url", "/")) if isinstance(srv, dict) else "/")
            rewritten.append({"url": f"{t.scheme}://{t.netloc}{sp.path.rstrip('/')}"})
        out["servers"] = rewritten[:1]
    return out


def _run_dast(target: str, ctx, runner, severities: str) -> list[Finding]:
    from ..modules.openapi import _load_spec
    from ..scope import Scope

    scope = ctx.get("scope") or Scope.allow_all()
    spec_url, spec = _load_spec(target, ctx, scope, ctx.get("limiter"),
                                ctx.get("http_timeout", 15))
    safe = build_dast_spec(spec, target) if spec else None
    if safe is None:
        return [Finding(
            NAME, "DAST skipped: no usable API spec", "info",
            "--dast needs an OpenAPI/Swagger spec with at least one GET "
            "operation (--spec or a common path).",
            rule_id=f"{NAME}.dast-no-spec")]
    if not hasattr(runner, "run_capture_with_input"):
        return []
    mode = "swagger" if "swagger" in safe else "openapi"   # Swagger 2 vs OpenAPI 3
    args = ["-l", "{in}", "-im", mode, "-dast", "-sfv",
            "-severity", severities,
            "-rate-limit", str(ctx.get("rate", 20)),
            "-timeout", "10", "-jsonl", "-silent"]
    stdout = runner.run_capture_with_input(
        "nuclei", args, ctx.get("nuclei_timeout", 1200),
        json.dumps(safe), "openapi.json")
    found = [f for f in parse_nuclei_jsonl(stdout, severities)
             if f.rule_id != f"{NAME}.nuclei.no-match"]
    ops = sum(1 for item in safe["paths"].values() for k in item if k.lower() == "get")
    found.append(Finding(
        NAME, "DAST run on API spec", "info",
        f"nuclei DAST templates ran against {ops} GET operation(s) from {spec_url}.",
        evidence=str(spec_url), rule_id=f"{NAME}.dast-ran",
        params={"ops": ops, "spec": spec_url}))
    return found


def run(target: str, ctx: dict) -> list[Finding]:
    runner = ctx.get("runner") or DockerRunner()
    severities = ctx.get("nuclei_severity", "low,medium,high,critical")
    args = [
        "-u", target,
        "-severity", severities,
        "-rate-limit", str(ctx.get("rate", 20)),
        "-timeout", "10",
        "-jsonl", "-silent",
    ]
    tags = ctx.get("nuclei_tags")
    if tags:
        args += ["-tags", tags]

    stdout = runner.run_capture("nuclei", args, ctx.get("nuclei_timeout", 1200))
    findings = parse_nuclei_jsonl(stdout, severities)
    if ctx.get("dast"):
        findings += _run_dast(target, ctx, runner, severities)
    return findings
