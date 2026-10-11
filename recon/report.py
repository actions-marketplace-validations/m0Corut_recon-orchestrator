"""Report rendering: Markdown (human), JSON (machine), SARIF (code scanning)."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .findings import SEVERITIES, ScanResult
from .i18n import DEFAULT_LANG, localize, ui

_SARIF_LEVEL = {
    "info": "note", "low": "note", "medium": "warning",
    "high": "error", "critical": "error",
}


def to_markdown(result: ScanResult, meta: dict, lang: str = DEFAULT_LANG,
                diff=None) -> str:
    counts = result.counts()
    t = ui(lang)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    summary = ", ".join(f"{counts[s]} {s}" for s in reversed(SEVERITIES) if counts[s])
    if not result.findings:
        summary = f"({t['no_findings']})"
    lines = [
        f"# {t['report_title']} — {result.target}",
        "",
        f"- **{t['date']}:** {now}",
        f"- **{t['modules']}:** {', '.join(meta.get('modules', []))}",
        f"- **{t['summary']}:** {summary}",
    ]
    if diff is not None:
        lines.append(
            f"- **{t['baseline']}:** {len(diff.new)} {t['new']}, "
            f"{len(diff.resolved)} {t['resolved']}")
    lines += [
        "",
        f"> {t['warning']}",
        "",
    ]
    if diff is not None and diff.new:
        lines += [f"## {t['new_findings']}", "",
                  f"| {t['severity']} | {t['module']} | {t['title_col']} |",
                  "|------|-------|--------|"]
        for f in diff.new:
            title, _, _ = localize(f, lang)
            lines.append(f"| {f.severity.upper()} | {f.module} | {title} |")
        lines.append("")
    lines += [
        f"## {t['findings']}",
        "",
        f"| {t['severity']} | {t['module']} | {t['title_col']} |",
        "|------|-------|--------|",
    ]
    for f in result.sorted():
        title, _, _ = localize(f, lang)
        lines.append(f"| {f.severity.upper()} | {f.module} | {title} |")
    lines += ["", f"## {t['details']}", ""]
    for f in result.sorted():
        title, detail, rec = localize(f, lang)
        lines.append(f"### [{f.severity.upper()}] {title}")
        lines.append(f"- **{t['module']}:** {f.module}")
        lines.append(f"- **{t['detail']}:** {detail}")
        if f.evidence:
            lines.append(f"- **{t['evidence']}:** `{f.evidence}`")
        if rec:
            lines.append(f"- **{t['recommendation']}:** {rec}")
        lines.append("")
    if result.errors:
        lines += [f"## {t['errors']}", ""]
        lines += [f"- {e}" for e in result.errors]
    return "\n".join(lines)


def to_json(result: ScanResult, meta: dict, lang: str = DEFAULT_LANG,
            diff=None) -> str:
    new_fps = diff.new_fingerprints if diff is not None else set()
    findings = []
    for f in result.sorted():
        title, detail, rec = localize(f, lang)
        d = f.to_dict()
        d["title"], d["detail"], d["recommendation"] = title, detail, rec
        if diff is not None:
            d["baseline_state"] = "new" if f.fingerprint in new_fps else "unchanged"
        findings.append(d)
    out = {
        "target": result.target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "lang": lang,
        "meta": meta,
        "counts": result.counts(),
        "findings": findings,
        "errors": result.errors,
    }
    if diff is not None:
        out["diff"] = {"new": len(diff.new), "resolved": len(diff.resolved),
                       "unchanged": len(diff.unchanged)}
    return json.dumps(out, indent=2, ensure_ascii=False)


INFO_URI = "https://github.com/m0Corut/recon-orchestrator"


def to_sarif(result: ScanResult, meta: dict, lang: str = DEFAULT_LANG,
             diff=None) -> str:
    t = ui(lang)
    new_fps = diff.new_fingerprints if diff is not None else set()
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for f in result.findings:
        title, detail, rec = localize(f, lang)
        if f.rule_id not in rules:
            help_text = detail + (f"\n\n{t['recommendation']}: {rec}" if rec else "")
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": title},
                "fullDescription": {"text": detail or title},
                "help": {"text": help_text or title},
                "helpUri": INFO_URI,
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(f.severity, "note")},
                "properties": {"module": f.module, "severity": f.severity},
            }
        res = {
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL.get(f.severity, "note"),
            "message": {"text": detail + (f"\n{t['evidence']}: {f.evidence}"
                                          if f.evidence else "")},
            "partialFingerprints": {"reconFingerprint/v1": f.fingerprint},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": result.target}
                }
            }],
        }
        if diff is not None:
            res["baselineState"] = "new" if f.fingerprint in new_fps else "unchanged"
        results.append(res)

    invocation = {
        "executionSuccessful": not result.errors,
        "toolExecutionNotifications": [
            {"level": "error", "message": {"text": e}} for e in result.errors
        ],
    }
    if meta.get("started_at"):
        invocation["startTimeUtc"] = meta["started_at"]
    if meta.get("ended_at"):
        invocation["endTimeUtc"] = meta["ended_at"]

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "recon-orchestrator",
                "informationUri": INFO_URI,
                "version": meta.get("version", "0.0.0"),
                "rules": list(rules.values()),
            }},
            "invocations": [invocation],
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)
