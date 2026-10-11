"""Report rendering: Markdown (human), JSON (machine), SARIF (code scanning)."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .findings import ScanResult, SEVERITIES

_SARIF_LEVEL = {
    "info": "note", "low": "note", "medium": "warning",
    "high": "error", "critical": "error",
}


def to_markdown(result: ScanResult, meta: dict) -> str:
    counts = result.counts()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# Güvenlik Tarama Raporu — {result.target}",
        "",
        f"- **Tarih:** {now}",
        f"- **Modüller:** {', '.join(meta.get('modules', []))}",
        f"- **Özet:** "
        + ", ".join(f"{counts[s]} {s}" for s in reversed(SEVERITIES) if counts[s])
        + (" (bulgu yok)" if not result.findings else ""),
        "",
        "> ⚠️ Yalnızca yetkili olduğunuz sistemlerde kullanın. Bu rapor hassas "
        "bilgi içerebilir; herkese açık paylaşmayın.",
        "",
        "## Bulgular",
        "",
        "| Önem | Modül | Başlık |",
        "|------|-------|--------|",
    ]
    for f in result.sorted():
        lines.append(f"| {f.severity.upper()} | {f.module} | {f.title} |")
    lines += ["", "## Detaylar", ""]
    for f in result.sorted():
        lines.append(f"### [{f.severity.upper()}] {f.title}")
        lines.append(f"- **Modül:** {f.module}")
        lines.append(f"- **Açıklama:** {f.detail}")
        if f.evidence:
            lines.append(f"- **Kanıt:** `{f.evidence}`")
        if f.recommendation:
            lines.append(f"- **Öneri:** {f.recommendation}")
        lines.append("")
    if result.errors:
        lines += ["## Hatalar", ""]
        lines += [f"- {e}" for e in result.errors]
    return "\n".join(lines)


def to_json(result: ScanResult, meta: dict) -> str:
    return json.dumps({
        "target": result.target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "meta": meta,
        "counts": result.counts(),
        "findings": [f.to_dict() for f in result.sorted()],
        "errors": result.errors,
    }, indent=2, ensure_ascii=False)


def to_sarif(result: ScanResult, meta: dict) -> str:
    rules, results = {}, []
    for f in result.findings:
        rule_id = f"{f.module}/{f.title}"[:200]
        rules.setdefault(rule_id, {
            "id": rule_id,
            "shortDescription": {"text": f.title},
            "defaultConfiguration": {"level": _SARIF_LEVEL.get(f.severity, "note")},
        })
        results.append({
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(f.severity, "note"),
            "message": {"text": f.detail + (f"\nKanıt: {f.evidence}" if f.evidence else "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": result.target}
                }
            }],
        })
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "recon-orchestrator",
                "informationUri": "https://github.com/",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)
