"""Trend page: how each host's findings changed across runs (``recon trend``).

Reads every ``<output_dir>/<host>_<stamp>/report.json`` and writes one
self-contained HTML page: per host, a stacked bar per run (findings by
severity) plus the same numbers as a table, with new/resolved counts from the
baseline diff. Like the HTML report it loads nothing external, and all text is
escaped because targets and paths come from report files.

Colours are validated for this chart (light and dark separately, with the
dataviz palette checker): the report's two reds were too close to tell apart
when stacked, so critical is purple here.
"""
from __future__ import annotations

import glob
import html
import json
import os
from datetime import datetime, timezone

from .findings import SEVERITIES
from .i18n import DEFAULT_LANG

LIGHT = {"critical": "#7a2a8c", "high": "#d1242f", "medium": "#bf8700",
         "low": "#0969da", "info": "#008f6f"}
DARK = {"critical": "#b45cc4", "high": "#ea5876", "medium": "#b18c17",
        "low": "#3f8ae0", "info": "#18a37f"}

TEXT = {
    "en": {"title": "Scan trend", "runs": "runs", "run": "Run", "total": "Total",
           "new": "New", "resolved": "Resolved", "suppressed": "Suppressed",
           "throttled": "Throttled", "empty": "No reports found in",
           "generated": "Generated", "chart": "Findings per run by severity"},
    "tr": {"title": "Tarama trendi", "runs": "tarama", "run": "Tarama", "total": "Toplam",
           "new": "Yeni", "resolved": "Çözülen", "suppressed": "Bastırılan",
           "throttled": "Kısıtlanan", "empty": "Şurada rapor bulunamadı:",
           "generated": "Oluşturma", "chart": "Taramalara göre önem dağılımı"},
}


def _esc(s: object) -> str:
    return html.escape(str(s), quote=True)


def collect_runs(output_dir: str, last: int = 20) -> dict[str, list[dict]]:
    """{host_slug: [run, ...]} oldest first, at most `last` runs per host."""
    hosts: dict[str, list[dict]] = {}
    for path in glob.glob(os.path.join(output_dir, "*_*", "report.json")):
        run_dir = os.path.basename(os.path.dirname(path))
        slug, _, stamp = run_dir.rpartition("_")
        if not slug:
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        counts = data.get("counts") or {}
        diff = data.get("diff") or {}
        hosts.setdefault(slug, []).append({
            "stamp": stamp,
            "target": data.get("target", slug),
            "when": data.get("generated_at", ""),
            "counts": {s: int(counts.get(s, 0)) for s in SEVERITIES},
            "new": diff.get("new"), "resolved": diff.get("resolved"),
            "suppressed": len(data.get("suppressed") or []),
            "throttled": (data.get("meta") or {}).get("throttled_responses", 0),
        })
    for slug in hosts:
        hosts[slug] = sorted(hosts[slug], key=lambda r: r["stamp"])[-last:]
    return dict(sorted(hosts.items()))


def _label(stamp: str) -> str:
    """20261012-091500 -> 10-12 09:15"""
    try:
        return datetime.strptime(stamp, "%Y%m%d-%H%M%S").strftime("%m-%d %H:%M")
    except ValueError:
        return stamp


def _day(stamp: str) -> str:
    """20261012-091500 -> 10-12 (axis label; the time is in tooltip and table)"""
    return _label(stamp).split(" ")[0]


def _bars_svg(runs: list[dict], title: str) -> str:
    # viewBox ~ rendered size, so 12px text stays 12px; narrow screens scroll
    # the chart box instead of shrinking the text
    width, height, pad_l, pad_b, pad_t = 940, 240, 40, 30, 10
    plot_h = height - pad_b - pad_t
    peak = max((sum(r["counts"].values()) for r in runs), default=0) or 1
    slot = (width - pad_l) / max(len(runs), 1)
    bar_w = max(6.0, min(36.0, slot * 0.6))
    order = list(SEVERITIES)                    # info at the bottom, critical on top
    parts = [f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{_esc(title)}">']
    for frac in (0.5, 1.0):                     # recessive grid + y labels
        y = pad_t + plot_h * (1 - frac)
        parts.append(f'<line class="grid" x1="{pad_l}" x2="{width}" y1="{y:.1f}" y2="{y:.1f}"/>')
        parts.append(f'<text class="axis" x="{pad_l - 6}" y="{y + 4:.1f}" '
                     f'text-anchor="end">{round(peak * frac)}</text>')
    parts.append(f'<line class="base" x1="{pad_l}" x2="{width}" '
                 f'y1="{pad_t + plot_h}" y2="{pad_t + plot_h}"/>')
    label_px = 52                               # "10-12" at 12px plus breathing room
    every = max(1, -(-label_px // max(int(slot), 1)))   # ceil: labels never collide
    for i, r in enumerate(runs):
        x = pad_l + slot * i + (slot - bar_w) / 2
        y = pad_t + plot_h
        segs = [(s, r["counts"][s]) for s in order if r["counts"][s]]
        tip = " · ".join(f"{n} {s}" for s, n in reversed(segs)) or "0"
        for j, (sev, n) in enumerate(segs):
            h = plot_h * n / peak
            top = j == len(segs) - 1
            seg_h = max(h - (0 if top else 2), 1)     # 2px surface gap between fills
            y -= h
            if top and seg_h > 4:                     # 4px rounded data-end
                parts.append(
                    f'<path class="s-{sev}" d="M{x:.1f},{y + seg_h:.1f} V{y + 4:.1f} '
                    f'Q{x:.1f},{y:.1f} {x + 4:.1f},{y:.1f} H{x + bar_w - 4:.1f} '
                    f'Q{x + bar_w:.1f},{y:.1f} {x + bar_w:.1f},{y + 4:.1f} '
                    f'V{y + seg_h:.1f} Z"/>')
            else:
                parts.append(f'<rect class="s-{sev}" x="{x:.1f}" y="{y:.1f}" '
                             f'width="{bar_w:.1f}" height="{seg_h:.1f}"/>')
        # hit target: the whole column, wider than the bar
        parts.append(f'<rect class="hit" x="{pad_l + slot * i:.1f}" y="{pad_t}" '
                     f'width="{slot:.1f}" height="{plot_h}" '
                     f'data-tip="{_esc(_label(r["stamp"]))}: {_esc(tip)}"/>')
        if i % every == 0 or i == len(runs) - 1:
            parts.append(f'<text class="axis" x="{x + bar_w / 2:.1f}" y="{height - 8}" '
                         f'text-anchor="middle">{_esc(_day(r["stamp"]))}</text>')
    parts.append("</svg>")
    return "".join(parts)


def _table(runs: list[dict], t: dict) -> str:
    head = "".join(f"<th>{_esc(s)}</th>" for s in reversed(SEVERITIES))
    rows = []
    for r in reversed(runs):                    # newest first in the table
        cells = "".join(f"<td>{r['counts'][s]}</td>" for s in reversed(SEVERITIES))
        dash = "–"
        rows.append(
            f"<tr><td>{_esc(_label(r['stamp']))}</td>{cells}"
            f"<td>{sum(r['counts'].values())}</td>"
            f"<td>{dash if r['new'] is None else r['new']}</td>"
            f"<td>{dash if r['resolved'] is None else r['resolved']}</td>"
            f"<td>{r['suppressed'] or dash}</td><td>{r['throttled'] or dash}</td></tr>")
    return (f"<div class='wrap'><table><thead><tr><th>{_esc(t['run'])}</th>{head}<th>{_esc(t['total'])}</th>"
            f"<th>{_esc(t['new'])}</th><th>{_esc(t['resolved'])}</th>"
            f"<th>{_esc(t['suppressed'])}</th><th>{_esc(t['throttled'])}</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></div>")


def to_trend_html(hosts: dict[str, list[dict]], output_dir: str,
                  lang: str = DEFAULT_LANG) -> str:
    t = TEXT.get(lang, TEXT["en"])
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    legend = "".join(f'<span class="key"><i class="k-{s}"></i>{_esc(s)}</span>'
                     for s in reversed(SEVERITIES))
    sections = []
    for runs in hosts.values():
        target = runs[-1]["target"]
        sections.append(
            f"<section><h2>{_esc(target)} <small>{len(runs)} {_esc(t['runs'])}</small></h2>"
            f"<div class='legend'>{legend}</div>"
            f"<div class='chart'>{_bars_svg(runs, t['chart'] + ' — ' + str(target))}</div>"
            f"{_table(runs, t)}</section>")
    if not sections:
        sections.append(f"<p>{_esc(t['empty'])} <code>{_esc(output_dir)}</code></p>")

    def palette(colors: dict[str, str]) -> str:
        return "".join(f".s-{s},.k-{s}{{fill:{c};background:{c}}}" for s, c in colors.items())

    return f"""<!doctype html>
<html lang="{_esc(lang)}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(t['title'])}</title>
<style>
  :root {{ color-scheme: light dark; --bg:#fcfcfb; --fg:#1f2328; --muted:#6e7781;
    --line:#d0d7de; --grid:#eaeef2; --tip:#1f2328; --tipfg:#fff; }}
  @media (prefers-color-scheme: dark) {{ :root {{ --bg:#1a1a19; --fg:#e6edf3;
    --muted:#8b949e; --line:#30363d; --grid:#262c33; --tip:#e6edf3; --tipfg:#1a1a19; }} }}
  body {{ font: 15px/1.5 system-ui, sans-serif; margin:0; background:var(--bg); color:var(--fg); }}
  main {{ padding: 16px; max-width: 980px; margin: 0 auto; }}
  h1 {{ font-size:20px; margin:8px 0 2px; }} h2 {{ font-size:16px; margin:28px 0 6px; }}
  h2 small, .meta, .axis {{ color:var(--muted); font-weight:400; }}
  .meta {{ font-size:13px; }}
  .chart {{ overflow-x:auto; margin-top:6px; }}
  svg {{ width:100%; min-width:600px; height:auto; display:block; }}
  .axis {{ font-size:12px; fill:var(--muted); }}
  code {{ word-break:break-all; }}
  .grid {{ stroke:var(--grid); stroke-width:1; }} .base {{ stroke:var(--line); stroke-width:1; }}
  .hit {{ fill:transparent; cursor:default; }} .hit:hover {{ fill:var(--grid); fill-opacity:.35; }}
  .legend {{ display:flex; gap:14px; flex-wrap:wrap; font-size:12px; color:var(--muted); }}
  .key i {{ display:inline-block; width:10px; height:10px; border-radius:2px; margin-right:5px; vertical-align:-1px; }}
  {palette(LIGHT)}
  @media (prefers-color-scheme: dark) {{ {palette(DARK)} }}
  .wrap {{ overflow-x:auto; }}
  table {{ border-collapse:collapse; width:100%; font-size:13px; margin-top:8px; }}
  th, td {{ text-align:right; padding:5px 8px; border-bottom:1px solid var(--line); white-space:nowrap; }}
  th:first-child, td:first-child {{ text-align:left; }}
  th {{ color:var(--muted); font-weight:600; }}
  #tip {{ position:fixed; pointer-events:none; background:var(--tip); color:var(--tipfg);
    font-size:12px; padding:4px 8px; border-radius:4px; display:none; }}
</style></head>
<body><main>
  <h1>{_esc(t['title'])}</h1>
  <div class="meta">{_esc(t['generated'])}: {now} · <code>{_esc(output_dir)}</code></div>
  {''.join(sections)}
</main>
<div id="tip" role="tooltip"></div>
<script>
var tip = document.getElementById('tip');
document.querySelectorAll('.hit').forEach(function (el) {{
  el.addEventListener('mousemove', function (e) {{
    tip.textContent = el.dataset.tip; tip.style.display = 'block';
    var x = Math.min(e.clientX + 12, window.innerWidth - tip.offsetWidth - 8);
    tip.style.left = x + 'px'; tip.style.top = (e.clientY - 34) + 'px';
  }});
  el.addEventListener('mouseleave', function () {{ tip.style.display = 'none'; }});
}});
</script>
</body></html>"""


def write_trend(output_dir: str, out_path: str | None = None, last: int = 20,
                lang: str = DEFAULT_LANG) -> str:
    out_path = out_path or os.path.join(output_dir, "trend.html")
    page = to_trend_html(collect_runs(output_dir, last), output_dir, lang)
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(page)
    return out_path
