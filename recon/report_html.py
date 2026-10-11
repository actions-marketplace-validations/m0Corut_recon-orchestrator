"""Self-contained single-file HTML report.

No external requests (reports contain sensitive data and must not phone home):
inline CSS + a little vanilla JS for severity/module filtering. All finding text
is HTML-escaped because evidence is attacker-influenced.
"""
from __future__ import annotations

import html
from datetime import datetime, timezone

from .findings import SEVERITIES, ScanResult
from .i18n import DEFAULT_LANG, localize, ui

_SEV_COLOR = {
    "critical": "#b1121b", "high": "#d1242f", "medium": "#bf8700",
    "low": "#0969da", "info": "#6e7781",
}


def _esc(s: str) -> str:
    return html.escape(str(s), quote=True)


def to_html(result: ScanResult, meta: dict, lang: str = DEFAULT_LANG,
            diff=None) -> str:
    t = ui(lang)
    counts = result.counts()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    new_fps = diff.new_fingerprints if diff is not None else set()

    tiles = "".join(
        f'<div class="tile" style="border-color:{_SEV_COLOR[s]}">'
        f'<div class="n" style="color:{_SEV_COLOR[s]}">{counts[s]}</div>'
        f'<div class="l">{s}</div></div>'
        for s in reversed(SEVERITIES)
    )

    rows = []
    for f in result.sorted():
        title, detail, rec = localize(f, lang)
        is_new = f.fingerprint in new_fps
        badge = f'<span class="new">{_esc(t["new"])}</span>' if is_new else ""
        rec_html = (f'<div class="rec"><b>{_esc(t["recommendation"])}:</b> '
                    f'{_esc(rec)}</div>') if rec else ""
        ev_html = (f'<div class="ev"><b>{_esc(t["evidence"])}:</b> '
                   f'<code>{_esc(f.evidence)}</code></div>') if f.evidence else ""
        rows.append(f"""
      <tr class="row" data-sev="{f.severity}" data-mod="{_esc(f.module)}">
        <td><span class="sev" style="background:{_SEV_COLOR[f.severity]}">
          {f.severity.upper()}</span></td>
        <td>{_esc(f.module)}</td>
        <td>{_esc(title)} {badge}
          <div class="detail">{_esc(detail)}{ev_html}{rec_html}</div></td>
      </tr>""")

    errors_html = ""
    if result.errors:
        items = "".join(f"<li>{_esc(e)}</li>" for e in result.errors)
        errors_html = f"<h2>{_esc(t['errors'])}</h2><ul class='err'>{items}</ul>"

    analyst_html = ""
    if meta.get("analyst_summary"):
        body_txt = _esc(meta["analyst_summary"]).replace("\n", "<br>")
        analyst_html = (f'<h2>{_esc(t["analyst"])}</h2>'
                        f'<div class="analyst">{body_txt}</div>')

    diff_html = ""
    if diff is not None:
        diff_html = (f'<p class="diff">{_esc(t["baseline"])}: '
                     f'<b>{len(diff.new)}</b> {_esc(t["new"])}, '
                     f'<b>{len(diff.resolved)}</b> {_esc(t["resolved"])}</p>')

    modules = sorted({f.module for f in result.findings})
    mod_opts = "".join(f'<option value="{_esc(m)}">{_esc(m)}</option>'
                       for m in modules)

    return f"""<!doctype html>
<html lang="{lang}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(t['report_title'])} — {_esc(result.target)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 15px/1.5 system-ui, sans-serif; margin: 0; background:#fff; color:#1f2328; }}
  @media (prefers-color-scheme: dark) {{ body {{ background:#0d1117; color:#e6edf3; }}
    .detail,.tile,td,th {{ border-color:#30363d !important; }}
    code {{ background:#161b22; }} header {{ background:#161b22; }} }}
  header {{ padding: 20px 24px; background:#f6f8fa; border-bottom:1px solid #d0d7de; }}
  h1 {{ font-size: 20px; margin:0 0 4px; }}
  .meta {{ color:#6e7781; font-size: 13px; }}
  main {{ padding: 16px 24px; max-width: 1000px; }}
  .tiles {{ display:flex; gap:10px; flex-wrap:wrap; margin:12px 0; }}
  .tile {{ border:2px solid; border-radius:8px; padding:8px 14px; min-width:66px; text-align:center; }}
  .tile .n {{ font-size:22px; font-weight:700; }}
  .tile .l {{ font-size:11px; text-transform:uppercase; color:#6e7781; }}
  .warn {{ background:#fff8c5; border:1px solid #d4a72c; border-radius:6px; padding:8px 12px; font-size:13px; }}
  @media (prefers-color-scheme: dark) {{ .warn {{ background:#2d2a1a; }} }}
  table {{ border-collapse: collapse; width:100%; margin-top:8px; }}
  th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #d0d7de; vertical-align:top; }}
  .sev {{ color:#fff; padding:1px 7px; border-radius:10px; font-size:11px; font-weight:700; white-space:nowrap; }}
  .detail {{ font-size:13px; color:#57606a; margin-top:5px; }}
  @media (prefers-color-scheme: dark) {{ .detail {{ color:#8b949e; }} }}
  code {{ background:#f6f8fa; padding:1px 5px; border-radius:4px; font-size:12px; word-break:break-all; }}
  .new {{ background:#1a7f37; color:#fff; font-size:10px; padding:1px 6px; border-radius:8px; }}
  .err li {{ color:#d1242f; }}
  .controls {{ margin:14px 0; display:flex; gap:10px; flex-wrap:wrap; }}
  select {{ padding:5px; }}
  .rec,.ev {{ margin-top:4px; }}
</style></head>
<body>
<header>
  <h1>{_esc(t['report_title'])} — {_esc(result.target)}</h1>
  <div class="meta">{_esc(t['date'])}: {now} · {_esc(t['modules'])}:
    {_esc(', '.join(meta.get('modules', [])))}</div>
</header>
<main>
  <div class="warn">{_esc(t['warning'])}</div>
  <div class="tiles">{tiles}</div>
  {diff_html}
  <div class="controls">
    <label>{_esc(t['severity'])}:
      <select id="fsev" onchange="flt()">
        <option value="">*</option>
        <option>critical</option><option>high</option><option>medium</option>
        <option>low</option><option>info</option>
      </select></label>
    <label>{_esc(t['module'])}:
      <select id="fmod" onchange="flt()"><option value="">*</option>{mod_opts}</select>
    </label>
  </div>
  <h2>{_esc(t['findings'])}</h2>
  <table><thead><tr>
    <th>{_esc(t['severity'])}</th><th>{_esc(t['module'])}</th><th>{_esc(t['title_col'])}</th>
  </tr></thead><tbody>{''.join(rows)}</tbody></table>
  {errors_html}
  {analyst_html}
</main>
<script>
function flt() {{
  var s = document.getElementById('fsev').value;
  var m = document.getElementById('fmod').value;
  document.querySelectorAll('.row').forEach(function(r) {{
    var ok = (!s || r.dataset.sev === s) && (!m || r.dataset.mod === m);
    r.style.display = ok ? '' : 'none';
  }});
}}
</script>
</body></html>"""
