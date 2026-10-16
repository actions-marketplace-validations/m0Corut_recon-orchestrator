import json
import os

from recon.trend import collect_runs, to_trend_html, write_trend


def _report(root, slug, stamp, counts, diff=None, suppressed=0, target=None):
    d = root / f"{slug}_{stamp}"
    d.mkdir(parents=True)
    data = {"target": target or f"https://{slug}", "generated_at": stamp,
            "counts": counts, "findings": [], "errors": [], "meta": {}}
    if diff:
        data["diff"] = diff
    if suppressed:
        data["suppressed"] = [{"rule_id": "x"}] * suppressed
    (d / "report.json").write_text(json.dumps(data), encoding="utf-8")


def test_collect_groups_sorts_and_limits(tmp_path):
    for i, stamp in enumerate(["20261012-100000", "20261010-100000", "20261011-100000"]):
        _report(tmp_path, "example.com", stamp, {"high": i})
    _report(tmp_path, "api.example.com", "20261012-090000", {"low": 2})
    (tmp_path / ".partial").mkdir()
    runs = collect_runs(str(tmp_path), last=2)
    assert list(runs) == ["api.example.com", "example.com"]
    assert [r["stamp"] for r in runs["example.com"]] == ["20261011-100000",
                                                         "20261012-100000"]


def test_html_is_self_contained_and_escaped(tmp_path):
    _report(tmp_path, "x", "20261012-100000", {"critical": 1, "high": 2, "info": 3},
            diff={"new": 1, "resolved": 0, "unchanged": 5}, suppressed=2,
            target='https://x/"><script>alert(1)</script>')
    page = to_trend_html(collect_runs(str(tmp_path)), str(tmp_path), "en")
    assert "<script>alert(1)" not in page
    assert "http" not in page.split("<body>")[0].replace("https://x", "")  # no external loads
    assert 'data-tip="10-12 10:00: 1 critical · 2 high · 3 info"' in page
    assert "<td>6</td>" in page                    # total
    assert "s-critical" in page and "Findings per run" in page


def test_empty_dir_and_turkish(tmp_path):
    page = to_trend_html(collect_runs(str(tmp_path)), str(tmp_path), "tr")
    assert "rapor bulunamadı" in page


def test_cli_trend_writes_file(tmp_path, capsys):
    from recon.cli import main
    _report(tmp_path, "x", "20261012-100000", {"low": 1})
    assert main(["trend", str(tmp_path)]) == 0
    out = capsys.readouterr().out.strip()
    assert out.endswith("trend.html") and os.path.exists(out)


def test_write_trend_custom_path(tmp_path):
    path = write_trend(str(tmp_path), str(tmp_path / "sub" / "t.html"))
    assert os.path.exists(path)
