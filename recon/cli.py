"""Command-line entry point for recon-orchestrator.

Thin wrapper: parse args, build a ScanContext, delegate to engine.run_scan,
then write the reports. All orchestration lives in recon/engine.py.
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone

from . import __version__
from .context import ScanContext
from .diff import (
    compute_diff,
    exceeds_new_threshold,
    find_latest_baseline,
    fingerprints_from_report,
)
from .dockerutil import docker_available
from .engine import resolve_modules, run_scan
from .findings import SEVERITY_RANK
from .modules import REGISTRY
from .report import to_json, to_markdown, to_sarif
from .scope import Scope

BANNER_WARNING = (
    "UYARI: Bu araç hedefe gerçek istekler gönderir. Yalnızca SAHİBİ OLDUĞUNUZ "
    "veya YAZILI İZNİNİZ olan sistemlerde kullanın. Yetkisiz tarama çoğu ülkede "
    "suçtur. Sorumluluk tamamen size aittir."
)


def _normalize_target(t: str) -> str:
    if not t.startswith(("http://", "https://")):
        return "https://" + t
    return t


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recon",
        description="Yetkili güvenlik taraması için araç orkestratörü "
                    "(nmap/nuclei/testssl + yerleşik kontroller).",
    )
    p.add_argument("target", help="Hedef URL veya alan adı (örn. https://ornek.com)")
    p.add_argument("-m", "--modules", default="all",
                   help=f"Virgülle modül listesi veya 'all'. Seçenekler: {', '.join(REGISTRY)}")
    p.add_argument("-o", "--output-dir", default="recon_runs",
                   help="Rapor çıktı dizini (varsayılan: recon_runs)")
    p.add_argument("--rate", type=int, default=20,
                   help="Aktif araçlar için istek/sn sınırı (varsayılan: 20)")
    p.add_argument("--wordlist", help="content modülü için kelime listesi dosyası")
    p.add_argument("--authorized", action="store_true",
                   help="Hedefi test etmeye yetkili olduğunuzu onaylar (zorunlu)")
    p.add_argument("--fail-on", default=None,
                   help="Bu önem seviyesi+ bulgu varsa çıkış kodu 2 "
                        "(info|low|medium|high|critical)")
    p.add_argument("--lang", default="en", choices=["en", "tr"],
                   help="Rapor dili (varsayılan: en)")
    p.add_argument("--scope", default=None,
                   help="Ek izinli host'lar (virgülle; *.ornek.com destekli). "
                        "Varsayılan: sadece hedef host.")
    p.add_argument("--allow-private", action="store_true",
                   help="Özel/loopback adreslere izin ver (iç sistemler için)")
    p.add_argument("--baseline", default=None,
                   help="Önceki report.json ya da run dizini; yeni/çözülen bulgular "
                        "karşılaştırılır")
    p.add_argument("--no-auto-baseline", action="store_true",
                   help="Aynı host için en son önceki çalıştırmayı otomatik baz alma")
    p.add_argument("--fail-on-new", default=None,
                   help="Bu önem seviyesi+ YENİ bulgu varsa çıkış kodu 2")
    p.add_argument("-v", "--version", action="version",
                   version=f"recon-orchestrator {__version__}")
    return p


def _load_wordlist(path: str) -> list[str]:
    with open(path, encoding="utf-8", errors="ignore") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]


def _host_slug(target: str) -> str:
    return target.split("://", 1)[-1].replace("/", "_").strip("_")


def _write_reports(result, meta, output_dir, lang="en", diff=None) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    run_dir = os.path.join(output_dir, f"{_host_slug(result.target)}_{stamp}")
    os.makedirs(run_dir, exist_ok=True)
    for fname, renderer in (("report.md", to_markdown),
                            ("report.json", to_json),
                            ("findings.sarif", to_sarif)):
        with open(os.path.join(run_dir, fname), "w", encoding="utf-8") as fh:
            fh.write(renderer(result, meta, lang, diff))
    return run_dir


def _run_diff_command(argv: list[str]) -> int:
    """`recon diff <baseline.json> <current.json>` — compare two reports."""
    import argparse as _ap

    from .diff import DiffResult, fingerprints_from_report
    p = _ap.ArgumentParser(prog="recon diff")
    p.add_argument("baseline")
    p.add_argument("current")
    a = p.parse_args(argv)

    base = fingerprints_from_report(a.baseline)
    cur = fingerprints_from_report(a.current)
    base_fps, cur_fps = set(base), set(cur)
    new = [cur[fp] for fp in cur_fps - base_fps]
    resolved = [base[fp] for fp in base_fps - cur_fps]
    unchanged = cur_fps & base_fps
    print(f"new: {len(new)}, resolved: {len(resolved)}, unchanged: {len(unchanged)}")
    for f in sorted(new, key=lambda x: x.get("severity", "")):
        print(f"  + [{f.get('severity','?').upper()}] {f.get('rule_id','?')} "
              f"{f.get('title','')}")
    _ = DiffResult  # keep import meaningful
    return 2 if new else 0


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and raw[0] == "diff":
        return _run_diff_command(raw[1:])

    args = build_parser().parse_args(argv)

    print(BANNER_WARNING, file=sys.stderr)
    if not args.authorized:
        print("\nHATA: --authorized bayrağı gerekli. Yetkiniz olduğunu onaylamadan "
              "tarama başlatılmaz.", file=sys.stderr)
        return 1

    target = _normalize_target(args.target)

    try:
        selected = resolve_modules(args.modules)
    except ValueError as e:
        print(f"HATA: {e}", file=sys.stderr)
        return 1

    extra_scope = [s.strip() for s in (args.scope or "").split(",") if s.strip()]
    scope = Scope.for_target(target, extra=extra_scope,
                             allow_private=args.allow_private)
    ctx = ScanContext(rate=args.rate, http_timeout=15, scope=scope)
    if args.wordlist:
        ctx.wordlist_entries = _load_wordlist(args.wordlist)

    ran: list[str] = []
    started_at = datetime.now(timezone.utc).isoformat()

    def on_event(kind: str, msg: str) -> None:
        if kind == "run":
            print(f"[*] {msg} çalışıyor...", file=sys.stderr)
            ran.append(msg)
        elif kind == "skip":
            print(f"[~] {msg}: Docker yok, atlandı.", file=sys.stderr)
        elif kind == "error":
            print(f"[!] {msg}", file=sys.stderr)

    result = run_scan(target, selected, ctx,
                      docker_ok=docker_available(), on_event=on_event)

    meta = {
        "modules": ran, "rate": args.rate, "version": __version__,
        "started_at": started_at,
        "ended_at": datetime.now(timezone.utc).isoformat(),
    }

    # baseline / diff
    diff = None
    baseline_path = args.baseline
    if not baseline_path and not args.no_auto_baseline:
        baseline_path = find_latest_baseline(args.output_dir, _host_slug(target))
    if baseline_path:
        baseline = fingerprints_from_report(baseline_path)
        if baseline:
            diff = compute_diff(result, baseline)

    run_dir = _write_reports(result, meta, args.output_dir, args.lang, diff)

    counts = result.counts()
    summary = ", ".join(f"{counts[s]} {s}" for s in counts if counts[s]) or "bulgu yok"
    print(f"\n[+] Bitti. Rapor: {run_dir}", file=sys.stderr)
    print(f"    {summary}", file=sys.stderr)
    if diff is not None:
        print(f"    baseline: {len(diff.new)} yeni, {len(diff.resolved)} çözülen",
              file=sys.stderr)

    if args.fail_on_new:
        if exceeds_new_threshold(diff or compute_diff(result, {}), args.fail_on_new):
            return 2
    if args.fail_on:
        threshold = SEVERITY_RANK.get(args.fail_on.lower())
        if threshold is not None and result.max_rank() >= threshold:
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
