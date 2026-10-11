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
from .dockerutil import docker_available
from .engine import resolve_modules, run_scan
from .findings import SEVERITY_RANK
from .modules import REGISTRY
from .report import to_json, to_markdown, to_sarif

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
    p.add_argument("-v", "--version", action="version",
                   version=f"recon-orchestrator {__version__}")
    return p


def _load_wordlist(path: str) -> list[str]:
    with open(path, encoding="utf-8", errors="ignore") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]


def _write_reports(result, meta, output_dir, lang="en") -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    host = result.target.split("://", 1)[-1].replace("/", "_").strip("_")
    run_dir = os.path.join(output_dir, f"{host}_{stamp}")
    os.makedirs(run_dir, exist_ok=True)
    for fname, renderer in (("report.md", to_markdown),
                            ("report.json", to_json),
                            ("findings.sarif", to_sarif)):
        with open(os.path.join(run_dir, fname), "w", encoding="utf-8") as fh:
            fh.write(renderer(result, meta, lang))
    return run_dir


def main(argv: list[str] | None = None) -> int:
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

    ctx = ScanContext(rate=args.rate, http_timeout=15)
    if args.wordlist:
        ctx.wordlist_entries = _load_wordlist(args.wordlist)

    ran: list[str] = []

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

    meta = {"modules": ran, "rate": args.rate, "version": __version__}
    run_dir = _write_reports(result, meta, args.output_dir, args.lang)

    counts = result.counts()
    summary = ", ".join(f"{counts[s]} {s}" for s in counts if counts[s]) or "bulgu yok"
    print(f"\n[+] Bitti. Rapor: {run_dir}", file=sys.stderr)
    print(f"    {summary}", file=sys.stderr)

    if args.fail_on:
        threshold = SEVERITY_RANK.get(args.fail_on.lower())
        if threshold is not None and result.max_rank() >= threshold:
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
