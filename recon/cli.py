"""Command-line entry point for recon-orchestrator."""
from __future__ import annotations

import argparse
import importlib
import os
import sys
from datetime import datetime, timezone

from . import __version__
from .dockerutil import docker_available
from .findings import ScanResult
from .report import to_json, to_markdown, to_sarif

# module name -> import path
MODULES = {
    "headers": "recon.modules.headers",
    "cors": "recon.modules.cors",
    "ports": "recon.modules.ports",
    "tls": "recon.modules.tls",
    "web": "recon.modules.web",
    "content": "recon.modules.content",
}
DEFAULT_ORDER = ["headers", "cors", "content", "ports", "tls", "web"]

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
                   help=f"Virgülle modül listesi veya 'all'. Seçenekler: {', '.join(MODULES)}")
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
    p.add_argument("-v", "--version", action="version",
                   version=f"recon-orchestrator {__version__}")
    return p


def _load_wordlist(path: str) -> list[str]:
    with open(path, encoding="utf-8", errors="ignore") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    print(BANNER_WARNING, file=sys.stderr)
    if not args.authorized:
        print("\nHATA: --authorized bayrağı gerekli. Yetkiniz olduğunu onaylamadan "
              "tarama başlatılmaz.", file=sys.stderr)
        return 1

    target = _normalize_target(args.target)

    if args.modules == "all":
        selected = DEFAULT_ORDER
    else:
        selected = [m.strip() for m in args.modules.split(",") if m.strip()]
    unknown = [m for m in selected if m not in MODULES]
    if unknown:
        print(f"HATA: bilinmeyen modül(ler): {', '.join(unknown)}", file=sys.stderr)
        return 1

    ctx = {"rate": args.rate}
    if args.wordlist:
        ctx["wordlist_entries"] = _load_wordlist(args.wordlist)

    docker_ok = docker_available()
    result = ScanResult(target=target)
    ran = []

    for name in selected:
        mod = importlib.import_module(MODULES[name])
        if getattr(mod, "NEEDS_DOCKER", False) and not docker_ok:
            result.errors.append(f"{name}: Docker çalışmıyor, atlandı.")
            print(f"[~] {name}: Docker yok, atlandı.", file=sys.stderr)
            continue
        print(f"[*] {name} çalışıyor...", file=sys.stderr)
        try:
            result.add(*mod.run(target, ctx))
            ran.append(name)
        except Exception as e:  # noqa: BLE001 - modül hatası taramayı durdurmasın
            result.errors.append(f"{name}: {e}")
            print(f"[!] {name} hata verdi: {e}", file=sys.stderr)

    # Write reports
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    host = target.split("://", 1)[-1].replace("/", "_").strip("_")
    run_dir = os.path.join(args.output_dir, f"{host}_{stamp}")
    os.makedirs(run_dir, exist_ok=True)
    meta = {"modules": ran, "rate": args.rate, "version": __version__}

    with open(os.path.join(run_dir, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(to_markdown(result, meta))
    with open(os.path.join(run_dir, "report.json"), "w", encoding="utf-8") as fh:
        fh.write(to_json(result, meta))
    with open(os.path.join(run_dir, "findings.sarif"), "w", encoding="utf-8") as fh:
        fh.write(to_sarif(result, meta))

    counts = result.counts()
    print(f"\n[+] Bitti. Rapor: {run_dir}", file=sys.stderr)
    print("    " + ", ".join(f"{counts[s]} {s}" for s in counts if counts[s])
          or "    bulgu yok", file=sys.stderr)

    if args.fail_on:
        from .findings import SEVERITY_RANK
        threshold = SEVERITY_RANK.get(args.fail_on.lower())
        if threshold is not None and result.max_rank() >= threshold:
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
