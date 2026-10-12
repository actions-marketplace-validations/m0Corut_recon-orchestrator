"""Command-line entry point for recon-orchestrator.

Thin wrapper: parse args, build a ScanContext, delegate to engine.run_scan,
then write the reports. All orchestration lives in recon/engine.py.

Argparse help text (--help) is always English, since it's static reference
text. Runtime messages (banner, progress, errors) follow --lang, defaulting
to English, via recon.i18n.ui().
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone

from . import __version__
from .checkpoint import Checkpoint, path_for
from .config import ConfigError, load_config, write_template
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
from .i18n import DEFAULT_LANG, module_description, ui
from .modules import REGISTRY
from .ratelimit import RateLimiter
from .report import to_json, to_markdown, to_sarif
from .report_html import to_html
from .runner import get_runner
from .scope import Scope
from .suppress import (
    SuppressionError,
    apply_suppressions,
    load_suppressions,
    resolve_path,
)

_RENDERERS = {
    "md": ("report.md", to_markdown),
    "json": ("report.json", to_json),
    "sarif": ("findings.sarif", to_sarif),
    "html": ("report.html", to_html),
}


def _peek_lang(argv: list[str]) -> str:
    """Read --lang from argv before full parsing, for pre-scan messages."""
    for i, a in enumerate(argv):
        if a == "--lang" and i + 1 < len(argv):
            return argv[i + 1]
        if a.startswith("--lang="):
            return a.split("=", 1)[1]
    return DEFAULT_LANG


def _normalize_target(t: str) -> str:
    if not t.startswith(("http://", "https://")):
        return "https://" + t
    return t


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recon",
        description="Tool orchestrator for authorized security testing "
                    "(nmap/nuclei/testssl + built-in checks).",
    )
    p.add_argument("target", nargs="?", default=None,
                   help="Target URL or domain (optional if config targets is used)")
    p.add_argument("-c", "--config", default=None,
                   help="YAML config file (recon.yaml)")
    p.add_argument("-m", "--modules", default=None,
                   help=f"Comma-separated module list or 'all'. Options: {', '.join(REGISTRY)}")
    p.add_argument("-o", "--output-dir", default=None,
                   help="Report output directory (default: recon_runs)")
    p.add_argument("--rate", type=int, default=None,
                   help="Requests/sec cap for active tools (default: 20)")
    p.add_argument("--wordlist", help="Wordlist file for the content module")
    p.add_argument("--authorized", action="store_true",
                   help="Confirms you are authorized to test the target (required)")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="Suppress progress output (summary and errors only)")
    p.add_argument("--fail-on", default=None,
                   help="Exit code 2 if any finding reaches this severity "
                        "(info|low|medium|high|critical)")
    p.add_argument("--lang", default=None, choices=["en", "tr"],
                   help="Report language (default: en)")
    p.add_argument("--scope", default=None,
                   help="Extra allowed hosts (comma-separated; *.example.com "
                        "supported). Default: target host only.")
    p.add_argument("--allow-private", action="store_true",
                   help="Let --scope wildcards reach hosts that resolve to "
                        "private/loopback/link-local addresses (for internal "
                        "systems). Hosts you name exactly are always allowed.")
    p.add_argument("--baseline", default=None,
                   help="Previous report.json or run directory to diff "
                        "new/resolved findings against")
    p.add_argument("--no-auto-baseline", action="store_true",
                   help="Don't automatically use the most recent previous "
                        "run for this host as a baseline")
    p.add_argument("--fail-on-new", default=None,
                   help="Exit code 2 if a NEW finding reaches this severity")
    p.add_argument("--discover", action="store_true",
                   help="Also inventory subdomains (CT logs, subfinder if present), "
                        "probe live hosts, flag dangling CNAMEs")
    p.add_argument("--scan-discovered", action="store_true",
                   help="With --discover: scan each live in-house subdomain too "
                        "(only if you are authorized for all of them)")
    p.add_argument("--resume", action="store_true",
                   help="Reuse modules finished by an interrupted run of the same "
                        "scan instead of re-running them")
    p.add_argument("--crawl-headless", action="store_true",
                   help="crawl/--dast: drive a headless browser so single-page-app "
                        "endpoints are discovered (needs Chromium; all-in-one image has it)")
    p.add_argument("--suppress-file", default=None,
                   help="Accepted-risk file (YAML; default: .reconignore.yml if present)")
    p.add_argument("--notify", action="append", default=None, metavar="URL",
                   help="Webhook to notify on new findings (Slack/Discord/Telegram/"
                        "generic JSON; repeatable)")
    p.add_argument("--notify-env", default=None, metavar="VAR",
                   help="Read webhook URL(s) from this env var, comma-separated (safer)")
    p.add_argument("--notify-min-severity", default=None,
                   help="Only notify for new findings at this severity+ (default: medium)")
    p.add_argument("--jobs", type=int, default=None,
                   help="Max concurrent modules (default: all)")
    p.add_argument("--serial", action="store_true",
                   help="Run modules sequentially instead of in parallel")
    p.add_argument("--format", default=None,
                   help="Report formats (comma-separated): md,json,sarif,html "
                        "(default: all)")
    p.add_argument("--runner", default="auto", choices=["auto", "docker", "native"],
                   help="How external tools are executed (default: auto)")
    p.add_argument("--auth-header", default=None,
                   help="Session header for authz (e.g. 'Cookie: session=...')")
    p.add_argument("--auth-header-env", default=None,
                   help="Read the session header from this env var (safer)")
    p.add_argument("--auth-page", action="append", default=None,
                   help="A path requiring login (repeatable); authz tests these")
    p.add_argument("--spec", default=None,
                   help="OpenAPI/Swagger spec URL/path (for the openapi module)")
    p.add_argument("--dast", action="store_true",
                   help="web module: also run nuclei DAST (fuzzing) templates on the "
                        "GET operations of the API spec (sends attack payloads)")
    p.add_argument("--github-issues", default=None, metavar="OWNER/REPO",
                   help="Open an issue in this repo for new findings (needs GITHUB_TOKEN)")
    p.add_argument("--issue-min-severity", default="high",
                   help="Minimum severity to open an issue for (default: high)")
    p.add_argument("--close-resolved", action="store_true",
                   help="Close issues for findings that are now resolved")
    p.add_argument("--analyst", default=None, choices=["openai", "anthropic"],
                   help="Optional: summarize findings with an LLM (API key from env)")
    p.add_argument("--analyst-model", default=None, help="Analyst model name")
    p.add_argument("--analyst-base-url", default=None,
                   help="OpenAI-compatible endpoint (for local models)")
    p.add_argument("--analyst-include-evidence", action="store_true",
                   help="Also send evidence text to the analyst (default: don't)")
    p.add_argument("-v", "--version", action="version",
                   version=f"recon-orchestrator {__version__}")
    return p


def _notify_urls(args, cfg: dict) -> list[str]:
    urls = list(args.notify or [])
    env_var = args.notify_env or cfg.get("notify_env")
    if env_var:
        urls += [u.strip() for u in os.environ.get(env_var, "").split(",") if u.strip()]
    return urls


def _load_wordlist(path: str) -> list[str]:
    with open(path, encoding="utf-8", errors="ignore") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]


def _host_slug(target: str) -> str:
    return target.split("://", 1)[-1].replace("/", "_").strip("_")


def _write_reports(result, meta, output_dir, lang="en", diff=None,
                   formats=None) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    run_dir = os.path.join(output_dir, f"{_host_slug(result.target)}_{stamp}")
    os.makedirs(run_dir, exist_ok=True)
    for fmt in (formats or list(_RENDERERS)):
        fname, renderer = _RENDERERS[fmt]
        with open(os.path.join(run_dir, fname), "w", encoding="utf-8") as fh:
            fh.write(renderer(result, meta, lang, diff))
    return run_dir


def _run_diff_command(argv: list[str]) -> int:
    """`recon diff <baseline.json> <current.json>` — compare two reports."""
    import argparse as _ap

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
    return 2 if new else 0


def _scan_one(target: str, settings: dict) -> tuple[int, list[str]]:
    """Run a single target end to end.

    Returns (exit code: 0 ok / 1 error / 2 gate hit, live URLs found by the
    discover module, if it ran).
    """
    t = ui(settings["lang"])
    try:
        selected = resolve_modules(settings["modules"])
    except ValueError as e:
        print(f"{t['err']}: {e}", file=sys.stderr)
        return 1, []

    scope = Scope.for_target(target, extra=settings["scope"],
                             allow_private=settings["allow_private"])
    limiter = RateLimiter(settings["rate"])
    ctx = ScanContext(rate=settings["rate"], http_timeout=15, scope=scope,
                      limiter=limiter,
                      runner=get_runner(settings["runner"]),
                      auth_header=settings["auth_header"],
                      auth_pages=settings["auth_pages"])
    if settings.get("spec"):
        ctx.extra["spec"] = settings["spec"]
    ctx.dast = bool(settings.get("dast"))
    ctx.crawl_headless = bool(settings.get("crawl_headless"))
    opts = settings["options"]
    for field in ("top_ports", "nuclei_tags", "nuclei_severity", "content_threads",
                  "http_timeout", "nmap_timeout", "tls_timeout", "nuclei_timeout",
                  "discover_max_hosts", "discover_timeout"):
        if field in opts:
            setattr(ctx, field, opts[field])
    wordlist = settings["wordlist"] or opts.get("wordlist")
    if wordlist:
        ctx.wordlist_entries = _load_wordlist(wordlist)

    ran: list[str] = []
    started_at = datetime.now(timezone.utc).isoformat()

    quiet = settings.get("quiet", False)

    def on_event(kind: str, msg: str) -> None:
        if kind == "run":
            ran.append(msg)
            if not quiet:
                print(f"[*] {target}: {msg} {t['running']}", file=sys.stderr)
        elif kind == "done" and not quiet:
            print(f"[✓] {msg}", file=sys.stderr)
        elif kind == "resume":
            ran.append(msg)
            if not quiet:
                print(f"[↺] {msg}: {t['resumed']}", file=sys.stderr)
        elif kind == "skip" and not quiet:
            print(f"[~] {msg}: {t['skipped']}", file=sys.stderr)
        elif kind == "error":
            print(f"[!] {msg}", file=sys.stderr)

    checkpoint = Checkpoint(path_for(settings["output_dir"], _host_slug(target)),
                            target, selected)
    if settings.get("resume"):
        completed = checkpoint.load()
    else:
        completed = {}
        checkpoint.clear()          # a fresh run must not leave stale state behind

    result = run_scan(target, selected, ctx,
                      docker_ok=docker_available(), on_event=on_event,
                      jobs=settings["jobs"], serial=settings["serial"],
                      completed=completed, on_module_done=checkpoint.record)

    if settings.get("suppressions"):
        expired = apply_suppressions(result, settings["suppressions"])
        for rule in expired:
            print(f"[!] {t['suppress_expired'].format(rule=rule.rule_id, date=rule.expires)}",
                  file=sys.stderr)

    meta = {"modules": ran, "rate": settings["rate"], "version": __version__,
            "started_at": started_at,
            "ended_at": datetime.now(timezone.utc).isoformat()}
    if limiter.throttled:
        # the target answered 429/503: say so, since findings may be incomplete
        meta["throttled_responses"] = limiter.throttled
        print(f"[!] {t['throttled'].format(n=limiter.throttled)}", file=sys.stderr)

    # Optional: analyst summary (opt-in)
    if settings.get("analyst"):
        from .analyst import build_findings_view, summarize
        from .i18n import localize
        provider = settings["analyst"]
        env_key = {"openai": "OPENAI_API_KEY",
                   "anthropic": "ANTHROPIC_API_KEY"}.get(provider, "")
        api_key = os.environ.get(env_key, "")
        base = settings.get("analyst_base_url")
        if not api_key and not base:
            print(f"[!] {env_key} {t['analyst_skipped_no_key']}", file=sys.stderr)
        else:
            view = build_findings_view(result, settings["lang"], localize,
                                       settings["analyst_include_evidence"])
            print(f"[*] {t['analyst_generating']} ({provider})...", file=sys.stderr)
            try:
                meta["analyst_summary"] = summarize(
                    view, provider, api_key=api_key,
                    model=settings.get("analyst_model"), base_url=base)
            except Exception as e:  # noqa: BLE001
                print(f"[!] {t['analyst_error']} {e}", file=sys.stderr)

    diff = None
    baseline_path = settings["baseline"]
    if not baseline_path and not settings["no_auto_baseline"]:
        baseline_path = find_latest_baseline(settings["output_dir"], _host_slug(target))
    if baseline_path:
        baseline = fingerprints_from_report(baseline_path)
        if baseline:
            diff = compute_diff(result, baseline)

    run_dir = _write_reports(result, meta, settings["output_dir"],
                             settings["lang"], diff, settings["formats"])
    checkpoint.clear()

    # Optional: open GitHub issues for new findings
    if settings.get("github_issues") and diff is not None:
        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            print(f"[!] {t['github_skipped_no_token']}", file=sys.stderr)
        else:
            from .i18n import localize
            from .integrations.github import post_findings
            try:
                gh = post_findings(
                    settings["github_issues"], token, diff, localize,
                    settings["lang"], settings["issue_min_severity"],
                    settings["close_resolved"])
                msg = t["github_result"].format(
                    created=len(gh["created"]), closed=len(gh["closed"]))
                print(f"[+] {msg}", file=sys.stderr)
            except Exception as e:  # noqa: BLE001
                print(f"[!] {t['github_error']} {e}", file=sys.stderr)

    # Optional: webhook notification for new findings
    if settings.get("notify_urls"):
        from .i18n import localize
        from .notify import select_new, send
        candidates = diff.new if diff is not None else result.sorted()
        to_send = select_new(candidates, settings["notify_min_severity"])
        if to_send:
            errs = send(settings["notify_urls"], target, to_send, run_dir,
                        localize, settings["lang"])
            for err in errs:
                print(f"[!] {t['notify_error']} {err}", file=sys.stderr)
            sent = len(settings["notify_urls"]) - len(errs)
            if sent and not quiet:
                print(f"[+] {t['notify_sent'].format(n=sent)}", file=sys.stderr)

    counts = result.counts()
    summary = ", ".join(f"{counts[s]} {s}" for s in counts if counts[s]) or t["no_findings_short"]
    print(f"\n[+] {t['scan_done']} {run_dir}", file=sys.stderr)
    print(f"    {summary}", file=sys.stderr)
    if result.suppressed:
        print(f"    {t['suppressed_line'].format(n=len(result.suppressed))}",
              file=sys.stderr)
    if diff is not None:
        print(f"    {t['baseline_line'].format(new=len(diff.new), resolved=len(diff.resolved))}",
              file=sys.stderr)

    discovered = list(ctx.extra.get("discovered_urls", []))
    if settings["fail_on_new"] and exceeds_new_threshold(
            diff or compute_diff(result, {}), settings["fail_on_new"]):
        return 2, discovered
    if settings["fail_on"]:
        threshold = SEVERITY_RANK.get(settings["fail_on"].lower())
        if threshold is not None and result.max_rank() >= threshold:
            return 2, discovered
    return 0, discovered


def _run_trend_command(argv: list[str]) -> int:
    """`recon trend [output_dir]` - one HTML page with each host's history."""
    from .trend import write_trend

    p = argparse.ArgumentParser(prog="recon trend")
    p.add_argument("output_dir", nargs="?", default="recon_runs")
    p.add_argument("-o", "--out", default=None,
                   help="Output file (default: <output_dir>/trend.html)")
    p.add_argument("--last", type=int, default=20, help="Runs per host (default: 20)")
    p.add_argument("--lang", default=DEFAULT_LANG, choices=["en", "tr"])
    a = p.parse_args(argv)
    print(write_trend(a.output_dir, a.out, a.last, a.lang))
    return 0


def _run_modules_command(lang: str) -> int:
    t = ui(lang)
    print(f"{t['available_modules']}\n")
    for name, spec in REGISTRY.items():
        tag = t["docker_tool"] if spec.needs_docker else t["pure_python"]
        active = t["active"] if spec.active else t["passive"]
        desc = module_description(name, spec.description, lang)
        print(f"  {name:10s} [{tag}, {active}] {desc}")
    return 0


def _run_doctor_command(lang: str) -> int:
    import shutil

    from .dockerutil import docker_available
    from .runner import TOOLS
    t = ui(lang)
    print(f"{t['doctor_title']}\n")
    print(f"  {t['docker_label']}: {t['present'] if docker_available() else t['missing']}")
    print(f"  {t['native_tools_label']}")
    labels = {tool: f"{tool} ({binary})" for tool, (_image, binary) in TOOLS.items()}
    width = max(len(label) for label in labels.values())   # one status column
    for tool, (_image, binary) in TOOLS.items():
        found = shutil.which(binary)
        print(f"    {labels[tool]:<{width}} : {found or t['missing']}")
    print(f"  {t['optional_packages_label']}")
    for pkg in ("yaml", "dns"):
        try:
            __import__(pkg)
            print(f"    {pkg}: {t['present']}")
        except ImportError:
            print(f"    {pkg}: {t['missing']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    pre_lang = _peek_lang(raw)
    from .modules import load_plugins
    for warning in load_plugins():
        print(f"[!] {warning}", file=sys.stderr)
    if raw and raw[0] == "diff":
        return _run_diff_command(raw[1:])
    if raw and raw[0] == "modules":
        return _run_modules_command(pre_lang)
    if raw and raw[0] == "doctor":
        return _run_doctor_command(pre_lang)
    if raw and raw[0] == "trend":
        return _run_trend_command(raw[1:])
    if raw and raw[0] == "init":
        path = raw[1] if len(raw) > 1 else "recon.yaml"
        t = ui(pre_lang)
        try:
            write_template(path)
        except ConfigError as e:
            print(f"{t['err']}: {e}", file=sys.stderr)
            return 1
        print(f"{t['wrote_template']} {path}")
        return 0

    args = build_parser().parse_args(argv)
    t = ui(args.lang or pre_lang)

    print(t["banner_warning"], file=sys.stderr)
    if not args.authorized:
        print(f"\n{t['err']}: {t['err_need_authorized']}", file=sys.stderr)
        return 1

    cfg: dict = {}
    if args.config:
        try:
            cfg = load_config(args.config)
        except ConfigError as e:
            print(f"{t['err']} ({t['err_config']}): {e}", file=sys.stderr)
            return 1

    # Resolve targets: positional wins, else config targets.
    if args.target:
        targets = [args.target]
    else:
        targets = list(cfg.get("targets", []))
    if not targets:
        print(f"{t['err']}: {t['err_no_target']}", file=sys.stderr)
        return 1

    cfg_scope = cfg.get("scope", [])
    cli_scope = [s.strip() for s in (args.scope or "").split(",") if s.strip()]
    settings = {
        "modules": args.modules if args.modules is not None else cfg.get("modules", "all"),
        "output_dir": args.output_dir or cfg.get("output_dir", "recon_runs"),
        "rate": args.rate if args.rate is not None else cfg.get("rate", 20),
        "lang": args.lang or cfg.get("lang", "en"),
        "scope": cli_scope or cfg_scope,
        "allow_private": args.allow_private or cfg.get("allow_private", False),
        "fail_on": args.fail_on or cfg.get("fail_on"),
        "fail_on_new": args.fail_on_new or cfg.get("fail_on_new"),
        "baseline": args.baseline,
        "no_auto_baseline": args.no_auto_baseline,
        "wordlist": args.wordlist,
        "jobs": args.jobs,
        "serial": args.serial,
        "runner": args.runner,
        "auth_header": (os.environ.get(args.auth_header_env)
                        if args.auth_header_env else args.auth_header),
        "auth_pages": args.auth_page,
        "spec": args.spec,
        "dast": args.dast,
        "crawl_headless": args.crawl_headless,
        "github_issues": args.github_issues,
        "issue_min_severity": args.issue_min_severity,
        "close_resolved": args.close_resolved,
        "analyst": args.analyst,
        "analyst_model": args.analyst_model,
        "analyst_base_url": args.analyst_base_url,
        "analyst_include_evidence": args.analyst_include_evidence,
        "quiet": args.quiet,
        "resume": args.resume,
        "formats": ([f.strip() for f in args.format.split(",") if f.strip()]
                    if args.format else None),
        "options": cfg.get("options", {}),
        "notify_urls": _notify_urls(args, cfg),
        "notify_min_severity": (args.notify_min_severity
                                or cfg.get("notify_min_severity", "medium")),
        "suppressions": [],
    }
    suppress_path = resolve_path(args.suppress_file or cfg.get("suppress_file"))
    if suppress_path:
        try:
            settings["suppressions"] = load_suppressions(suppress_path)
        except SuppressionError as e:
            print(f"{t['err']} ({t['err_suppress']}): {e}", file=sys.stderr)
            return 1
    if settings["formats"]:
        bad = [f for f in settings["formats"] if f not in _RENDERERS]
        if bad:
            print(f"{t['err']}: {t['err_unknown_formats']}: {', '.join(bad)}",
                  file=sys.stderr)
            return 1

    if args.scan_discovered and not args.discover:
        print(f"{t['err']}: --scan-discovered requires --discover", file=sys.stderr)
        return 1
    if args.discover:
        try:
            names = resolve_modules(settings["modules"])
        except ValueError as e:
            print(f"{t['err']}: {e}", file=sys.stderr)
            return 1
        settings["modules"] = names + ([] if "discover" in names else ["discover"])

    rc = 0
    done = {_normalize_target(x).rstrip("/") for x in targets}
    for raw_target in targets:
        code, discovered = _scan_one(_normalize_target(raw_target), settings)
        rc = max(rc, code)
        extra = [u for u in discovered if u.rstrip("/") not in done]
        if not extra:
            continue
        if not args.scan_discovered:
            if not settings["quiet"]:
                print(f"[i] {t['discovered_hint'].format(n=len(extra))}", file=sys.stderr)
            continue
        print(f"[*] {t['discovered_scanning'].format(n=len(extra))}", file=sys.stderr)
        sub = dict(settings, modules=[m for m in settings["modules"] if m != "discover"])
        for url in extra:
            done.add(url.rstrip("/"))
            rc = max(rc, _scan_one(url, sub)[0])
    return rc


if __name__ == "__main__":
    sys.exit(main())
