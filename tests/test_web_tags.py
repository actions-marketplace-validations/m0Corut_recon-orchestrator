from recon.context import ScanContext
from recon.modules.web import build_nuclei_args, effective_severities


def test_default_has_no_tags():
    args = build_nuclei_args("https://x", ScanContext())
    assert "-tags" not in args
    assert "info" not in effective_severities(ScanContext())


def test_profile_adds_tags():
    args = build_nuclei_args("https://x", ScanContext(nuclei_profile="panels"))
    assert args[args.index("-tags") + 1] == "panel,exposure"


def test_info_severity_opt_in():
    sev = effective_severities(ScanContext(nuclei_info=True))
    assert sev.startswith("info,")


def test_explicit_tags_override_profile():
    ctx = ScanContext(nuclei_profile="full")
    ctx.nuclei_tags = "cve"
    args = build_nuclei_args("https://x", ctx)
    assert args[args.index("-tags") + 1] == "cve"
