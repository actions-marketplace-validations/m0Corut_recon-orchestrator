import time

from recon.context import ScanContext
from recon.engine import run_scan
from recon.ratelimit import NullLimiter, RateLimiter


def test_rate_limiter_spaces_requests():
    rl = RateLimiter(rate=20)   # 50ms apart
    start = time.monotonic()
    for _ in range(4):
        rl.acquire()
    elapsed = time.monotonic() - start
    # 4 acquisitions -> ~3 intervals of 50ms = ~0.15s (allow slack)
    assert elapsed >= 0.12


def test_rate_limiter_zero_is_noop():
    rl = RateLimiter(rate=0)
    start = time.monotonic()
    for _ in range(100):
        rl.acquire()
    assert time.monotonic() - start < 0.05


def test_null_limiter():
    NullLimiter().acquire()  # does nothing, no error


def test_parallel_runs_all_modules(monkeypatch):
    import recon.modules.cors as cors
    import recon.modules.headers as headers
    monkeypatch.setattr(headers, "run", lambda t, c: [])
    monkeypatch.setattr(cors, "run", lambda t, c: [])
    ctx = ScanContext()
    result = run_scan("https://example.com", ["headers", "cors"], ctx,
                      docker_ok=True, serial=False)
    assert result.errors == []


def test_parallel_dedups_by_fingerprint(monkeypatch):
    from recon.findings import Finding
    dupe = Finding("headers", "t", "low", "d", evidence="e", rule_id="headers.x")
    import recon.modules.cors as cors
    import recon.modules.headers as headers
    # both modules return the same finding fingerprint
    monkeypatch.setattr(headers, "run",
                        lambda t, c: [Finding("headers", "t", "low", "d",
                                              evidence="e", rule_id="headers.x")])
    monkeypatch.setattr(cors, "run",
                        lambda t, c: [Finding("headers", "t", "low", "d",
                                              evidence="e", rule_id="headers.x")])
    ctx = ScanContext()
    result = run_scan("https://example.com", ["headers", "cors"], ctx,
                      docker_ok=True)
    assert len([f for f in result.findings if f.fingerprint == dupe.fingerprint]) == 1
