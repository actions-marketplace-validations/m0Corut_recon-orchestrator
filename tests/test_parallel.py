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


def test_limiter_backs_off_on_429_and_decays():
    rl = RateLimiter(rate=0)
    rl.observe(429)
    assert rl.penalty == RateLimiter.MIN_PENALTY and rl.throttled == 1
    rl.observe(503)
    assert rl.penalty == RateLimiter.MIN_PENALTY * 2
    for _ in range(100):
        rl.observe(429)
    assert rl.penalty == RateLimiter.MAX_PENALTY
    for _ in range(RateLimiter.DECAY_AFTER):
        rl.observe(200)
    assert rl.penalty == RateLimiter.MAX_PENALTY / 2


def test_limiter_penalty_spaces_even_unlimited_rate():
    rl = RateLimiter(rate=0)
    rl.penalty = 0.05
    start = time.monotonic()
    for _ in range(3):
        rl.acquire()
    assert time.monotonic() - start >= 0.08


def test_limiter_honours_retry_after():
    rl = RateLimiter(rate=0)
    rl.observe(429, "0.1")
    start = time.monotonic()
    rl.acquire()
    assert time.monotonic() - start >= 0.08
    rl2 = RateLimiter(rate=0)
    rl2.observe(429, "Wed, 21 Oct 2015 07:28:00 GMT")   # date form -> ignored
    assert rl2._next <= time.monotonic()


def test_scoped_get_feeds_limiter(monkeypatch):
    import recon.scope as scope_mod
    from recon.scope import Scope, scoped_get

    class R:
        status_code = 429
        headers = {"Retry-After": "0"}
    monkeypatch.setattr(scope_mod.requests, "get", lambda *a, **k: R())
    rl = RateLimiter(rate=0)
    scoped_get("https://example.com/", Scope(["example.com"]), limiter=rl)
    assert rl.throttled == 1
