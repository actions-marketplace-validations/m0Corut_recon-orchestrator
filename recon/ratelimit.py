"""Process-wide rate limiter shared by active HTTP modules.

When modules run in parallel, each would otherwise apply its own rate, so the
real load on the target multiplies. A single shared limiter makes ``--rate`` an
aggregate ceiling: request start times are spaced by ``1/rate`` seconds across
all threads.
"""
from __future__ import annotations

import threading
import time


class RateLimiter:
    def __init__(self, rate: float) -> None:
        self.interval = (1.0 / rate) if rate and rate > 0 else 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def acquire(self) -> None:
        if self.interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            wait = self._next - now
            if wait < 0:
                wait = 0.0
            self._next = max(now, self._next) + self.interval
        if wait > 0:
            time.sleep(wait)


class NullLimiter:
    """No-op limiter for direct module calls/tests."""

    def acquire(self) -> None:  # noqa: D401
        return
