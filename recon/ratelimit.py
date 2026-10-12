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
    """Aggregate request spacing that also backs off when the target pushes back.

    ``observe()`` is fed each response status. A 429/503 adds a penalty on top of
    the base interval (doubling per hit, capped) and honours ``Retry-After``;
    a run of successful responses decays the penalty again. So ``--rate`` is a
    ceiling, and a struggling or rate-limiting target automatically gets less.
    """

    THROTTLE_STATUSES = (429, 503)
    MIN_PENALTY = 0.25          # seconds added on the first throttle response
    MAX_PENALTY = 10.0          # cap on the added spacing
    MAX_RETRY_AFTER = 60.0      # cap on an honoured Retry-After pause
    DECAY_AFTER = 20            # successes before the penalty is halved

    def __init__(self, rate: float) -> None:
        self.interval = (1.0 / rate) if rate and rate > 0 else 0.0
        self.penalty = 0.0
        self.throttled = 0          # throttle responses seen (for the report)
        self._ok_streak = 0
        self._lock = threading.Lock()
        self._next = 0.0

    def acquire(self) -> None:
        with self._lock:
            spacing = self.interval + self.penalty
            now = time.monotonic()
            if spacing <= 0 and self._next <= now:
                return
            wait = max(0.0, self._next - now)
            self._next = max(now, self._next) + spacing
        if wait > 0:
            time.sleep(wait)

    def observe(self, status: int, retry_after: str | None = None) -> None:
        with self._lock:
            if status in self.THROTTLE_STATUSES:
                self.throttled += 1
                self._ok_streak = 0
                self.penalty = min(self.MAX_PENALTY,
                                   max(self.MIN_PENALTY, self.penalty * 2))
                pause = _parse_retry_after(retry_after)
                if pause:
                    self._next = max(self._next,
                                     time.monotonic() + min(pause, self.MAX_RETRY_AFTER))
                return
            if self.penalty:
                self._ok_streak += 1
                if self._ok_streak >= self.DECAY_AFTER:
                    self._ok_streak = 0
                    self.penalty = self.penalty / 2 if self.penalty > 0.05 else 0.0


def _parse_retry_after(value: str | None) -> float:
    """Seconds from a Retry-After header (delta-seconds form only)."""
    if not value:
        return 0.0
    try:
        return max(0.0, float(value.strip()))
    except ValueError:
        return 0.0      # HTTP-date form: fall back to the exponential penalty


class NullLimiter:
    """No-op limiter for direct module calls/tests."""

    throttled = 0

    def acquire(self) -> None:  # noqa: D401
        return

    def observe(self, status: int, retry_after: str | None = None) -> None:
        return
