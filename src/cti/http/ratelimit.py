"""Sliding-window rate limiter."""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable


class RateLimiter:
    """Allow at most ``max_requests`` calls per ``window_seconds``.

    ``acquire()`` blocks until a slot is free. Clock and sleep are injectable for tests.
    """

    def __init__(
        self,
        max_requests: int,
        window_seconds: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if max_requests < 1 or window_seconds <= 0:
            raise ValueError("max_requests must be >= 1 and window_seconds > 0")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._clock = clock
        self._sleep = sleep
        self._times: deque[float] = deque()
        self._lock = threading.Lock()

    def _evict(self, now: float) -> None:
        while self._times and self._times[0] <= now - self.window_seconds:
            self._times.popleft()

    def acquire(self) -> None:
        with self._lock:
            now = self._clock()
            self._evict(now)
            while len(self._times) >= self.max_requests:
                self._sleep(self._times[0] + self.window_seconds - now)
                now = self._clock()
                self._evict(now)
            self._times.append(now)
