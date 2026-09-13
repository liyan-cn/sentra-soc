from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class SlidingWindowLimiter:
    """Small per-process limiter for protecting authentication work and SQLite writes."""

    def __init__(self, limit: int, window_seconds: int = 60):
        self.limit = max(0, int(limit))
        self.window_seconds = max(1, int(window_seconds))
        self._entries: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._calls = 0

    def allow(self, key: str, now: float | None = None) -> bool:
        if self.limit == 0:
            return True
        current = time.monotonic() if now is None else now
        cutoff = current - self.window_seconds
        with self._lock:
            self._calls += 1
            if self._calls % 1000 == 0:
                for stale_key in [name for name, values in self._entries.items()
                                  if not values or values[-1] <= cutoff]:
                    self._entries.pop(stale_key, None)
            entries = self._entries[key]
            while entries and entries[0] <= cutoff:
                entries.popleft()
            if len(entries) >= self.limit:
                return False
            entries.append(current)
            return True
