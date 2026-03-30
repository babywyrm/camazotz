"""In-memory token-bucket rate limiter keyed by client + difficulty."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

LIMITS: dict[str, int] = {
    "easy": 0,
    "medium": 30,
    "hard": 10,
}

WINDOW_SECONDS: float = 60.0


@dataclass
class _Bucket:
    tokens: int = 0
    window_start: float = field(default_factory=time.monotonic)


class TokenBucketLimiter:
    def __init__(self) -> None:
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def allow(self, client_id: str, *, difficulty: str) -> bool:
        limit = LIMITS.get(difficulty, 0)
        if limit == 0:
            return True

        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.setdefault(client_id, _Bucket(window_start=now))
            if now - bucket.window_start >= WINDOW_SECONDS:
                bucket.tokens = 0
                bucket.window_start = now
            if bucket.tokens >= limit:
                return False
            bucket.tokens += 1
            return True

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()
