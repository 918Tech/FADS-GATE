from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class RateLimitExceeded(ValueError):
    pass


_LOCK = threading.RLock()
_BUCKETS: dict[str, deque[float]] = defaultdict(deque)


def check_rate_limit(
    key: str,
    *,
    limit: int,
    window_seconds: int,
    now: float | None = None,
) -> None:
    current = time.time() if now is None else float(now)
    cutoff = current - window_seconds
    with _LOCK:
        bucket = _BUCKETS[key]
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()
        if len(bucket) >= limit:
            raise RateLimitExceeded("rate limit exceeded")
        bucket.append(current)
