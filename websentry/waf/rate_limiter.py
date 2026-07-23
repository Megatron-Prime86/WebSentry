"""Per-IP rate limiting — catches brute-force and flooding patterns.

Signature rules (rules/patterns.py) catch payload-shaped attacks. This
catches a different pattern: one source hammering the app with requests,
regardless of what's in them — classic brute-force login attempts, credential
stuffing, or basic DoS-style flooding.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

WINDOW_SECONDS = 10
MAX_REQUESTS_PER_WINDOW = 20  # tune to taste; low enough to demo easily

_lock = threading.Lock()
_request_times: dict[str, deque[float]] = defaultdict(lambda: deque())


def is_rate_limited(src_ip: str) -> bool:
    """Record this request and return True if src_ip has exceeded the limit.

    Uses a sliding window: only requests within the last WINDOW_SECONDS
    count toward the limit, so a burst ages out naturally.
    """
    now = time.monotonic()
    with _lock:
        times = _request_times[src_ip]
        times.append(now)

        while times and now - times[0] > WINDOW_SECONDS:
            times.popleft()

        return len(times) > MAX_REQUESTS_PER_WINDOW
