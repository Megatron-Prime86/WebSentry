"""Tracks blocked/allowed requests and exports them for the dashboard.

Mirrors the pattern used in the NIDS project: an in-memory rolling buffer
(capped so memory/export size stays bounded) plus a periodic JSON export
that the dashboard polls.
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any

MAX_ALERTS = 500
EXPORT_INTERVAL_SECONDS = 1

_EXPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "exports")
os.makedirs(_EXPORTS_DIR, exist_ok=True)

_state_lock = threading.Lock()
_alerts: deque[dict[str, Any]] = deque(maxlen=MAX_ALERTS)
_stats = {"total_requests": 0, "blocked_requests": 0, "allowed_requests": 0}


def log_blocked(src_ip: str, path: str, method: str, match: dict[str, str]) -> dict[str, Any]:
    """Record a blocked (malicious) request."""
    alert = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "path": path,
        "method": method,
        "attack": match["attack"],
        "field": match["field"],
        "value": match["value"][:200],  # cap stored payload size
        "action": "blocked",
    }
    with _state_lock:
        _alerts.append(alert)
        _stats["total_requests"] += 1
        _stats["blocked_requests"] += 1
    return alert


def log_allowed(src_ip: str, path: str, method: str) -> None:
    """Record an allowed (clean) request — counted for stats, not stored in full."""
    with _state_lock:
        _stats["total_requests"] += 1
        _stats["allowed_requests"] += 1


def get_snapshot() -> dict[str, Any]:
    """Return the current alerts + stats for the dashboard."""
    with _state_lock:
        return {
            "alerts": list(_alerts),
            "stats": dict(_stats),
        }


def _export_loop() -> None:
    while True:
        snapshot = get_snapshot()
        try:
            with open(os.path.join(_EXPORTS_DIR, "waf_alerts.json"), "w") as file:
                json.dump(snapshot["alerts"], file, indent=2)
            with open(os.path.join(_EXPORTS_DIR, "waf_stats.json"), "w") as file:
                json.dump(snapshot["stats"], file, indent=2)
        except OSError:
            pass
        time.sleep(EXPORT_INTERVAL_SECONDS)


def start_export_thread() -> None:
    thread = threading.Thread(target=_export_loop, daemon=True)
    thread.start()
