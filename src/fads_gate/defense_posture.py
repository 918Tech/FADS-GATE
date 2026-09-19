from __future__ import annotations

import json
import os
import threading
import time
from typing import Any

from .beacon_sync import BeaconSyncError, fetch_defense_posture

_LOCK = threading.RLock()
_STATE: dict[str, Any] = {
    "mode": "NORMAL",
    "severity": 0,
    "active_events": 0,
    "updated_at": 0,
    "source": "local-default",
}
_STARTED = False

MODE_RATE_LIMIT_FACTOR = {
    "NORMAL": 1.0,
    "HEIGHTENED": 0.75,
    "CONTAINMENT": 0.5,
    "CRITICAL": 0.25,
}


def enabled() -> bool:
    return os.environ.get("FADS_AUTO_DEPLOY_ON_ATTACK", "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def current_posture() -> dict[str, Any]:
    with _LOCK:
        return dict(_STATE)


def rate_limit_for(base_limit: int) -> int:
    posture = current_posture()
    factor = MODE_RATE_LIMIT_FACTOR.get(str(posture.get("mode", "NORMAL")), 1.0)
    return max(10, int(base_limit * factor))


def _update(value: dict[str, Any]) -> None:
    with _LOCK:
        _STATE.clear()
        _STATE.update(value)
        _STATE["updated_at"] = int(time.time())
        _STATE["source"] = "global-coordinator"


def refresh_once() -> dict[str, Any]:
    if not enabled():
        return current_posture()
    try:
        value = fetch_defense_posture()
        _update(value)
    except BeaconSyncError:
        # Fail safe without globally quarantining unrelated assets.
        with _LOCK:
            _STATE["source"] = "local-degraded"
            _STATE["updated_at"] = int(time.time())
    return current_posture()


def _poll_loop() -> None:
    interval = max(5, int(os.environ.get("FADS_DEFENSE_POLL_SECONDS", "15")))
    while True:
        refresh_once()
        time.sleep(interval)


def start_poller() -> None:
    global _STARTED
    if not enabled() or _STARTED:
        return
    _STARTED = True
    thread = threading.Thread(target=_poll_loop, name="fads-defense-posture", daemon=True)
    thread.start()
