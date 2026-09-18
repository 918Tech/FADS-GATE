from __future__ import annotations

import threading
import time
from dataclasses import asdict
from typing import Any

from .proximity_jumper import AnchorObservation, LandmarkObservation

_LOCK = threading.RLock()
_CACHE: dict[str, AnchorObservation] = {}
DEFAULT_TTL_SECONDS = 180


def put_anchor(anchor: AnchorObservation) -> None:
    with _LOCK:
        _CACHE[anchor.asset_id] = anchor


def get_anchor(asset_id: str, *, now: int | None = None, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> AnchorObservation | None:
    current = int(time.time() if now is None else now)
    with _LOCK:
        value = _CACHE.get(asset_id)
        if value is None:
            return None
        if current - value.observed_at > ttl_seconds:
            _CACHE.pop(asset_id, None)
            return None
        return value


def list_anchors(*, now: int | None = None, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> list[AnchorObservation]:
    current = int(time.time() if now is None else now)
    alive: list[AnchorObservation] = []
    with _LOCK:
        stale = []
        for asset_id, value in _CACHE.items():
            if current - value.observed_at > ttl_seconds:
                stale.append(asset_id)
            else:
                alive.append(value)
        for asset_id in stale:
            _CACHE.pop(asset_id, None)
    return alive


def parse_anchor(*, asset_id: str, payload: dict[str, Any], observed_at: int | None = None) -> AnchorObservation:
    now = int(time.time() if observed_at is None else observed_at)
    raw = payload.get("landmarks", [])
    if not isinstance(raw, list):
        raise ValueError("landmarks must be a list")
    observations: list[LandmarkObservation] = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("landmark must be an object")
        landmark_id = str(item.get("landmark_id", "")).strip()
        if not landmark_id.startswith("hmac-sha256:"):
            raise ValueError("landmark_id must be pseudonymized")
        rssi = int(item.get("rssi", -127))
        channel = int(item.get("channel", 0))
        observed = int(item.get("observed_at", now))
        captive = bool(item.get("captive_portal", True))
        if rssi < -127 or rssi > 0:
            raise ValueError("rssi out of range")
        if channel < 0 or channel > 233:
            raise ValueError("channel out of range")
        observations.append(
            LandmarkObservation(
                landmark_id=landmark_id,
                rssi=rssi,
                channel=channel,
                observed_at=observed,
                captive_portal=captive,
            )
        )
    echo_score = float(payload.get("echo_score", 0.0))
    echo_score = max(0.0, min(1.0, echo_score))
    return AnchorObservation(
        asset_id=asset_id,
        observations=tuple(observations),
        echo_score=echo_score,
        observed_at=now,
    )


def public_anchor(anchor: AnchorObservation) -> dict[str, Any]:
    return {
        "asset_id": anchor.asset_id,
        "landmark_count": len(anchor.observations),
        "echo_score": anchor.echo_score,
        "observed_at": anchor.observed_at,
    }
