from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import time
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

JUMPER_VERSION = "918-PROX/1"


class ProximityError(ValueError):
    pass


@dataclass(frozen=True)
class LandmarkObservation:
    landmark_id: str
    rssi: int
    channel: int
    observed_at: int
    captive_portal: bool = True


@dataclass(frozen=True)
class AnchorObservation:
    asset_id: str
    observations: tuple[LandmarkObservation, ...]
    echo_score: float
    observed_at: int


def _landmark_key() -> bytes:
    value = os.environ.get("FADS_LANDMARK_KEY", "")
    if len(value) < 32:
        raise ProximityError("FADS_LANDMARK_KEY must be at least 32 characters")
    return value.encode("utf-8")


def pseudonymize_landmark(*, bssid: str, ssid: str = "") -> str:
    normalized = f"{bssid.strip().lower()}|{ssid.strip()}".encode("utf-8")
    digest = hmac.new(_landmark_key(), normalized, hashlib.sha256).hexdigest()
    return f"hmac-sha256:{digest}"


def sanitize_observation(value: Mapping[str, Any], *, now: int | None = None) -> LandmarkObservation:
    bssid = str(value.get("bssid", "")).strip()
    ssid = str(value.get("ssid", "")).strip()
    if not bssid:
        raise ProximityError("bssid is required")
    rssi = int(value.get("rssi", -127))
    channel = int(value.get("channel", 0))
    captive = bool(value.get("captive_portal", False))
    observed_at = int(value.get("observed_at", int(time.time() if now is None else now)))
    if rssi < -127 or rssi > 0:
        raise ProximityError("rssi must be between -127 and 0")
    if channel < 0 or channel > 233:
        raise ProximityError("channel out of range")
    return LandmarkObservation(
        landmark_id=pseudonymize_landmark(bssid=bssid, ssid=ssid),
        rssi=rssi,
        channel=channel,
        observed_at=observed_at,
        captive_portal=captive,
    )


def shared_landmark_score(a: Sequence[LandmarkObservation], b: Sequence[LandmarkObservation]) -> float:
    left = {item.landmark_id: item for item in a if item.captive_portal}
    right = {item.landmark_id: item for item in b if item.captive_portal}
    shared = set(left) & set(right)
    if not shared:
        return 0.0
    scores: list[float] = []
    for key in shared:
        ra = left[key].rssi
        rb = right[key].rssi
        strength = (max(ra, rb) + 127) / 127.0
        similarity = max(0.0, 1.0 - abs(ra - rb) / 60.0)
        scores.append(strength * similarity)
    return sum(scores) / len(scores)


def _softmax(values: Sequence[float]) -> list[float]:
    if not values:
        return []
    maximum = max(values)
    exp_values = [math.exp(v - maximum) for v in values]
    total = sum(exp_values)
    return [v / total for v in exp_values]


def rank_hops(
    *,
    current: AnchorObservation,
    candidates: Iterable[AnchorObservation],
    max_age_seconds: int = 180,
    now: int | None = None,
) -> list[dict[str, Any]]:
    current_time = int(time.time() if now is None else now)
    scored: list[tuple[AnchorObservation, float, float]] = []

    for candidate in candidates:
        if candidate.asset_id == current.asset_id:
            continue
        if current_time - candidate.observed_at > max_age_seconds:
            continue
        landmark = shared_landmark_score(current.observations, candidate.observations)
        if landmark <= 0:
            continue
        echo_gradient = max(-1.0, min(1.0, candidate.echo_score - current.echo_score))
        raw = (landmark * 2.0) + (echo_gradient * 1.25)
        scored.append((candidate, raw, landmark))

    probabilities = _softmax([item[1] for item in scored])
    result: list[dict[str, Any]] = []
    for (candidate, raw, landmark), probability in zip(scored, probabilities):
        result.append(
            {
                "asset_id": candidate.asset_id,
                "probability": probability,
                "score": raw,
                "shared_landmark_score": landmark,
                "echo_score": candidate.echo_score,
                "direction": "closer" if candidate.echo_score > current.echo_score else "not_closer",
            }
        )
    return sorted(result, key=lambda item: item["probability"], reverse=True)


def next_hop(*, current: AnchorObservation, candidates: Iterable[AnchorObservation], now: int | None = None) -> dict[str, Any] | None:
    ranked = rank_hops(current=current, candidates=candidates, now=now)
    for item in ranked:
        if item["direction"] == "closer":
            return {
                "schema": JUMPER_VERSION,
                "current_asset": current.asset_id,
                "next_asset": item["asset_id"],
                "probability": item["probability"],
                "reason": "shared-passive-portal-landmarks-plus-echo-gradient",
                "network_use": False,
                "association": False,
                "authentication": False,
            }
    return None


def encode_anchor(anchor: AnchorObservation) -> str:
    return json.dumps(
        {
            "asset_id": anchor.asset_id,
            "observations": [item.__dict__ for item in anchor.observations],
            "echo_score": anchor.echo_score,
            "observed_at": anchor.observed_at,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
