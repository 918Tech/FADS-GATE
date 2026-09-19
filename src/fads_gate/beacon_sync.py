from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from .beacon_sync_auth import headers
from .continent_beacons import current_beacon
from .proximity_jumper import AnchorObservation, LandmarkObservation


class BeaconSyncError(RuntimeError):
    pass


@dataclass(frozen=True)
class SyncedCandidate:
    anchor: AnchorObservation
    beacon: dict[str, Any]


def coordinator_urls() -> tuple[str, ...]:
    raw = os.environ.get("FADS_PROXIMITY_COORDINATOR_URLS", "").strip()
    if raw:
        values = tuple(item.strip().rstrip("/") for item in raw.split(",") if item.strip())
        if values:
            return values
    single = os.environ.get("FADS_PROXIMITY_COORDINATOR_URL", "").strip().rstrip("/")
    return (single,) if single else ()


def _serialize_anchor(anchor: AnchorObservation) -> dict[str, Any]:
    beacon = current_beacon()
    return {
        "asset_id": anchor.asset_id,
        "observations": [
            {
                "landmark_id": item.landmark_id,
                "rssi": item.rssi,
                "channel": item.channel,
                "observed_at": item.observed_at,
                "captive_portal": item.captive_portal,
            }
            for item in anchor.observations
        ],
        "echo_score": anchor.echo_score,
        "observed_at": anchor.observed_at,
        "beacon": {
            "id": beacon.beacon_id,
            "logical_continent": beacon.logical_continent,
            "hosting_continent": beacon.hosting_continent,
            "physical_host_region": beacon.physical_host_region,
            "relay_hosted": beacon.relay_hosted,
        },
    }


def publish_anchor(anchor: AnchorObservation) -> None:
    bases = coordinator_urls()
    if not bases:
        raise BeaconSyncError("proximity coordinator URL not configured")
    path = "/v2/beacon-sync/anchor"
    body = json.dumps(_serialize_anchor(anchor), sort_keys=True, separators=(",", ":")).encode("utf-8")
    errors = []
    for base in bases:
        signed = headers(method="POST", path=path, body=body)
        request = urllib.request.Request(
            base + path,
            data=body,
            method="POST",
            headers={"content-type": "application/json", "user-agent": "918-FADS-BeaconSync/1.1", **signed},
        )
        try:
            with urllib.request.urlopen(request, timeout=8) as response:
                payload = json.loads(response.read(262_144))
            if isinstance(payload, dict) and payload.get("status") == "accepted":
                return
            errors.append(f"{base}: rejected")
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            errors.append(f"{base}: {exc}")
    raise BeaconSyncError("; ".join(errors))


def fetch_candidates(*, exclude_asset: str) -> list[SyncedCandidate]:
    bases = coordinator_urls()
    if not bases:
        raise BeaconSyncError("proximity coordinator URL not configured")
    query = urllib.parse.urlencode({"exclude": exclude_asset})
    path = "/v2/beacon-sync/candidates"
    full_path = path + "?" + query
    signed = headers(method="GET", path=full_path, body=b"")
    payload = None
    errors = []
    for base in bases:
        request = urllib.request.Request(
            base + full_path,
            method="GET",
            headers={"user-agent": "918-FADS-BeaconSync/1.1", **signed},
        )
        try:
            with urllib.request.urlopen(request, timeout=8) as response:
                candidate_payload = json.loads(response.read(1_048_576))
            if isinstance(candidate_payload, dict) and isinstance(candidate_payload.get("candidates"), list):
                payload = candidate_payload
                break
            errors.append(f"{base}: invalid response")
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            errors.append(f"{base}: {exc}")
    if payload is None:
        raise BeaconSyncError("; ".join(errors) or "invalid coordinator response")

    result: list[SyncedCandidate] = []
    for item in payload["candidates"]:
        if not isinstance(item, dict):
            continue
        observations = []
        for obs in item.get("observations", []):
            if not isinstance(obs, dict):
                continue
            observations.append(
                LandmarkObservation(
                    landmark_id=str(obs.get("landmark_id", "")),
                    rssi=int(obs.get("rssi", -127)),
                    channel=int(obs.get("channel", 0)),
                    observed_at=int(obs.get("observed_at", 0)),
                    captive_portal=bool(obs.get("captive_portal", True)),
                )
            )
        result.append(
            SyncedCandidate(
                anchor=AnchorObservation(
                    asset_id=str(item.get("asset_id", "")),
                    observations=tuple(observations),
                    echo_score=float(item.get("echo_score", 0.0)),
                    observed_at=int(item.get("observed_at", 0)),
                ),
                beacon=item.get("beacon", {}) if isinstance(item.get("beacon"), dict) else {},
            )
        )
    return result


def publish_defense_event(event: dict[str, Any]) -> dict[str, Any]:
    bases = coordinator_urls()
    if not bases:
        raise BeaconSyncError("proximity coordinator URL not configured")
    path = "/v2/beacon-sync/defense-event"
    body = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
    errors = []
    accepted = 0
    for base in bases:
        signed = headers(method="POST", path=path, body=body)
        request = urllib.request.Request(
            base + path,
            data=body,
            method="POST",
            headers={
                "content-type": "application/json",
                "user-agent": "918-FADS-DefenseEvent/1.3",
                **signed,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                payload = json.loads(response.read(262_144))
            if isinstance(payload, dict) and payload.get("status") == "accepted":
                accepted += 1
            else:
                errors.append(f"{base}: rejected")
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            errors.append(f"{base}: {exc}")
    if accepted == 0:
        raise BeaconSyncError("; ".join(errors) or "defense event rejected")
    return {
        "accepted": accepted,
        "total": len(bases),
        "status": "accepted" if accepted == len(bases) else "partial",
        "errors": errors,
    }


def fetch_defense_posture() -> dict[str, Any]:
    bases = coordinator_urls()
    if not bases:
        raise BeaconSyncError("proximity coordinator URL not configured")
    path = "/v2/beacon-sync/defense-posture"
    errors = []
    valid: list[dict[str, Any]] = []
    for base in bases:
        signed = headers(method="GET", path=path, body=b"")
        request = urllib.request.Request(
            base + path,
            method="GET",
            headers={"user-agent": "918-FADS-DefensePosture/1.3", **signed},
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                payload = json.loads(response.read(262_144))
            if isinstance(payload, dict) and payload.get("schema") == "918-DEFENSE-POSTURE/1":
                valid.append(payload)
            else:
                errors.append(f"{base}: invalid response")
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            errors.append(f"{base}: {exc}")
    if not valid:
        raise BeaconSyncError("; ".join(errors) or "defense posture unavailable")
    strongest = max(valid, key=lambda item: int(item.get("severity", 0)))
    strongest = dict(strongest)
    strongest["coordinators_responding"] = len(valid)
    strongest["coordinators_total"] = len(bases)
    strongest["redundancy"] = "full" if len(valid) == len(bases) else "degraded"
    return strongest
