from __future__ import annotations

import json
import os
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .beacon_sync_auth import BeaconSyncAuthError, verify

TTL_SECONDS = 180
_LOCK = threading.RLock()
_ANCHORS: dict[str, dict[str, Any]] = {}


def _prune(now: int | None = None) -> None:
    current = int(time.time() if now is None else now)
    with _LOCK:
        stale = [
            asset_id
            for asset_id, value in _ANCHORS.items()
            if current - int(value.get("observed_at", 0)) > TTL_SECONDS
        ]
        for asset_id in stale:
            _ANCHORS.pop(asset_id, None)


def _validate_anchor(payload: dict[str, Any]) -> dict[str, Any]:
    asset_id = str(payload.get("asset_id", "")).strip()
    if not asset_id or len(asset_id) > 128:
        raise ValueError("invalid asset_id")
    observations = payload.get("observations", [])
    if not isinstance(observations, list):
        raise ValueError("observations must be a list")
    clean_obs: list[dict[str, Any]] = []
    for item in observations:
        if not isinstance(item, dict):
            continue
        landmark_id = str(item.get("landmark_id", "")).strip()
        if not landmark_id.startswith("hmac-sha256:"):
            raise ValueError("raw Wi-Fi identifiers are not accepted")
        rssi = int(item.get("rssi", -127))
        channel = int(item.get("channel", 0))
        observed_at = int(item.get("observed_at", 0))
        captive = bool(item.get("captive_portal", True))
        if rssi < -127 or rssi > 0:
            raise ValueError("rssi out of range")
        if channel < 0 or channel > 233:
            raise ValueError("channel out of range")
        clean_obs.append(
            {
                "landmark_id": landmark_id,
                "rssi": rssi,
                "channel": channel,
                "observed_at": observed_at,
                "captive_portal": captive,
            }
        )
    beacon = payload.get("beacon", {})
    if not isinstance(beacon, dict):
        raise ValueError("beacon must be an object")
    clean_beacon = {
        "id": str(beacon.get("id", "")).strip(),
        "logical_continent": str(beacon.get("logical_continent", "")).strip(),
        "hosting_continent": str(beacon.get("hosting_continent", "")).strip(),
        "physical_host_region": str(beacon.get("physical_host_region", "")).strip(),
        "relay_hosted": bool(beacon.get("relay_hosted", False)),
    }
    observed_at = int(payload.get("observed_at", int(time.time())))
    return {
        "asset_id": asset_id,
        "observations": clean_obs,
        "echo_score": max(0.0, min(1.0, float(payload.get("echo_score", 0.0)))),
        "observed_at": observed_at,
        "beacon": clean_beacon,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "FADS-PROX-COORD/1.1"

    def _json(self, status: int, value: Any) -> None:
        body = json.dumps(value, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.send_header("cache-control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("content-length", "0"))
        if length <= 0 or length > 1_048_576:
            raise ValueError("invalid body length")
        return self.rfile.read(length)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            _prune()
            with _LOCK:
                count = len(_ANCHORS)
            self._json(
                200,
                {
                    "status": "operational",
                    "system": "918 Proximity Coordinator",
                    "schema": "918-PROX/1",
                    "anchor_ttl_seconds": TTL_SECONDS,
                    "active_anchors": count,
                    "raw_wifi_identifiers": False,
                    "build_commit": os.environ.get("RENDER_GIT_COMMIT", os.environ.get("FADS_BUILD_COMMIT", "unknown")),
                },
            )
            return

        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/v2/beacon-sync/candidates":
            self._json(404, {"error": "not_found"})
            return
        try:
            verify(
                method="GET",
                path=self.path,
                body=b"",
                beacon_id_header=self.headers.get("x-918-beacon-id"),
                beacon_id_header=self.headers.get("x-918-beacon-id"),
                timestamp_header=self.headers.get("x-918-beacon-timestamp"),
                signature_header=self.headers.get("x-918-beacon-signature"),
            )
            query = urllib.parse.parse_qs(parsed.query)
            exclude = str(query.get("exclude", [""])[0])
            _prune()
            with _LOCK:
                candidates = [
                    value
                    for asset_id, value in _ANCHORS.items()
                    if asset_id != exclude
                ]
            self._json(200, {"schema": "918-PROX/1", "candidates": candidates})
        except BeaconSyncAuthError as exc:
            self._json(401, {"error": "beacon_sync_auth", "detail": str(exc)})

    def do_POST(self) -> None:
        if self.path != "/v2/beacon-sync/anchor":
            self._json(404, {"error": "not_found"})
            return
        try:
            body = self._read_body()
            verify(
                method="POST",
                path=self.path,
                body=body,
                timestamp_header=self.headers.get("x-918-beacon-timestamp"),
                signature_header=self.headers.get("x-918-beacon-signature"),
            )
            payload = json.loads(body)
            if not isinstance(payload, dict):
                raise ValueError("body must be object")
            anchor = _validate_anchor(payload)
            _prune()
            with _LOCK:
                _ANCHORS[anchor["asset_id"]] = anchor
            self._json(
                200,
                {
                    "status": "accepted",
                    "asset_id": anchor["asset_id"],
                    "expires_in": TTL_SECONDS,
                },
            )
        except BeaconSyncAuthError as exc:
            self._json(401, {"error": "beacon_sync_auth", "detail": str(exc)})
        except (ValueError, json.JSONDecodeError) as exc:
            self._json(400, {"error": "invalid_request", "detail": str(exc)})

    def log_message(self, format: str, *args: Any) -> None:
        return


def main() -> int:
    server = ThreadingHTTPServer(("0.0.0.0", int(__import__("os").environ.get("PORT", "8080"))), Handler)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
