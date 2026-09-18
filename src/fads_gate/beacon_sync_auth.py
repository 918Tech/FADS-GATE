from __future__ import annotations

import hashlib
import hmac
import json
import os
import time


class BeaconSyncAuthError(ValueError):
    pass


def _client_key() -> bytes:
    value = os.environ.get("FADS_BEACON_SYNC_KEY", "")
    if len(value) < 32:
        raise BeaconSyncAuthError("FADS_BEACON_SYNC_KEY must be at least 32 characters")
    return value.encode("utf-8")


def _beacon_id() -> str:
    value = os.environ.get("FADS_BEACON_ID", os.environ.get("FADS_NODE_ID", "")).strip()
    if not value:
        raise BeaconSyncAuthError("beacon id is required")
    return value


def _server_key(beacon_id: str) -> bytes:
    raw = os.environ.get("FADS_BEACON_SYNC_KEYS", "").strip()
    if raw:
        try:
            keyring = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise BeaconSyncAuthError("invalid beacon keyring") from exc
        if not isinstance(keyring, dict):
            raise BeaconSyncAuthError("invalid beacon keyring")
        value = str(keyring.get(beacon_id, ""))
        if len(value) < 32:
            raise BeaconSyncAuthError("unknown beacon id")
        return value.encode("utf-8")
    return _client_key()


def _digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def signature(
    *,
    method: str,
    path: str,
    timestamp: int,
    body: bytes,
    beacon_id: str,
    key: bytes,
) -> str:
    canonical = (
        f"{beacon_id}\n{int(timestamp)}\n{method.upper()}\n{path}\n{_digest(body)}"
    ).encode("utf-8")
    return "sha256=" + hmac.new(key, canonical, hashlib.sha256).hexdigest()


def headers(*, method: str, path: str, body: bytes, timestamp: int | None = None) -> dict[str, str]:
    ts = int(time.time() if timestamp is None else timestamp)
    beacon_id = _beacon_id()
    return {
        "x-918-beacon-id": beacon_id,
        "x-918-beacon-timestamp": str(ts),
        "x-918-beacon-signature": signature(
            method=method,
            path=path,
            timestamp=ts,
            body=body,
            beacon_id=beacon_id,
            key=_client_key(),
        ),
    }


def verify(
    *,
    method: str,
    path: str,
    body: bytes,
    beacon_id_header: str | None,
    timestamp_header: str | None,
    signature_header: str | None,
    now: int | None = None,
    max_skew_seconds: int = 90,
) -> None:
    beacon_id = str(beacon_id_header or "").strip()
    if not beacon_id:
        raise BeaconSyncAuthError("missing beacon id")
    try:
        timestamp = int(str(timestamp_header or ""))
    except ValueError as exc:
        raise BeaconSyncAuthError("invalid beacon timestamp") from exc
    current = int(time.time() if now is None else now)
    if abs(current - timestamp) > max_skew_seconds:
        raise BeaconSyncAuthError("beacon request outside allowed clock skew")
    expected = signature(
        method=method,
        path=path,
        timestamp=timestamp,
        body=body,
        beacon_id=beacon_id,
        key=_server_key(beacon_id),
    )
    if not signature_header or not hmac.compare_digest(signature_header, expected):
        raise BeaconSyncAuthError("invalid beacon signature")
