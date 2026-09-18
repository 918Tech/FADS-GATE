from __future__ import annotations

import hashlib
import hmac
import os
import time


class BeaconSyncAuthError(ValueError):
    pass


def _key() -> bytes:
    value = os.environ.get("FADS_BEACON_SYNC_KEY", "")
    if len(value) < 32:
        raise BeaconSyncAuthError("FADS_BEACON_SYNC_KEY must be at least 32 characters")
    return value.encode("utf-8")


def _digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def signature(*, method: str, path: str, timestamp: int, body: bytes) -> str:
    canonical = f"{int(timestamp)}\n{method.upper()}\n{path}\n{_digest(body)}".encode("utf-8")
    return "sha256=" + hmac.new(_key(), canonical, hashlib.sha256).hexdigest()


def headers(*, method: str, path: str, body: bytes, timestamp: int | None = None) -> dict[str, str]:
    ts = int(time.time() if timestamp is None else timestamp)
    return {
        "x-918-beacon-timestamp": str(ts),
        "x-918-beacon-signature": signature(method=method, path=path, timestamp=ts, body=body),
    }


def verify(
    *,
    method: str,
    path: str,
    body: bytes,
    timestamp_header: str | None,
    signature_header: str | None,
    now: int | None = None,
    max_skew_seconds: int = 90,
) -> None:
    try:
        timestamp = int(str(timestamp_header or ""))
    except ValueError as exc:
        raise BeaconSyncAuthError("invalid beacon timestamp") from exc
    current = int(time.time() if now is None else now)
    if abs(current - timestamp) > max_skew_seconds:
        raise BeaconSyncAuthError("beacon request outside allowed clock skew")
    expected = signature(method=method, path=path, timestamp=timestamp, body=body)
    if not signature_header or not hmac.compare_digest(signature_header, expected):
        raise BeaconSyncAuthError("invalid beacon signature")
