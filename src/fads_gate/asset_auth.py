from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Mapping

from .global_mesh import EXCLUDED_COUNTRIES, GLOBAL_SCOPE

TOKEN_VERSION = 2
DEFAULT_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60


class AssetAuthError(ValueError):
    pass


@dataclass(frozen=True)
class AssetIdentity:
    asset_id: str
    country: str
    region: str
    platform: str
    issued_at: int
    expires_at: int
    attested_ip_hash: str
    attested_at: int
    attestation_providers: tuple[str, ...]
    scope: str = GLOBAL_SCOPE


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _token_key() -> bytes:
    value = os.environ.get("FADS_TOKEN_KEY", "")
    if len(value) < 32:
        raise AssetAuthError("FADS_TOKEN_KEY must be at least 32 characters")
    return value.encode("utf-8")


def enrollment_key_valid(candidate: str | None) -> bool:
    expected = os.environ.get("FADS_ENROLLMENT_KEY", "")
    if len(expected) < 32 or not candidate:
        return False
    return hmac.compare_digest(candidate.encode("utf-8"), expected.encode("utf-8"))


def _validate_registration(
    *,
    asset_id: str,
    country: str,
    region: str,
    platform: str,
    attested_ip_hash: str,
    attestation_providers: tuple[str, ...],
) -> tuple[str, str, str, str, str, tuple[str, ...]]:
    asset_id = asset_id.strip()
    country = country.strip().upper()
    region = region.strip()
    platform = platform.strip().lower()
    attested_ip_hash = attested_ip_hash.strip()
    providers = tuple(str(item).strip() for item in attestation_providers if str(item).strip())

    if not asset_id or len(asset_id) > 128:
        raise AssetAuthError("asset_id is required and must be <= 128 characters")
    if len(country) != 2 or not country.isalpha():
        raise AssetAuthError("attested country must be a two-letter code")
    if country in EXCLUDED_COUNTRIES:
        raise AssetAuthError("asset country is excluded by GLOBAL_EXCEPT_KP policy")
    if not region or len(region) > 128:
        raise AssetAuthError("region is required and must be <= 128 characters")
    if not platform or len(platform) > 64:
        raise AssetAuthError("platform is required and must be <= 64 characters")
    if not attested_ip_hash.startswith("sha256:") or len(attested_ip_hash) != 71:
        raise AssetAuthError("invalid attested IP hash")
    if len(providers) < 2:
        raise AssetAuthError("at least two attestation providers are required")
    return asset_id, country, region, platform, attested_ip_hash, providers


def issue_asset_token(
    *,
    asset_id: str,
    country: str,
    region: str,
    platform: str,
    attested_ip_hash: str,
    attestation_providers: tuple[str, ...],
    attested_at: int | None = None,
    now: int | None = None,
    ttl_seconds: int | None = None,
) -> tuple[str, AssetIdentity]:
    asset_id, country, region, platform, attested_ip_hash, providers = _validate_registration(
        asset_id=asset_id,
        country=country,
        region=region,
        platform=platform,
        attested_ip_hash=attested_ip_hash,
        attestation_providers=attestation_providers,
    )
    issued_at = int(time.time() if now is None else now)
    attested_at_value = int(issued_at if attested_at is None else attested_at)
    ttl = int(
        ttl_seconds
        if ttl_seconds is not None
        else os.environ.get("FADS_TOKEN_TTL_SECONDS", DEFAULT_TOKEN_TTL_SECONDS)
    )
    ttl = max(300, min(ttl, 365 * 24 * 60 * 60))
    expires_at = issued_at + ttl
    header = {"alg": "HS256", "typ": "918-ASSET", "ver": TOKEN_VERSION}
    payload = {
        "sub": asset_id,
        "country": country,
        "region": region,
        "platform": platform,
        "iat": issued_at,
        "exp": expires_at,
        "scope": GLOBAL_SCOPE,
        "attested_ip_hash": attested_ip_hash,
        "attested_at": attested_at_value,
        "attestation_providers": list(providers),
    }
    signing_input = _b64url_encode(_canonical(header)) + "." + _b64url_encode(_canonical(payload))
    signature = hmac.new(_token_key(), signing_input.encode("ascii"), hashlib.sha256).digest()
    token = signing_input + "." + _b64url_encode(signature)
    identity = AssetIdentity(
        asset_id,
        country,
        region,
        platform,
        issued_at,
        expires_at,
        attested_ip_hash,
        attested_at_value,
        providers,
    )
    return token, identity


def verify_asset_token(token: str, *, now: int | None = None) -> AssetIdentity:
    try:
        header_part, payload_part, signature_part = token.split(".", 2)
        header = json.loads(_b64url_decode(header_part))
        payload = json.loads(_b64url_decode(payload_part))
        signature = _b64url_decode(signature_part)
    except Exception as exc:
        raise AssetAuthError("malformed asset token") from exc

    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise AssetAuthError("malformed asset token")
    if header.get("alg") != "HS256" or header.get("typ") != "918-ASSET":
        raise AssetAuthError("unsupported asset token")
    if int(header.get("ver", 0)) != TOKEN_VERSION:
        raise AssetAuthError("asset token must use geo-attested version 2")

    signing_input = header_part + "." + payload_part
    expected = hmac.new(_token_key(), signing_input.encode("ascii"), hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        raise AssetAuthError("invalid asset token signature")

    current = int(time.time() if now is None else now)
    try:
        issued_at = int(payload["iat"])
        expires_at = int(payload["exp"])
        attested_at = int(payload["attested_at"])
    except (KeyError, TypeError, ValueError) as exc:
        raise AssetAuthError("invalid asset token timestamps") from exc

    if issued_at > current + 300 or attested_at > current + 300:
        raise AssetAuthError("asset token contains future timestamp")
    if expires_at <= current:
        raise AssetAuthError("asset token expired")
    if payload.get("scope") != GLOBAL_SCOPE:
        raise AssetAuthError("asset token scope mismatch")

    raw_providers = payload.get("attestation_providers", [])
    if not isinstance(raw_providers, list):
        raise AssetAuthError("invalid attestation providers")

    asset_id, country, region, platform, attested_ip_hash, providers = _validate_registration(
        asset_id=str(payload.get("sub", "")),
        country=str(payload.get("country", "")),
        region=str(payload.get("region", "")),
        platform=str(payload.get("platform", "")),
        attested_ip_hash=str(payload.get("attested_ip_hash", "")),
        attestation_providers=tuple(str(item) for item in raw_providers),
    )

    return AssetIdentity(
        asset_id,
        country,
        region,
        platform,
        issued_at,
        expires_at,
        attested_ip_hash,
        attested_at,
        providers,
    )


def bearer_token(header: str | None) -> str:
    if not header:
        raise AssetAuthError("missing Authorization header")
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        raise AssetAuthError("Authorization must use Bearer token")
    return value.strip()
