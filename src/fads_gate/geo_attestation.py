from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Iterable, Mapping

from .global_mesh import EXCLUDED_COUNTRIES

DEFAULT_PROVIDERS = (
    "https://ipwho.is/{ip}",
    "https://ipapi.co/{ip}/json/",
)


class GeoAttestationError(ValueError):
    pass


class GeoExcludedError(GeoAttestationError):
    pass


@dataclass(frozen=True)
class GeoAttestation:
    country: str
    source_ip_hash: str
    providers: tuple[str, ...]
    consensus: bool


def _public_ip(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise GeoAttestationError("invalid source IP") from exc
    if not ip.is_global:
        raise GeoAttestationError("source IP is not globally routable")
    return str(ip)


def source_ip_from_headers(
    headers: Mapping[str, str],
    peer_ip: str | None = None,
) -> str:
    forwarded = headers.get("x-forwarded-for") or headers.get("X-Forwarded-For") or ""
    candidates = [part.strip() for part in forwarded.split(",") if part.strip()]
    mode = os.environ.get("FADS_X_FORWARDED_FOR_MODE", "first").strip().lower()
    ordered = candidates if mode == "first" else list(reversed(candidates))
    for candidate in ordered:
        try:
            return _public_ip(candidate)
        except GeoAttestationError:
            continue
    if peer_ip:
        return _public_ip(peer_ip)
    raise GeoAttestationError("no trusted public source IP available")


def _provider_urls() -> tuple[str, ...]:
    raw = os.environ.get("FADS_GEO_PROVIDERS", "").strip()
    if not raw:
        return DEFAULT_PROVIDERS
    values = tuple(item.strip() for item in raw.split(",") if item.strip())
    if len(values) < 2:
        raise GeoAttestationError("at least two geo providers are required")
    return values


def _extract_country(url: str, payload: object) -> str:
    if not isinstance(payload, dict):
        raise GeoAttestationError("geo provider returned non-object JSON")
    if "ipwho.is" in url:
        if payload.get("success") is False:
            raise GeoAttestationError("ipwho.is lookup failed")
        country = payload.get("country_code")
    elif "ipapi.co" in url:
        if payload.get("error") is True:
            raise GeoAttestationError("ipapi.co lookup failed")
        country = payload.get("country_code")
    else:
        country = payload.get("country_code") or payload.get("countryCode")
    country = str(country or "").upper()
    if len(country) != 2 or not country.isalpha():
        raise GeoAttestationError("geo provider returned invalid country code")
    return country


def _lookup(url_template: str, ip: str) -> tuple[str, str]:
    url = url_template.replace("{ip}", urllib.parse.quote(ip, safe=""))
    request = urllib.request.Request(
        url,
        headers={"user-agent": "918-FADS-GeoAttestation/0.6"},
    )
    with urllib.request.urlopen(request, timeout=8) as response:
        payload = json.loads(response.read(262_144))
    return _extract_country(url_template, payload), urllib.parse.urlparse(url_template).netloc


def attest_source_ip(ip: str) -> GeoAttestation:
    ip = _public_ip(ip)
    countries: list[str] = []
    providers: list[str] = []
    errors: list[str] = []

    for provider in _provider_urls():
        try:
            country, provider_name = _lookup(provider, ip)
            countries.append(country)
            providers.append(provider_name)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, GeoAttestationError) as exc:
            errors.append(f"{provider}: {exc}")

    if len(countries) < 2:
        raise GeoAttestationError("independent geo consensus unavailable: " + "; ".join(errors))
    if len(set(countries)) != 1:
        raise GeoAttestationError("geo providers disagree on source country")

    country = countries[0]
    if country in EXCLUDED_COUNTRIES:
        raise GeoExcludedError("source country excluded by GLOBAL_EXCEPT_KP policy")

    salt = os.environ.get("FADS_GEO_HASH_SALT", "")
    if len(salt) < 32:
        raise GeoAttestationError("FADS_GEO_HASH_SALT must be at least 32 characters")
    digest = hashlib.sha256((salt + "|" + ip).encode("utf-8")).hexdigest()

    return GeoAttestation(
        country=country,
        source_ip_hash=f"sha256:{digest}",
        providers=tuple(providers),
        consensus=True,
    )
