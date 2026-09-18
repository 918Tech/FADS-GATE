from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

CONTINENTS = (
    "north-america",
    "south-america",
    "europe",
    "africa",
    "asia",
    "oceania",
    "antarctica",
)

@dataclass(frozen=True)
class ContinentBeacon:
    beacon_id: str
    continent: str
    hosting_region: str
    in_continent_hosting: bool
    role: str = "proximity-relay"

def current_beacon() -> ContinentBeacon:
    continent = os.environ.get("FADS_BEACON_CONTINENT", "unknown").strip().lower()
    hosting_region = os.environ.get("FADS_NODE_REGION", "unknown").strip().lower()
    beacon_id = os.environ.get("FADS_BEACON_ID", os.environ.get("FADS_NODE_ID", "fads-beacon")).strip()
    in_continent = os.environ.get("FADS_BEACON_IN_CONTINENT", "false").strip().lower() == "true"
    return ContinentBeacon(
        beacon_id=beacon_id,
        continent=continent,
        hosting_region=hosting_region,
        in_continent_hosting=in_continent,
    )

def validate_continent(value: str) -> str:
    normalized = value.strip().lower()
    if normalized not in CONTINENTS:
        raise ValueError(f"unsupported continent: {value}")
    return normalized
