from __future__ import annotations

import os
from dataclasses import dataclass

CONTINENTS = (
    "North America",
    "South America",
    "Europe",
    "Africa",
    "Asia",
    "Oceania",
    "Antarctica",
)


@dataclass(frozen=True)
class ContinentBeacon:
    beacon_id: str
    logical_continent: str
    hosting_continent: str
    physical_host_region: str
    relay_hosted: bool


def current_beacon() -> ContinentBeacon:
    logical = os.environ.get("FADS_BEACON_CONTINENT", "Unassigned").strip()
    hosting = os.environ.get("FADS_HOSTING_CONTINENT", logical).strip()
    region = os.environ.get("FADS_NODE_REGION", "unknown").strip()
    beacon_id = os.environ.get("FADS_BEACON_ID", os.environ.get("FADS_NODE_ID", "fads-node")).strip()
    relay = logical != hosting
    return ContinentBeacon(
        beacon_id=beacon_id,
        logical_continent=logical,
        hosting_continent=hosting,
        physical_host_region=region,
        relay_hosted=relay,
    )


def validate_continent(name: str) -> str:
    cleaned = name.strip()
    if cleaned not in CONTINENTS:
        raise ValueError(f"unsupported continent: {cleaned}")
    return cleaned
