from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

GLOBAL_SCOPE = "GLOBAL_EXCEPT_KP"
EXCLUDED_COUNTRIES = frozenset({"KP"})


@dataclass(frozen=True)
class MeshScopeDecision:
    in_scope: bool
    scope: str
    country: str
    reason: str


def normalize_country(value: Any) -> str:
    return str(value or "").strip().upper()


def evaluate_scope(payload: Mapping[str, Any]) -> MeshScopeDecision:
    asset = payload.get("protected_asset")
    if not isinstance(asset, Mapping):
        return MeshScopeDecision(
            in_scope=True,
            scope=GLOBAL_SCOPE,
            country="UNKNOWN",
            reason="country_not_supplied",
        )

    country = normalize_country(asset.get("country"))
    if country in EXCLUDED_COUNTRIES:
        return MeshScopeDecision(
            in_scope=False,
            scope=GLOBAL_SCOPE,
            country=country,
            reason="jurisdiction_excluded_by_918_policy",
        )

    return MeshScopeDecision(
        in_scope=True,
        scope=GLOBAL_SCOPE,
        country=country or "UNKNOWN",
        reason="within_global_defense_scope",
    )
