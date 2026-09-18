from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True)
class CapabilityRequest:
    subject_id: str
    requested: tuple[str, ...]
    manifest: Mapping[str, Any] = field(default_factory=dict)
    context: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CapabilityDecision:
    capability: str
    allowed: bool
    reason: str
    rule_id: str | None = None
    risk: int = 0


@dataclass(frozen=True)
class GatewayResult:
    subject_id: str
    requested: tuple[str, ...]
    granted: tuple[str, ...]
    stripped: tuple[str, ...]
    decisions: tuple[CapabilityDecision, ...]
    detection: "DetectionReport"
    event_hash: str | None = None

    @property
    def changed(self) -> bool:
        return self.requested != self.granted


from .guardian import DetectionReport  # noqa: E402
