from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .models import CapabilityDecision


DEFAULT_CAPABILITY_RISK: dict[str, int] = {
    "telemetry.read": 10,
    "repo.read": 20,
    "filesystem.read": 25,
    "http.get": 30,
    "network.outbound": 55,
    "filesystem.write": 60,
    "repo.write": 65,
    "repo.push": 75,
    "process.exec": 85,
    "secrets.read": 95,
    "capability.delegate": 100,
}


@dataclass(frozen=True)
class PolicyRule:
    id: str
    effect: str
    capabilities: tuple[str, ...]
    subjects: tuple[str, ...] = ("*",)
    max_risk: int = 100
    require_declared_agent: bool | None = None

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "PolicyRule":
        effect = str(raw.get("effect", "deny")).lower()
        if effect not in {"allow", "deny"}:
            raise ValueError(f"invalid policy effect: {effect}")
        return cls(
            id=str(raw["id"]),
            effect=effect,
            capabilities=tuple(map(str, raw.get("capabilities", ()))),
            subjects=tuple(map(str, raw.get("subjects", ("*",)))),
            max_risk=int(raw.get("max_risk", 100)),
            require_declared_agent=raw.get("require_declared_agent"),
        )

    def matches(self, *, subject_id: str, capability: str, risk: int, is_declared_agent: bool) -> bool:
        if not any(fnmatch.fnmatchcase(subject_id, pat) for pat in self.subjects):
            return False
        if not any(fnmatch.fnmatchcase(capability, pat) for pat in self.capabilities):
            return False
        if risk > self.max_risk:
            return False
        if self.require_declared_agent is not None and self.require_declared_agent != is_declared_agent:
            return False
        return True


class CapabilityPolicy:
    def __init__(
        self,
        *,
        rules: Iterable[PolicyRule] = (),
        default: str = "deny",
        hard_denies: Iterable[str] = (),
        risk_map: Mapping[str, int] | None = None,
    ) -> None:
        if default not in {"allow", "deny"}:
            raise ValueError("default must be allow or deny")
        self.rules = tuple(rules)
        self.default = default
        self.hard_denies = tuple(hard_denies)
        self.risk_map = dict(DEFAULT_CAPABILITY_RISK)
        if risk_map:
            self.risk_map.update({str(k): int(v) for k, v in risk_map.items()})

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "CapabilityPolicy":
        return cls(
            rules=(PolicyRule.from_mapping(rule) for rule in raw.get("rules", ())),
            default=str(raw.get("default", "deny")).lower(),
            hard_denies=map(str, raw.get("hard_denies", ())),
            risk_map=raw.get("risk_map"),
        )

    @classmethod
    def from_json(cls, path: str | Path) -> "CapabilityPolicy":
        return cls.from_mapping(json.loads(Path(path).read_text(encoding="utf-8")))

    def risk_for(self, capability: str) -> int:
        if capability in self.risk_map:
            return self.risk_map[capability]
        return 70

    def evaluate(self, *, subject_id: str, capability: str, is_declared_agent: bool) -> CapabilityDecision:
        risk = self.risk_for(capability)

        if any(fnmatch.fnmatchcase(capability, pat) for pat in self.hard_denies):
            return CapabilityDecision(capability, False, "hard-deny", "hard-deny", risk)

        for rule in self.rules:
            if rule.matches(
                subject_id=subject_id,
                capability=capability,
                risk=risk,
                is_declared_agent=is_declared_agent,
            ):
                return CapabilityDecision(
                    capability=capability,
                    allowed=rule.effect == "allow",
                    reason=f"rule:{rule.effect}",
                    rule_id=rule.id,
                    risk=risk,
                )

        return CapabilityDecision(
            capability=capability,
            allowed=self.default == "allow",
            reason=f"default:{self.default}",
            rule_id=None,
            risk=risk,
        )
