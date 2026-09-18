from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


_AGENT_KINDS = {"agent", "assistant", "autonomous-agent", "tool-agent", "model-agent"}


@dataclass(frozen=True)
class DetectionReport:
    is_declared_agent: bool
    confidence: int
    signals: tuple[str, ...]


class FADSGuardian:
    """Evidence-based detector using explicit machine-readable boundary evidence."""

    def inspect(self, manifest: Mapping[str, Any] | None) -> DetectionReport:
        manifest = manifest or {}
        signals: list[str] = []
        confidence = 0

        kind = str(manifest.get("kind", "")).strip().lower()
        if kind in _AGENT_KINDS:
            signals.append(f"declared-kind:{kind}")
            confidence += 50

        if manifest.get("agent") is True:
            signals.append("declared-agent-flag")
            confidence += 35

        tools = manifest.get("tools")
        if isinstance(tools, list) and tools:
            signals.append("tool-manifest-present")
            confidence += 10

        protocol = str(manifest.get("protocol", "")).strip().lower()
        if protocol in {"mcp", "a2a", "tool-calling", "function-calling"}:
            signals.append(f"agent-protocol:{protocol}")
            confidence += 10

        return DetectionReport(
            is_declared_agent=confidence >= 50,
            confidence=min(confidence, 100),
            signals=tuple(signals),
        )
