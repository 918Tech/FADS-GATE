from __future__ import annotations

from dataclasses import replace
from typing import Any, Mapping, Sequence

from .audit import HashChainAuditLog, result_event
from .guardian import FADSGuardian
from .models import CapabilityRequest, GatewayResult
from .policy import CapabilityPolicy


class CapabilityGateway:
    """Evaluate and reduce an incoming capability set before execution."""

    def __init__(
        self,
        policy: CapabilityPolicy,
        *,
        guardian: FADSGuardian | None = None,
        audit_log: HashChainAuditLog | None = None,
    ) -> None:
        self.policy = policy
        self.guardian = guardian or FADSGuardian()
        self.audit_log = audit_log

    def authorize(self, request: CapabilityRequest) -> GatewayResult:
        detection = self.guardian.inspect(request.manifest)
        requested = tuple(dict.fromkeys(request.requested))
        decisions = tuple(
            self.policy.evaluate(
                subject_id=request.subject_id,
                capability=capability,
                is_declared_agent=detection.is_declared_agent,
            )
            for capability in requested
        )
        granted = tuple(item.capability for item in decisions if item.allowed)
        stripped = tuple(item.capability for item in decisions if not item.allowed)
        result = GatewayResult(
            subject_id=request.subject_id,
            requested=requested,
            granted=granted,
            stripped=stripped,
            decisions=decisions,
            detection=detection,
        )
        if self.audit_log is not None:
            result = replace(result, event_hash=self.audit_log.append(result_event(result)))
        return result

    def strip_manifest(
        self,
        *,
        subject_id: str,
        manifest: Mapping[str, Any],
        capability_field: str = "capabilities",
        context: Mapping[str, Any] | None = None,
    ) -> tuple[dict[str, Any], GatewayResult]:
        requested_raw = manifest.get(capability_field, ())
        if not isinstance(requested_raw, Sequence) or isinstance(requested_raw, (str, bytes)):
            raise TypeError(f"{capability_field} must be a list-like value")
        request = CapabilityRequest(
            subject_id=subject_id,
            requested=tuple(map(str, requested_raw)),
            manifest=manifest,
            context=context or {},
        )
        result = self.authorize(request)
        reduced = dict(manifest)
        reduced[capability_field] = list(result.granted)
        return reduced, result
