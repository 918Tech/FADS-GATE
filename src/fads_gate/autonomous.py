from __future__ import annotations

import os
from typing import Any, Mapping

from .public_threat_arrays import enrich_observables


def autonomous_enabled() -> bool:
    return os.environ.get("FADS_AUTONOMOUS_MODE", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def apply_public_threat_policy(
    result: dict[str, Any],
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    if not autonomous_enabled():
        result["autonomous_mode"] = False
        return result

    observables = payload.get("observables", {})
    if not isinstance(observables, Mapping):
        observables = {}

    ips = observables.get("ips", ())
    domains = observables.get("domains", ())
    hashes = observables.get("sha256", ())
    ips = ips if isinstance(ips, list) else ()
    domains = domains if isinstance(domains, list) else ()
    hashes = hashes if isinstance(hashes, list) else ()

    enrichment = enrich_observables(ips=ips, domains=domains, hashes=hashes)
    result["autonomous_mode"] = True
    result["public_threat_arrays"] = enrichment

    confidence = int(enrichment.get("confidence", 0) or 0)
    malicious = enrichment.get("malicious_infrastructure", [])
    if not isinstance(malicious, list):
        malicious = []

    if malicious and confidence >= 90:
        if result.get("state") not in {"TERMINATED", "OUT_OF_SCOPE"}:
            result["state"] = "QUARANTINED"
            result["route"] = "HOUSE_OF_MIRRORS_PUBLIC_THREAT"
            result["decision"] = "PUBLIC_THREAT_CORROBORATED: DECEIVE_AND_CONTAIN"
            result["granted"] = [
                capability
                for capability in result.get("granted", [])
                if capability == "telemetry.read"
            ]
            result["autonomous_action"] = {
                "type": "QUARANTINE_LOCAL_ASSET",
                "reason": "corroborated_public_threat_intelligence",
                "remote_contact": False,
            }
    elif malicious and confidence >= 70:
        if result.get("state") == "TRUSTED":
            result["state"] = "RESTRICTED"
            result["route"] = "CLOAK_RESTRICTED"
            result["decision"] = "PUBLIC_THREAT_CORROBORATED: RESTRICT"
            result["autonomous_action"] = {
                "type": "RESTRICT_LOCAL_ASSET",
                "reason": "public_threat_intelligence",
                "remote_contact": False,
            }

    return result
