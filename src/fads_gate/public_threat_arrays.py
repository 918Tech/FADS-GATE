from __future__ import annotations

import ipaddress
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict
from typing import Any, Iterable, Mapping


class PublicThreatArrayError(RuntimeError):
    pass


@dataclass(frozen=True)
class ThreatArrayFinding:
    source: str
    observable: str
    observable_type: str
    classification: str
    confidence: int
    cluster_labels: tuple[str, ...]
    malicious_infrastructure: bool
    reference: str | None
    evidence: dict[str, Any]


def _json_request(
    url: str,
    *,
    method: str = "GET",
    body: Mapping[str, Any] | None = None,
    headers: Mapping[str, str] | None = None,
) -> Any:
    data = None
    final_headers = {
        "accept": "application/json",
        "user-agent": "918-FADS-PublicThreatArrays/0.9",
        **dict(headers or {}),
    }
    if body is not None:
        data = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        final_headers["content-type"] = "application/json"
    request = urllib.request.Request(url, data=data, method=method, headers=final_headers)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.loads(response.read(2_097_152))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise PublicThreatArrayError(f"{url}: HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise PublicThreatArrayError(f"{url}: {exc}") from exc


def _clean_ip(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise PublicThreatArrayError("invalid IP observable") from exc
    if not ip.is_global:
        raise PublicThreatArrayError("IP observable must be globally routable")
    return str(ip)


def greynoise_community_lookup(ip: str) -> ThreatArrayFinding | None:
    observable = _clean_ip(ip)
    url = "https://api.greynoise.io/v3/community/" + urllib.parse.quote(observable, safe="")
    payload = _json_request(url)
    if payload is None or not isinstance(payload, Mapping):
        return None

    noise = bool(payload.get("noise", False))
    riot = bool(payload.get("riot", False))
    classification = str(payload.get("classification") or "unknown").lower()
    name = str(payload.get("name") or "").strip()
    message = str(payload.get("message") or "").strip()
    link = str(payload.get("link") or "").strip() or None

    malicious = noise and classification == "malicious"
    confidence = 85 if malicious else (60 if noise else 20)
    if riot:
        confidence = min(confidence, 25)

    labels = []
    if name:
        labels.append(name)
    if noise:
        labels.append("internet-noise")
    if riot:
        labels.append("known-benign-service")

    return ThreatArrayFinding(
        source="greynoise-community",
        observable=observable,
        observable_type="ip",
        classification=classification,
        confidence=confidence,
        cluster_labels=tuple(dict.fromkeys(labels)),
        malicious_infrastructure=malicious,
        reference=link,
        evidence={
            "noise": noise,
            "riot": riot,
            "message": message,
        },
    )


def _threatfox_key() -> str:
    return os.environ.get("THREATFOX_AUTH_KEY", "").strip()


def threatfox_lookup(observable: str) -> tuple[ThreatArrayFinding, ...]:
    auth_key = _threatfox_key()
    if not auth_key:
        return ()
    term = observable.strip()
    if not term or len(term) > 2048:
        raise PublicThreatArrayError("invalid ThreatFox observable")
    payload = _json_request(
        "https://threatfox-api.abuse.ch/api/v1/",
        method="POST",
        body={"query": "search_ioc", "search_term": term, "exact_match": True},
        headers={"Auth-Key": auth_key},
    )
    if not isinstance(payload, Mapping):
        return ()
    if payload.get("query_status") not in {"ok", "no_result"}:
        raise PublicThreatArrayError("ThreatFox query failed")
    data = payload.get("data")
    if not isinstance(data, list):
        return ()

    findings: list[ThreatArrayFinding] = []
    for item in data[:50]:
        if not isinstance(item, Mapping):
            continue
        ioc = str(item.get("ioc") or term)
        threat_type = str(item.get("threat_type") or "unknown")
        threat_desc = str(item.get("threat_type_desc") or "")
        malware = str(item.get("malware_printable") or item.get("malware") or "").strip()
        tags_raw = item.get("tags") or item.get("tag_list") or []
        tags = [str(tag) for tag in tags_raw] if isinstance(tags_raw, list) else []
        confidence_raw = item.get("confidence_level", 50)
        try:
            confidence = max(0, min(100, int(confidence_raw)))
        except (TypeError, ValueError):
            confidence = 50
        labels = [value for value in [malware, *tags] if value]
        reference = str(item.get("reference") or "").strip() or None

        findings.append(
            ThreatArrayFinding(
                source="threatfox",
                observable=ioc,
                observable_type=str(item.get("ioc_type") or "ioc"),
                classification=threat_type,
                confidence=confidence,
                cluster_labels=tuple(dict.fromkeys(labels)),
                malicious_infrastructure=True,
                reference=reference,
                evidence={
                    "threat_type_desc": threat_desc,
                    "first_seen": item.get("first_seen"),
                    "last_seen": item.get("last_seen"),
                    "is_compromised": item.get("is_compromised"),
                },
            )
        )
    return tuple(findings)


def enrich_observables(
    *,
    ips: Iterable[str] = (),
    domains: Iterable[str] = (),
    hashes: Iterable[str] = (),
) -> dict[str, Any]:
    findings: list[ThreatArrayFinding] = []
    errors: list[str] = []
    sources_used: set[str] = set()

    for value in list(dict.fromkeys(ips))[:64]:
        try:
            result = greynoise_community_lookup(value)
            if result is not None:
                findings.append(result)
                sources_used.add(result.source)
        except PublicThreatArrayError as exc:
            errors.append(f"greynoise:{value}:{exc}")

        try:
            results = threatfox_lookup(value)
            findings.extend(results)
            if results:
                sources_used.add("threatfox")
        except PublicThreatArrayError as exc:
            errors.append(f"threatfox:{value}:{exc}")

    for value in list(dict.fromkeys(domains))[:64]:
        try:
            results = threatfox_lookup(value)
            findings.extend(results)
            if results:
                sources_used.add("threatfox")
        except PublicThreatArrayError as exc:
            errors.append(f"threatfox:{value}:{exc}")

    for value in list(dict.fromkeys(hashes))[:64]:
        try:
            results = threatfox_lookup(value)
            findings.extend(results)
            if results:
                sources_used.add("threatfox")
        except PublicThreatArrayError as exc:
            errors.append(f"threatfox:{value}:{exc}")

    actor_clusters = sorted(
        {
            label
            for finding in findings
            if finding.malicious_infrastructure
            for label in finding.cluster_labels
            if label and label not in {"internet-noise", "known-benign-service"}
        }
    )

    infrastructure = [
        finding.observable
        for finding in findings
        if finding.malicious_infrastructure
    ]
    max_confidence = max(
        (finding.confidence for finding in findings if finding.malicious_infrastructure),
        default=0,
    )

    return {
        "schema": "918-PUBLIC-THREAT-ARRAYS/1",
        "sources_used": sorted(sources_used),
        "findings": [asdict(item) for item in findings],
        "malicious_infrastructure": list(dict.fromkeys(infrastructure)),
        "threat_clusters": actor_clusters,
        "confidence": max_confidence,
        "errors": errors,
        "personal_identity_inference": False,
        "physical_person_tracking": False,
    }
