from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

REGISTRY_SCHEMA = "918-ARSENAL-CAPABILITY-REGISTRY/1"
DEFAULT_SOURCE_URL = "https://github.com/rawfilejson/awesome-osint-arsenal"

# The registry is intentionally conservative. Catalog membership is not trust.
# Unknown or mixed-purpose tools are denied autonomous execution until reviewed.
_DENY_AUTONOMOUS_MARKERS = {
    "red-team",
    "offensive",
    "exploit",
    "exploitation",
    "phishing",
    "credential",
    "password",
    "brute-force",
    "bruteforce",
    "mobile-hacking",
    "hacking-framework",
    "attack",
}

_DEFENSIVE_MARKERS = {
    "blue-team",
    "defensive",
    "threat-intel",
    "malware-threat-intel",
    "detection",
    "soc",
}

_DFIR_MARKERS = {
    "forensics",
    "reverse-engineering",
    "reverse engineering",
    "dfir",
    "metadata",
    "firmware",
    "hardware",
}

_IDENTITY_REVIEW_MARKERS = {
    "people",
    "identity",
    "facial",
    "phone",
    "email",
    "social-media",
    "social media",
    "geolocation",
    "person-lookup",
    "username",
}

_ACTIVE_RECON_MARKERS = {
    "scanner",
    "scanning",
    "recon",
    "enumeration",
    "subdomain",
    "port scan",
    "network recon",
    "web application",
    "dorking",
}


@dataclass(frozen=True)
class CapabilityPolicy:
    capability_class: str
    execution_policy: str
    beacon_use: tuple[str, ...]
    fads_use: tuple[str, ...]
    autonomous_execution: bool
    remote_contact_allowed: bool
    requires_enrolled_asset: bool
    requires_explicit_authorization: bool
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["beacon_use"] = list(self.beacon_use)
        value["fads_use"] = list(self.fads_use)
        return value


def _text_blob(tool: Mapping[str, Any]) -> str:
    tags = tool.get("tags", [])
    if not isinstance(tags, list):
        tags = []
    parts = [
        str(tool.get("name", "")),
        str(tool.get("description", "")),
        str(tool.get("category", "")),
        " ".join(str(tag) for tag in tags),
    ]
    return " ".join(parts).lower()


def _contains_any(blob: str, markers: Iterable[str]) -> bool:
    return any(marker in blob for marker in markers)


def classify_tool(tool: Mapping[str, Any]) -> CapabilityPolicy:
    """Return the default FADS/BEACON policy for a third-party catalog entry.

    This function never executes, installs, probes, imports, or contacts a tool.
    Classification is metadata-only and intentionally defaults to deny.
    """

    blob = _text_blob(tool)

    if _contains_any(blob, _DENY_AUTONOMOUS_MARKERS):
        return CapabilityPolicy(
            capability_class="OFFENSIVE_OR_CREDENTIAL",
            execution_policy="DENY_AUTONOMOUS",
            beacon_use=("catalog-reference",),
            fads_use=(),
            autonomous_execution=False,
            remote_contact_allowed=False,
            requires_enrolled_asset=True,
            requires_explicit_authorization=True,
            rationale=(
                "Offensive, exploitation, phishing, credential, or attack-oriented "
                "capabilities are never granted autonomous FADS authority."
            ),
        )

    if _contains_any(blob, _DFIR_MARKERS):
        return CapabilityPolicy(
            capability_class="DFIR_OR_REVERSE_ENGINEERING",
            execution_policy="ENROLLED_ASSET_ONLY",
            beacon_use=("artifact-analysis", "evidence-correlation"),
            fads_use=("defensive-analysis-input",),
            autonomous_execution=False,
            remote_contact_allowed=False,
            requires_enrolled_asset=True,
            requires_explicit_authorization=False,
            rationale=(
                "DFIR/reverse-engineering tools may analyze artifacts from assets "
                "the operator is authorized to defend; they are not a live attack path."
            ),
        )

    if _contains_any(blob, _DEFENSIVE_MARKERS):
        return CapabilityPolicy(
            capability_class="DEFENSIVE_SENSOR_OR_THREAT_INTEL",
            execution_policy="DEFENSIVE_SANDBOX",
            beacon_use=("ioc-enrichment", "evidence-correlation"),
            fads_use=("sensor-input", "detection-rule-input"),
            autonomous_execution=False,
            remote_contact_allowed=False,
            requires_enrolled_asset=False,
            requires_explicit_authorization=False,
            rationale=(
                "Defensive and threat-intelligence capabilities may supply evidence "
                "or telemetry, but the registry itself never grants execution authority."
            ),
        )

    if _contains_any(blob, _IDENTITY_REVIEW_MARKERS):
        return CapabilityPolicy(
            capability_class="PUBLIC_IDENTITY_OSINT",
            execution_policy="INTELLIGENCE_REVIEW_ONLY",
            beacon_use=("public-source-correlation",),
            fads_use=(),
            autonomous_execution=False,
            remote_contact_allowed=False,
            requires_enrolled_asset=False,
            requires_explicit_authorization=True,
            rationale=(
                "Identity-oriented OSINT is limited to public-source evidence review; "
                "no autonomous person tracking, contact, or identity inference is allowed."
            ),
        )

    if _contains_any(blob, _ACTIVE_RECON_MARKERS):
        return CapabilityPolicy(
            capability_class="ACTIVE_RECON_OR_ENUMERATION",
            execution_policy="EXPLICIT_AUTHORIZATION_ONLY",
            beacon_use=("catalog-reference",),
            fads_use=(),
            autonomous_execution=False,
            remote_contact_allowed=False,
            requires_enrolled_asset=True,
            requires_explicit_authorization=True,
            rationale=(
                "Reconnaissance/enumeration may contact remote systems and therefore "
                "requires explicit authorization and separate execution controls."
            ),
        )

    return CapabilityPolicy(
        capability_class="UNCLASSIFIED",
        execution_policy="DEFAULT_DENY",
        beacon_use=("catalog-reference",),
        fads_use=(),
        autonomous_execution=False,
        remote_contact_allowed=False,
        requires_enrolled_asset=True,
        requires_explicit_authorization=True,
        rationale="Unknown or mixed-purpose capability; default deny until reviewed.",
    )


def normalize_entry(tool: Mapping[str, Any]) -> dict[str, Any]:
    policy = classify_tool(tool)
    install = tool.get("install", {})
    install_method = install.get("method") if isinstance(install, Mapping) else None
    tags = tool.get("tags", [])
    aliases = tool.get("aliases", [])
    return {
        "tool_id": str(tool.get("id", "")).strip(),
        "name": str(tool.get("name", "")).strip(),
        "description": str(tool.get("description", "")).strip(),
        "category": str(tool.get("category", "")).strip(),
        "url": str(tool.get("url", "")).strip(),
        "install_method": str(install_method or "").strip(),
        "tags": [str(value) for value in tags] if isinstance(tags, list) else [],
        "aliases": [str(value) for value in aliases] if isinstance(aliases, list) else [],
        "archived": bool(tool.get("archived", False)),
        "policy": policy.to_dict(),
        "execution_material_imported": False,
    }


def build_registry(
    catalog: list[Any],
    *,
    source_sha256: str,
    source_url: str = DEFAULT_SOURCE_URL,
    source_commit: str | None = None,
) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    rejected = 0
    for item in catalog:
        if not isinstance(item, Mapping):
            rejected += 1
            continue
        entries.append(normalize_entry(item))

    counts = Counter(entry["policy"]["capability_class"] for entry in entries)
    policy_counts = Counter(entry["policy"]["execution_policy"] for entry in entries)

    return {
        "schema": REGISTRY_SCHEMA,
        "system": "BEACON+FADS-GATE",
        "source": {
            "name": "awesome-osint-arsenal",
            "url": source_url,
            "commit": source_commit,
            "catalog_sha256": f"sha256:{source_sha256}",
            "origin": "third-party",
            "license": "unknown",
            "usage": "catalog metadata only; no third-party tool code executed or installed",
        },
        "invariants": {
            "default_deny": True,
            "catalog_membership_is_not_trust": True,
            "execution_material_imported": False,
            "autonomous_remote_contact": False,
            "offensive_capabilities_receive_autonomous_authority": False,
            "fads_enforcement_requires_local_evidence": True,
        },
        "summary": {
            "accepted_entries": len(entries),
            "rejected_entries": rejected,
            "capability_classes": dict(sorted(counts.items())),
            "execution_policies": dict(sorted(policy_counts.items())),
        },
        "tools": entries,
    }


def import_catalog(
    input_path: str | Path,
    output_path: str | Path,
    *,
    source_url: str = DEFAULT_SOURCE_URL,
    source_commit: str | None = None,
) -> dict[str, Any]:
    input_file = Path(input_path)
    raw = input_file.read_bytes()
    catalog = json.loads(raw.decode("utf-8"))
    if not isinstance(catalog, list):
        raise ValueError("catalog root must be a JSON array")

    registry = build_registry(
        catalog,
        source_sha256=hashlib.sha256(raw).hexdigest(),
        source_url=source_url,
        source_commit=source_commit,
    )
    Path(output_path).write_text(
        json.dumps(registry, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return registry


def load_registry(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema") != REGISTRY_SCHEMA:
        raise ValueError("not a supported Arsenal capability registry")
    return value


def find_tool(registry: Mapping[str, Any], tool_id: str) -> dict[str, Any] | None:
    tools = registry.get("tools", [])
    if not isinstance(tools, list):
        return None
    for item in tools:
        if isinstance(item, dict) and item.get("tool_id") == tool_id:
            return item
    return None


def _cmd_import(args: argparse.Namespace) -> int:
    registry = import_catalog(
        args.input,
        args.output,
        source_url=args.source_url,
        source_commit=args.source_commit,
    )
    print(
        json.dumps(
            {
                "status": "IMPORTED",
                "schema": registry["schema"],
                "accepted_entries": registry["summary"]["accepted_entries"],
                "rejected_entries": registry["summary"]["rejected_entries"],
                "output": str(Path(args.output)),
                "execution_material_imported": False,
            },
            sort_keys=True,
        )
    )
    return 0


def _cmd_inspect(args: argparse.Namespace) -> int:
    registry = load_registry(args.registry)
    tool = find_tool(registry, args.tool_id)
    if tool is None:
        print(json.dumps({"status": "NOT_FOUND", "tool_id": args.tool_id}))
        return 1
    print(json.dumps(tool, indent=2, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="fads-arsenal-registry",
        description=(
            "Import third-party OSINT/security catalog metadata into a default-deny "
            "BEACON/FADS capability registry. This command never installs tools."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    import_cmd = sub.add_parser("import", help="import a local tools.json catalog")
    import_cmd.add_argument("--input", required=True)
    import_cmd.add_argument("--output", required=True)
    import_cmd.add_argument("--source-url", default=DEFAULT_SOURCE_URL)
    import_cmd.add_argument("--source-commit")
    import_cmd.set_defaults(func=_cmd_import)

    inspect_cmd = sub.add_parser("inspect", help="inspect one classified registry entry")
    inspect_cmd.add_argument("--registry", required=True)
    inspect_cmd.add_argument("--tool-id", required=True)
    inspect_cmd.set_defaults(func=_cmd_inspect)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
