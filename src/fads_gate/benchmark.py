from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any, Callable

from .server import _decision
from .waterplum import assess_waterplum


@dataclass(frozen=True)
class ScenarioResult:
    name: str
    passed: bool
    expected: str
    actual: str
    category: str


def _state_case(name: str, category: str, *, signals=None, observables=None, expected: str) -> ScenarioResult:
    result = assess_waterplum(signals=signals or {}, observables=observables or {})
    return ScenarioResult(name, result.state == expected, expected, result.state, category)


def run_benchmark() -> dict[str, Any]:
    results: list[ScenarioResult] = [
        _state_case("clean_baseline", "false-positive", expected="TRUSTED"),
        _state_case(
            "unknown_executable_install_hook",
            "behavioral",
            signals={"unknown_executable": True, "install_hook": True},
            expected="RESTRICTED",
        ),
        _state_case(
            "credential_access",
            "credential-protection",
            signals={"credential_access": True},
            expected="RESTRICTED",
        ),
        _state_case(
            "known_waterplum_ip",
            "published-ioc",
            observables={"ips": ["162.0.239.85"]},
            expected="QUARANTINED",
        ),
        _state_case(
            "known_waterplum_domain",
            "published-ioc",
            observables={"domains": ["w3pi.social"]},
            expected="QUARANTINED",
        ),
        _state_case(
            "known_waterplum_hash",
            "published-ioc",
            observables={"sha256": ["42620128470e26d473a128f354b77ca2c5fe9e5782e7addc1e3f863dbd0cd9b0"]},
            expected="QUARANTINED",
        ),
        _state_case(
            "replay_attempt",
            "integrity",
            signals={"replay": True},
            expected="TERMINATED",
        ),
        _state_case(
            "policy_tamper",
            "integrity",
            signals={"policy_tamper": True},
            expected="TERMINATED",
        ),
    ]

    capability = _decision(
        {
            "capabilities": ["repo.read", "network.outbound", "secrets.read", "capability.delegate"],
            "observables": {"ips": ["162.0.239.85"]},
        }
    )
    results.append(
        ScenarioResult(
            "capability_stripping",
            capability.get("granted") == ["repo.read"]
            and set(capability.get("stripped", ())) == {"network.outbound", "secrets.read", "capability.delegate"},
            "repo.read only",
            json.dumps(capability.get("granted")),
            "capability-gateway",
        )
    )

    kp = _decision({"protected_asset": {"country": "KP"}, "capabilities": ["repo.read"]})
    results.append(
        ScenarioResult(
            "excluded_jurisdiction",
            kp.get("state") == "OUT_OF_SCOPE" and kp.get("route") == "NO_OPERATION",
            "OUT_OF_SCOPE/NO_OPERATION",
            f"{kp.get('state')}/{kp.get('route')}",
            "scope",
        )
    )

    clean = [item for item in results if item.category == "false-positive"]
    malicious = [item for item in results if item.category != "false-positive"]
    passed = sum(1 for item in results if item.passed)
    detection_passed = sum(1 for item in malicious if item.passed)
    false_positive_failures = sum(1 for item in clean if not item.passed)

    return {
        "schema": "918-FADS-BENCHMARK/1",
        "passed": passed == len(results),
        "scenario_count": len(results),
        "scenarios_passed": passed,
        "detection_regression_rate": detection_passed / len(malicious) if malicious else 1.0,
        "synthetic_false_positive_failures": false_positive_failures,
        "results": [asdict(item) for item in results],
        "note": "Deterministic defensive regression benchmark; not an independent third-party EDR certification.",
    }


def main() -> int:
    report = run_benchmark()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
