from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request
from typing import Any

from .benchmark import run_benchmark
from .continent_beacons import CONTINENTS

DEFAULT_COORDINATORS = (
    "https://nine18-proximity-coordinator.onrender.com/healthz",
    "https://nine18-proximity-coordinator-eu.onrender.com/healthz",
)

DEFAULT_BEACONS = (
    "https://nine18-fads-waterplum.onrender.com/healthz",
    "https://nine18-beacon-south-america.onrender.com/healthz",
    "https://nine18-fads-frankfurt.onrender.com/healthz",
    "https://nine18-beacon-africa.onrender.com/healthz",
    "https://nine18-fads-singapore.onrender.com/healthz",
    "https://nine18-beacon-oceania.onrender.com/healthz",
    "https://nine18-beacon-antarctica.onrender.com/healthz",
)


def _probe(url: str) -> dict[str, Any]:
    try:
        request = urllib.request.Request(url, headers={"user-agent": "918-FADS-ReleaseGate/1.2"})
        with urllib.request.urlopen(request, timeout=12) as response:
            payload = json.loads(response.read(262_144))
        return {
            "url": url,
            "ok": response.status == 200 and isinstance(payload, dict) and payload.get("status") == "operational",
            "status": response.status,
            "payload": payload if isinstance(payload, dict) else {},
        }
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return {"url": url, "ok": False, "error": str(exc), "payload": {}}


def test_readiness() -> dict[str, Any]:
    benchmark = run_benchmark()
    checks = {
        "benchmark_passed": bool(benchmark["passed"]),
        "seven_continents_defined": len(CONTINENTS) == 7,
        "zero_false_positive_regressions": benchmark["synthetic_false_positive_failures"] == 0,
        "all_synthetic_defense_scenarios_pass": benchmark["scenarios_passed"] == benchmark["scenario_count"],
    }
    return {
        "status": "TEST_READY" if all(checks.values()) else "NOT_READY",
        "checks": checks,
        "benchmark": benchmark,
    }


def production_readiness() -> dict[str, Any]:
    base = test_readiness()
    coordinator_urls = tuple(
        item.strip()
        for item in os.environ.get(
            "FADS_RELEASE_COORDINATORS", ",".join(DEFAULT_COORDINATORS)
        ).split(",")
        if item.strip()
    )
    beacon_urls = tuple(
        item.strip()
        for item in os.environ.get(
            "FADS_RELEASE_BEACONS", ",".join(DEFAULT_BEACONS)
        ).split(",")
        if item.strip()
    )
    ledger_url = os.environ.get("FADS_EVIDENCE_LEDGER_HEALTH_URL", "").strip()

    coordinator_results = [_probe(url) for url in coordinator_urls]
    beacon_results = [_probe(url) for url in beacon_urls]
    ledger = _probe(ledger_url) if ledger_url else {"ok": False, "error": "ledger health URL not configured", "payload": {}}

    all_builds = {
        result.get("payload", {}).get("build_commit")
        or result.get("payload", {}).get("node", {}).get("build_commit")
        for result in coordinator_results + beacon_results
        if result.get("ok")
    }
    all_builds.discard(None)
    all_builds.discard("unknown")

    production_checks = {
        "test_ready": base["status"] == "TEST_READY",
        "seven_beacons_live": len(beacon_results) == 7 and all(item["ok"] for item in beacon_results),
        "dual_coordinators_live": len(coordinator_results) >= 2 and all(item["ok"] for item in coordinator_results[:2]),
        "version_consistent": len(all_builds) <= 1,
        "ledger_live": bool(ledger.get("ok")),
        "ledger_database_bound": ledger.get("payload", {}).get("database_bound") is True,
        "evidence_signing_configured": len(os.environ.get("FADS_EVIDENCE_KEY", "")) >= 32,
        "ledger_ingest_signing_configured": len(os.environ.get("FADS_LEDGER_INGEST_KEY", "")) >= 32,
        "token_epoch_configured": os.environ.get("FADS_TOKEN_EPOCH", "").isdigit(),
        "per_beacon_keyring_configured": bool(os.environ.get("FADS_BEACON_SYNC_KEYS", "").strip()),
    }

    return {
        "status": "PRODUCTION_READY" if all(production_checks.values()) else "TEST_READY_ONLY",
        "checks": production_checks,
        "test_readiness": base,
        "coordinators": coordinator_results,
        "beacons": beacon_results,
        "ledger": ledger,
        "build_commits": sorted(all_builds),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("test", "production"), default="test")
    args = parser.parse_args()
    result = test_readiness() if args.mode == "test" else production_readiness()
    print(json.dumps(result, indent=2, sort_keys=True))
    expected = "TEST_READY" if args.mode == "test" else "PRODUCTION_READY"
    return 0 if result["status"] == expected else 2


if __name__ == "__main__":
    raise SystemExit(main())
