from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any

DEFAULT_TARGETS = (
    ("north-america", "https://nine18-fads-waterplum.onrender.com/healthz"),
    ("south-america", "https://nine18-beacon-south-america.onrender.com/healthz"),
    ("europe", "https://nine18-fads-frankfurt.onrender.com/healthz"),
    ("africa", "https://nine18-beacon-africa.onrender.com/healthz"),
    ("asia", "https://nine18-fads-singapore.onrender.com/healthz"),
    ("oceania", "https://nine18-beacon-oceania.onrender.com/healthz"),
    ("antarctica", "https://nine18-beacon-antarctica.onrender.com/healthz"),
    ("proximity-coordinator", "https://nine18-proximity-coordinator.onrender.com/healthz"),
)


def _targets() -> tuple[tuple[str, str], ...]:
    raw = os.environ.get("FADS_WATCHDOG_TARGETS", "").strip()
    if not raw:
        return DEFAULT_TARGETS
    result: list[tuple[str, str]] = []
    for item in raw.split(","):
        name, sep, url = item.partition("=")
        if sep and name.strip() and url.strip():
            result.append((name.strip(), url.strip()))
    return tuple(result) or DEFAULT_TARGETS


def _probe(name: str, url: str) -> dict[str, Any]:
    started = time.monotonic()
    request = urllib.request.Request(
        url,
        headers={"user-agent": "918-FADS-Watchdog/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            payload = json.loads(response.read(262_144))
        ok = isinstance(payload, dict) and payload.get("status") == "operational"
        return {
            "name": name,
            "url": url,
            "ok": ok,
            "http_status": response.status,
            "latency_ms": round((time.monotonic() - started) * 1000, 1),
            "status": payload.get("status") if isinstance(payload, dict) else None,
            "build_commit": (payload.get("build_commit") or (payload.get("node", {}) if isinstance(payload.get("node"), dict) else {}).get("build_commit")) if isinstance(payload, dict) else None,
        }
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return {
            "name": name,
            "url": url,
            "ok": False,
            "error": str(exc),
            "latency_ms": round((time.monotonic() - started) * 1000, 1),
        }


def main() -> int:
    results = [_probe(name, url) for name, url in _targets()]
    commits = {item.get("build_commit") for item in results if item.get("build_commit") not in {None, "unknown"}}
    version_consistent = len(commits) <= 1
    healthy = all(item["ok"] for item in results) and version_consistent
    output = {
        "schema": "918-WATCHDOG/1",
        "healthy": healthy,
        "version_consistent": version_consistent,
        "build_commits": sorted(commits),
        "targets": results,
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0 if healthy else 2


if __name__ == "__main__":
    raise SystemExit(main())
