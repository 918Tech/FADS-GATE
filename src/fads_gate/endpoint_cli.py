from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

from .asset_auth import AssetAuthError
from .endpoint_sensor import collect_endpoint_telemetry

DEFAULT_ENDPOINTS = (
    "https://nine18-fads-waterplum.onrender.com/v2/evaluate",
    "https://nine18-fads-oregon.onrender.com/v2/evaluate",
    "https://nine18-fads-frankfurt.onrender.com/v2/evaluate",
    "https://nine18-fads-singapore.onrender.com/v2/evaluate",
)


def _load_token(path: str | None) -> str:
    token = Path(path).read_text(encoding="utf-8").strip() if path else os.environ.get("FADS_ASSET_TOKEN", "").strip()
    if not token:
        raise AssetAuthError("asset token required via --token-file or FADS_ASSET_TOKEN")
    return token


def _post(url: str, token: str, telemetry: dict) -> dict:
    payload = {
        "capabilities": ["telemetry.read"],
        "signals": telemetry["signals"],
        "observables": telemetry["observables"],
        "sensor": telemetry["sensor"],
    }
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        method="POST",
        headers={
            "authorization": f"Bearer {token}",
            "content-type": "application/json",
            "user-agent": "918-FADS-Universal-Sensor/1.3",
        },
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        value = json.loads(response.read(1_048_576))
    if not isinstance(value, dict):
        raise ValueError("mesh response must be an object")
    return value


def _evaluate(endpoints: list[str], token: str, telemetry: dict) -> tuple[dict, str]:
    errors: list[str] = []
    for endpoint in endpoints:
        try:
            return _post(endpoint, token, telemetry), endpoint
        except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"{endpoint}: {exc}")
    raise RuntimeError("; ".join(errors) or "mesh unavailable")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fads-universal-sensor")
    parser.add_argument("--token-file")
    parser.add_argument("--endpoint", action="append", default=[])
    parser.add_argument("--scan-root", action="append", default=[])
    parser.add_argument("--interval", type=int, default=0)
    parser.add_argument("--output")
    return parser


def _run_once(args: argparse.Namespace, token: str) -> int:
    telemetry = collect_endpoint_telemetry(args.scan_root)
    endpoints = args.endpoint or list(DEFAULT_ENDPOINTS)
    try:
        result, endpoint = _evaluate(endpoints, token, telemetry)
    except RuntimeError as exc:
        print(json.dumps({"error": "mesh_unavailable", "detail": str(exc)}, sort_keys=True))
        return 5
    output = {
        "source": "918-universal-sensor",
        "endpoint": endpoint,
        "sensor": telemetry["sensor"],
        "state": result.get("state"),
        "route": result.get("route"),
        "score": result.get("score"),
        "matches": result.get("matches", []),
        "node": result.get("node"),
        "scope": result.get("scope"),
        "asset": result.get("asset"),
        "evidence": result.get("evidence"),
        "defense_deployment": result.get("defense_deployment"),
        "defense_posture": result.get("defense_posture"),
        "evidence_persistence": result.get("evidence_persistence"),
    }
    rendered = json.dumps(output, indent=2, sort_keys=True)
    print(rendered)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    return 0 if output["state"] in {"TRUSTED", "OUT_OF_SCOPE"} else 3


def main() -> int:
    args = build_parser().parse_args()
    try:
        token = _load_token(args.token_file)
    except (AssetAuthError, OSError) as exc:
        print(json.dumps({"error": "asset_auth", "detail": str(exc)}, sort_keys=True))
        return 6
    if args.interval <= 0:
        return _run_once(args, token)
    interval = max(30, args.interval)
    while True:
        _run_once(args, token)
        time.sleep(interval)


if __name__ == "__main__":
    raise SystemExit(main())
