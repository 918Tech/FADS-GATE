from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from pathlib import Path

from .sensor import remote_payload, scan_workspace
from .waterplum import assess_waterplum

EXIT_BY_STATE = {
    "TRUSTED": 0,
    "RESTRICTED": 2,
    "QUARANTINED": 3,
    "TERMINATED": 4,
    "OUT_OF_SCOPE": 0,
}


def _post_json(url: str, payload: dict) -> dict:
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "content-type": "application/json",
            "user-agent": "918-FADS-WaterPlum-Sensor/0.4",
        },
    )
    try:
        response = urllib.request.urlopen(req, timeout=15)
    except urllib.error.HTTPError as exc:
        body = exc.read(1_048_576)
        if exc.code == 451:
            value = json.loads(body)
            if isinstance(value, dict):
                return value
        raise
    with response:
        body = response.read(1_048_576)
    value = json.loads(body)
    if not isinstance(value, dict):
        raise ValueError("evaluator response must be an object")
    return value


def _post_mesh(endpoints: list[str], payload: dict) -> tuple[dict, str]:
    errors: list[str] = []
    for endpoint in endpoints:
        try:
            return _post_json(endpoint, payload), endpoint
        except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"{endpoint}: {exc}")
    raise RuntimeError("; ".join(errors) or "no endpoints configured")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fads-waterplum-scan")
    parser.add_argument("--root", default=".")
    parser.add_argument("--endpoint", action="append", default=[])
    parser.add_argument("--country")
    parser.add_argument(
        "--fail-on",
        choices=("restricted", "quarantined", "terminated"),
        default="quarantined",
    )
    parser.add_argument("--output")
    return parser


def _threshold(state: str) -> int:
    return {
        "restricted": 2,
        "quarantined": 3,
        "terminated": 4,
    }[state]


def main() -> int:
    args = build_parser().parse_args()
    scan = scan_workspace(Path(args.root))
    local = assess_waterplum(
        signals=scan["signals"],
        observables=scan["observables"],
    )

    result = {
        "source": "local",
        "state": local.state,
        "route": local.route,
        "score": local.score,
        "matches": list(local.matches),
        "signals": scan["signals"],
        "observables": scan["observables"],
    }

    if args.endpoint:
        payload = remote_payload(scan)
        if args.country:
            payload["protected_asset"] = {"country": args.country.upper()}
        try:
            remote, endpoint = _post_mesh(args.endpoint, payload)
        except RuntimeError as exc:
            print(json.dumps({"error": "mesh_unavailable", "detail": str(exc)}, sort_keys=True))
            return 5
        result = {
            **result,
            "source": "local+remote",
            "remote": remote,
            "remote_endpoint": endpoint,
            "state": str(remote.get("state", result["state"])),
            "route": str(remote.get("route", result["route"])),
            "score": int(remote.get("score", result["score"])),
            "matches": list(remote.get("matches", result["matches"])),
        }

    rendered = json.dumps(result, indent=2, sort_keys=True)
    print(rendered)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")

    rank = EXIT_BY_STATE.get(result["state"], 4)
    return rank if rank >= _threshold(args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main())
