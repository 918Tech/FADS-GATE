from __future__ import annotations

import argparse
import json
import os
import urllib.request
from pathlib import Path
from typing import Any

from .asset_auth import AssetAuthError
from .proximity_jumper import sanitize_observation

DEFAULT_ENDPOINT = "https://nine18-fads-waterplum.onrender.com"


def _load_token(path: str) -> str:
    value = Path(path).read_text(encoding="utf-8").strip()
    if not value:
        raise AssetAuthError("empty asset token")
    return value


def _load_observations(path: str) -> list[dict[str, Any]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("passive observation file must contain a JSON array")
    return [item for item in payload if isinstance(item, dict)]


def _reduced_payload(raw: list[dict[str, Any]], echo_score: float) -> dict[str, Any]:
    landmarks = []
    for item in raw:
        observation = sanitize_observation(item)
        if not observation.captive_portal:
            continue
        landmarks.append(
            {
                "landmark_id": observation.landmark_id,
                "rssi": observation.rssi,
                "channel": observation.channel,
                "observed_at": observation.observed_at,
                "captive_portal": True,
            }
        )
    return {
        "landmarks": landmarks,
        "echo_score": max(0.0, min(1.0, float(echo_score))),
    }


def _post(url: str, token: str, payload: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        method="POST",
        headers={
            "authorization": f"Bearer {token}",
            "content-type": "application/json",
            "user-agent": "918-FADS-Passive-Proximity/0.7",
        },
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        result = json.loads(response.read(1_048_576))
    if not isinstance(result, dict):
        raise ValueError("proximity response must be an object")
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fads-proximity-jumper")
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--input", required=True, help="JSON array produced by passive monitor hardware")
    parser.add_argument("--echo-score", type=float, required=True)
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument("--next", action="store_true", help="request next closer enrolled anchor")
    parser.add_argument("--output")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if len(os.environ.get("FADS_LANDMARK_KEY", "")) < 32:
        print(json.dumps({"error": "FADS_LANDMARK_KEY must be at least 32 characters"}))
        return 6
    try:
        token = _load_token(args.token_file)
        raw = _load_observations(args.input)
        payload = _reduced_payload(raw, args.echo_score)
        path = "/v2/proximity/next" if args.next else "/v2/proximity/observe"
        result = _post(args.endpoint.rstrip("/") + path, token, payload)
    except Exception as exc:
        print(json.dumps({"error": "proximity_jumper", "detail": str(exc)}, sort_keys=True))
        return 5

    rendered = json.dumps(result, indent=2, sort_keys=True)
    print(rendered)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
