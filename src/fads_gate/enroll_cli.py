from __future__ import annotations

import argparse
import json
import os
import urllib.request
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fads-enroll-asset")
    parser.add_argument("--endpoint", default="https://nine18-fads-waterplum.onrender.com/v1/enroll")
    parser.add_argument("--asset-id", required=True)
    parser.add_argument("--expected-country")
    parser.add_argument("--region", required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--output", required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    key = os.environ.get("FADS_ENROLLMENT_KEY", "").strip()
    if not key:
        print(json.dumps({"error": "FADS_ENROLLMENT_KEY is required"}))
        return 6
    payload = {
        "asset_id": args.asset_id,
        "region": args.region,
        "platform": args.platform,
    }
    if args.expected_country:
        payload["country"] = args.expected_country.upper()
    }
    request = urllib.request.Request(
        args.endpoint,
        data=json.dumps(payload, sort_keys=True).encode("utf-8"),
        method="POST",
        headers={
            "content-type": "application/json",
            "x-918-enrollment-key": key,
            "user-agent": "918-FADS-Enrollment/0.6",
        },
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        result = json.loads(response.read(1_048_576))
    token = str(result["token"])
    output = Path(args.output)
    output.write_text(token + "\n", encoding="utf-8")
    try:
        output.chmod(0o600)
    except OSError:
        pass
    print(json.dumps({"asset": result["asset"], "scope": result["scope"], "token_file": str(output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
