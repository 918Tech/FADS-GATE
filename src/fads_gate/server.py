from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .asset_auth import (
    AssetAuthError,
    bearer_token,
    enrollment_key_valid,
    issue_asset_token,
    verify_asset_token,
)
from .global_mesh import GLOBAL_SCOPE, evaluate_scope
from .waterplum import PROFILE_DATE, PROFILE_ID, assess_waterplum

ALLOW = {"repo.read", "telemetry.read"}
HARD_DENY = {"secrets.read", "capability.delegate", "network.outbound"}

DECOY_TOPOLOGY = (
    {"host": "fake-build-01", "ip": "192.0.2.18", "service": "build-api"},
    {"host": "fake-git-02", "ip": "198.51.100.39", "service": "git-mirror"},
    {"host": "fake-vault-01", "ip": "203.0.113.14", "service": "vault-decoy"},
)


def _node() -> dict[str, str]:
    return {
        "id": os.environ.get("FADS_NODE_ID", "fads-node"),
        "region": os.environ.get("FADS_NODE_REGION", "unknown"),
        "scope": GLOBAL_SCOPE,
    }


def _decision(payload: dict[str, Any]) -> dict[str, Any]:
    scope = evaluate_scope(payload)
    node = _node()
    if not scope.in_scope:
        return {
            "state": "OUT_OF_SCOPE",
            "route": "NO_OPERATION",
            "decision": "EXCLUDED_BY_918_POLICY",
            "score": 0,
            "matches": [],
            "requested": [],
            "granted": [],
            "stripped": [],
            "active_contact": False,
            "scope": asdict(scope),
            "node": node,
            "evidence": {
                "schema": "918-IPCTX/1",
                "system": "BEACON",
                "component": "global-defense-mesh",
                "origin": "derived",
                "canonical": False,
            },
        }

    requested = tuple(dict.fromkeys(map(str, payload.get("capabilities", ()))))
    assessment = assess_waterplum(
        signals=payload.get("signals"),
        observables=payload.get("observables"),
    )
    granted = tuple(item for item in requested if item in ALLOW and item not in HARD_DENY)
    if assessment.state == "TERMINATED":
        granted = ()
    stripped = tuple(item for item in requested if item not in granted)

    evidence_payload = {
        "profile": assessment.profile,
        "score": assessment.score,
        "state": assessment.state,
        "route": assessment.route,
        "requested": requested,
        "granted": granted,
        "stripped": stripped,
        "matches": assessment.matches,
        "scope": asdict(scope),
        "node": node,
    }
    evidence_hash = hashlib.sha256(
        json.dumps(evidence_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    result = {
        **asdict(assessment),
        "requested": list(requested),
        "granted": list(granted),
        "stripped": list(stripped),
        "scope": asdict(scope),
        "node": node,
        "evidence": {
            "schema": "918-IPCTX/1",
            "system": "BEACON",
            "component": "global-defense-mesh",
            "origin": "derived",
            "content_hash": f"sha256:{evidence_hash}",
            "canonical": False,
        },
        "active_contact": False,
        "attribution_note": (
            "Indicator matches are defensive signals and do not by themselves prove operator identity."
        ),
    }
    if assessment.route == "HOUSE_OF_MIRRORS_WATERPLUM":
        result["decoy_topology"] = list(DECOY_TOPOLOGY)
    return result


class Handler(BaseHTTPRequestHandler):
    server_version = "FADS-GATE/0.5"

    def _json(self, status: int, value: Any) -> None:
        body = json.dumps(value, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.send_header("cache-control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("content-length", "0"))
        if length <= 0 or length > 1_048_576:
            raise ValueError("invalid body length")
        payload = json.loads(self.rfile.read(length))
        if not isinstance(payload, dict):
            raise ValueError("body must be object")
        return payload

    def do_GET(self) -> None:
        if self.path in {"/", "/healthz", "/v1/mesh"}:
            self._json(
                200,
                {
                    "status": "operational",
                    "system": "918 Technologies FADS-GATE",
                    "profile": PROFILE_ID,
                    "profile_date": PROFILE_DATE,
                    "active_contact": False,
                    "mirror_namespace": "house-of-mirrors.decoy",
                    "node": _node(),
                    "scope": GLOBAL_SCOPE,
                    "excluded_countries": ["KP"],
                    "authenticated_sensor_api": "/v2/evaluate",
                    "enrollment_api": "/v1/enroll",
                },
            )
            return
        self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        try:
            if self.path == "/v1/enroll":
                if not enrollment_key_valid(self.headers.get("x-918-enrollment-key")):
                    self._json(401, {"error": "invalid_enrollment_key"})
                    return
                payload = self._read_json()
                token, identity = issue_asset_token(
                    asset_id=str(payload.get("asset_id", "")),
                    country=str(payload.get("country", "")),
                    region=str(payload.get("region", "")),
                    platform=str(payload.get("platform", "")),
                )
                self._json(
                    201,
                    {
                        "token": token,
                        "asset": asdict(identity),
                        "scope": GLOBAL_SCOPE,
                        "node": _node(),
                    },
                )
                return

            if self.path == "/v2/evaluate":
                identity = verify_asset_token(bearer_token(self.headers.get("authorization")))
                payload = self._read_json()
                payload["protected_asset"] = {
                    "country": identity.country,
                    "region": identity.region,
                    "platform": identity.platform,
                }
                result = _decision(payload)
                result["asset"] = {
                    "asset_id": identity.asset_id,
                    "country": identity.country,
                    "region": identity.region,
                    "platform": identity.platform,
                    "expires_at": identity.expires_at,
                }
                self._json(200, result)
                return

            if self.path == "/v1/evaluate":
                payload = self._read_json()
                result = _decision(payload)
                self._json(451 if result.get("state") == "OUT_OF_SCOPE" else 200, result)
                return

            self._json(404, {"error": "not_found"})
        except AssetAuthError as exc:
            self._json(401, {"error": "asset_auth", "detail": str(exc)})
        except (ValueError, json.JSONDecodeError) as exc:
            self._json(400, {"error": "invalid_request", "detail": str(exc)})

    def log_message(self, format: str, *args: Any) -> None:
        return


def main() -> int:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    ThreadingHTTPServer((host, port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
