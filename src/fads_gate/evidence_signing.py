from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any, Mapping


def _key() -> bytes:
    value = os.environ.get("FADS_EVIDENCE_KEY", "")
    if len(value) < 32:
        return b""
    return value.encode("utf-8")


def sign_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    key = _key()
    result = {
        "content_hash": f"sha256:{digest}",
        "signature_alg": None,
        "signature": None,
        "signed": False,
    }
    if key:
        sig = hmac.new(key, payload, hashlib.sha256).hexdigest()
        result.update({
            "signature_alg": "HMAC-SHA256",
            "signature": f"sha256:{sig}",
            "signed": True,
        })
    return result
