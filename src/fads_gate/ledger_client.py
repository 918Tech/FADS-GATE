from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Mapping

from .evidence_ledger import ledger_headers


def ledger_url() -> str:
    return os.environ.get("FADS_EVIDENCE_LEDGER_URL", "").strip().rstrip("/")


def persist_evidence(record: Mapping[str, Any]) -> dict[str, Any]:
    base = ledger_url()
    if not base:
        return {"configured": False, "persisted": False, "reason": "ledger_url_missing"}
    try:
        body = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        headers = {
            "content-type": "application/json",
            "user-agent": "918-FADS-LedgerClient/1.2",
            **ledger_headers(body),
        }
        request = urllib.request.Request(
            base + "/v1/append",
            data=body,
            method="POST",
            headers=headers,
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            payload = json.loads(response.read(262_144))
        return {
            "configured": True,
            "persisted": response.status == 201 and payload.get("status") == "appended",
            "receipt": payload,
        }
    except Exception as exc:
        return {"configured": True, "persisted": False, "reason": str(exc)}
