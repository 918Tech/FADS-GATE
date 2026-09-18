from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Mapping


ZERO_HASH = "0" * 64


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class HashChainAuditLog:
    """Append-only JSONL audit log with a SHA-256 hash chain."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def _tail_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return ZERO_HASH
        last = self.path.read_text(encoding="utf-8").splitlines()[-1]
        return str(json.loads(last)["event_hash"])

    def append(self, event: Mapping[str, Any]) -> str:
        previous_hash = self._tail_hash()
        payload = {"previous_hash": previous_hash, **dict(event)}
        event_hash = hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()
        record = {**payload, "event_hash": event_hash}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(_canonical_json(record) + "\n")
        return event_hash

    def verify(self) -> tuple[bool, int]:
        if not self.path.exists():
            return True, 0
        previous_hash = ZERO_HASH
        count = 0
        for line in self.path.read_text(encoding="utf-8").splitlines():
            count += 1
            record = json.loads(line)
            recorded_hash = record.pop("event_hash")
            if record.get("previous_hash") != previous_hash:
                return False, count
            expected = hashlib.sha256(_canonical_json(record).encode("utf-8")).hexdigest()
            if recorded_hash != expected:
                return False, count
            previous_hash = recorded_hash
        return True, count


def result_event(result: Any) -> dict[str, Any]:
    return {
        "type": "capability-decision",
        "subject_id": result.subject_id,
        "requested": list(result.requested),
        "granted": list(result.granted),
        "stripped": list(result.stripped),
        "detection": asdict(result.detection),
        "decisions": [asdict(item) for item in result.decisions],
    }
