from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Mapping

try:
    import psycopg
except ImportError:  # pragma: no cover - deployment dependency check
    psycopg = None


class EvidenceLedgerError(RuntimeError):
    pass


def _database_url() -> str:
    return os.environ.get("DATABASE_URL", "").strip()


def _ingest_key() -> bytes:
    value = os.environ.get("FADS_LEDGER_INGEST_KEY", "")
    if len(value) < 32:
        raise EvidenceLedgerError("FADS_LEDGER_INGEST_KEY must be at least 32 characters")
    return value.encode("utf-8")


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _payload_hash(record: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(record)).hexdigest()


def _auth_signature(body: bytes, timestamp: int) -> str:
    canonical = str(timestamp).encode("ascii") + b"\n" + hashlib.sha256(body).hexdigest().encode("ascii")
    return "sha256=" + hmac.new(_ingest_key(), canonical, hashlib.sha256).hexdigest()


def verify_ingest_auth(
    *,
    body: bytes,
    timestamp_header: str | None,
    signature_header: str | None,
    now: int | None = None,
    max_skew_seconds: int = 90,
) -> None:
    try:
        timestamp = int(str(timestamp_header or ""))
    except ValueError as exc:
        raise EvidenceLedgerError("invalid ledger timestamp") from exc
    current = int(time.time() if now is None else now)
    if abs(current - timestamp) > max_skew_seconds:
        raise EvidenceLedgerError("ledger request outside replay window")
    expected = _auth_signature(body, timestamp)
    if not signature_header or not hmac.compare_digest(signature_header, expected):
        raise EvidenceLedgerError("invalid ledger signature")


def ledger_headers(body: bytes, *, timestamp: int | None = None) -> dict[str, str]:
    ts = int(time.time() if timestamp is None else timestamp)
    return {
        "x-918-ledger-timestamp": str(ts),
        "x-918-ledger-signature": _auth_signature(body, ts),
    }


def _connect():
    if psycopg is None:
        raise EvidenceLedgerError("psycopg is not installed")
    url = _database_url()
    if not url:
        raise EvidenceLedgerError("DATABASE_URL is not configured")
    return psycopg.connect(url, autocommit=False)


def initialize_schema() -> None:
    with _connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS fads_evidence (
                    seq BIGSERIAL PRIMARY KEY,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    content_hash TEXT NOT NULL UNIQUE,
                    prev_chain_hash TEXT NOT NULL,
                    chain_hash TEXT NOT NULL UNIQUE,
                    record JSONB NOT NULL
                )
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS fads_evidence_created_at_idx ON fads_evidence(created_at)"
            )
        conn.commit()


def append_record(record: Mapping[str, Any]) -> dict[str, Any]:
    payload_hash = _payload_hash(record)
    with _connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(%s)", (9181201,))
            cur.execute(
                "SELECT chain_hash FROM fads_evidence ORDER BY seq DESC LIMIT 1"
            )
            row = cur.fetchone()
            prev = row[0] if row else "GENESIS"
            chain_hash = hashlib.sha256(
                (prev + "|" + payload_hash).encode("utf-8")
            ).hexdigest()
            cur.execute(
                """
                INSERT INTO fads_evidence(content_hash, prev_chain_hash, chain_hash, record)
                VALUES (%s, %s, %s, %s::jsonb)
                RETURNING seq, created_at
                """,
                (
                    "sha256:" + payload_hash,
                    prev,
                    "sha256:" + chain_hash,
                    json.dumps(record, sort_keys=True, separators=(",", ":")),
                ),
            )
            seq, created_at = cur.fetchone()
        conn.commit()
    return {
        "seq": int(seq),
        "created_at": created_at.isoformat(),
        "content_hash": "sha256:" + payload_hash,
        "prev_chain_hash": prev,
        "chain_hash": "sha256:" + chain_hash,
    }


def verify_chain() -> dict[str, Any]:
    expected_prev = "GENESIS"
    checked = 0
    with _connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT seq, content_hash, prev_chain_hash, chain_hash, record FROM fads_evidence ORDER BY seq ASC"
            )
            for seq, content_hash, prev, chain_hash, record in cur.fetchall():
                if prev != expected_prev:
                    return {"valid": False, "checked": checked, "broken_at": int(seq), "reason": "prev_hash"}
                payload_hash = _payload_hash(record)
                if content_hash != "sha256:" + payload_hash:
                    return {"valid": False, "checked": checked, "broken_at": int(seq), "reason": "content_hash"}
                expected_chain = "sha256:" + hashlib.sha256(
                    (expected_prev + "|" + payload_hash).encode("utf-8")
                ).hexdigest()
                if chain_hash != expected_chain:
                    return {"valid": False, "checked": checked, "broken_at": int(seq), "reason": "chain_hash"}
                expected_prev = chain_hash
                checked += 1
    return {"valid": True, "checked": checked, "head": expected_prev}


class Handler(BaseHTTPRequestHandler):
    server_version = "FADS-EVIDENCE-LEDGER/1.2"

    def _json(self, status: int, value: Any) -> None:
        body = json.dumps(value, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.send_header("cache-control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> bytes:
        length = int(self.headers.get("content-length", "0"))
        if length <= 0 or length > 1_048_576:
            raise EvidenceLedgerError("invalid body length")
        return self.rfile.read(length)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            try:
                initialize_schema()
                chain = verify_chain()
                self._json(
                    200,
                    {
                        "status": "operational" if chain["valid"] else "degraded",
                        "system": "918 FADS Evidence Ledger",
                        "database_bound": True,
                        "chain": chain,
                    },
                )
            except Exception as exc:
                self._json(
                    503,
                    {
                        "status": "degraded",
                        "system": "918 FADS Evidence Ledger",
                        "database_bound": False,
                        "error": str(exc),
                    },
                )
            return
        if self.path == "/v1/verify":
            try:
                self._json(200, verify_chain())
            except Exception as exc:
                self._json(503, {"valid": False, "error": str(exc)})
            return
        self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        if self.path != "/v1/append":
            self._json(404, {"error": "not_found"})
            return
        try:
            body = self._body()
            verify_ingest_auth(
                body=body,
                timestamp_header=self.headers.get("x-918-ledger-timestamp"),
                signature_header=self.headers.get("x-918-ledger-signature"),
            )
            value = json.loads(body)
            if not isinstance(value, dict):
                raise EvidenceLedgerError("record must be an object")
            initialize_schema()
            result = append_record(value)
            self._json(201, {"status": "appended", **result})
        except (EvidenceLedgerError, json.JSONDecodeError) as exc:
            self._json(400, {"error": "ledger_rejected", "detail": str(exc)})
        except Exception as exc:
            self._json(503, {"error": "ledger_unavailable", "detail": str(exc)})

    def log_message(self, format: str, *args: Any) -> None:
        return


def main() -> int:
    port = int(os.environ.get("PORT", "8080"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
