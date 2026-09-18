import os
import unittest
from unittest.mock import patch

from fads_gate.benchmark import run_benchmark
from fads_gate.evidence_ledger import ledger_headers, verify_ingest_auth
from fads_gate.release_gate import test_readiness


class WorldUseReadinessTests(unittest.TestCase):
    def test_defensive_benchmark_passes(self):
        report = run_benchmark()
        self.assertTrue(report["passed"])
        self.assertEqual(report["synthetic_false_positive_failures"], 0)
        self.assertEqual(report["scenarios_passed"], report["scenario_count"])

    def test_test_readiness_reaches_test_ready(self):
        result = test_readiness()
        self.assertEqual(result["status"], "TEST_READY")
        self.assertTrue(all(result["checks"].values()))

    def test_ledger_ingest_auth_round_trip(self):
        body = b'{"state":"QUARANTINED"}'
        with patch.dict(os.environ, {"FADS_LEDGER_INGEST_KEY": "k" * 64}, clear=False):
            headers = ledger_headers(body, timestamp=1000)
            verify_ingest_auth(
                body=body,
                timestamp_header=headers["x-918-ledger-timestamp"],
                signature_header=headers["x-918-ledger-signature"],
                now=1000,
            )

    def test_ledger_replay_window_fails(self):
        body = b'{"state":"TRUSTED"}'
        with patch.dict(os.environ, {"FADS_LEDGER_INGEST_KEY": "k" * 64}, clear=False):
            headers = ledger_headers(body, timestamp=1000)
            with self.assertRaises(Exception):
                verify_ingest_auth(
                    body=body,
                    timestamp_header=headers["x-918-ledger-timestamp"],
                    signature_header=headers["x-918-ledger-signature"],
                    now=1200,
                )


if __name__ == "__main__":
    unittest.main()
