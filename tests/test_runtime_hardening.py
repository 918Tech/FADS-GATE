import os
import unittest
from unittest.mock import patch

from fads_gate.evidence_signing import sign_evidence
from fads_gate.rate_limit import RateLimitExceeded, check_rate_limit


class RuntimeHardeningTests(unittest.TestCase):
    def test_rate_limit_fails_after_limit(self):
        key = "test-key"
        check_rate_limit(key, limit=2, window_seconds=60, now=100)
        check_rate_limit(key, limit=2, window_seconds=60, now=101)
        with self.assertRaises(RateLimitExceeded):
            check_rate_limit(key, limit=2, window_seconds=60, now=102)

    def test_rate_limit_window_expires(self):
        key = "test-expire"
        check_rate_limit(key, limit=1, window_seconds=10, now=100)
        check_rate_limit(key, limit=1, window_seconds=10, now=111)

    def test_evidence_signs_when_key_present(self):
        with patch.dict(os.environ, {"FADS_EVIDENCE_KEY": "e" * 64}, clear=False):
            result = sign_evidence({"a": 1})
        self.assertTrue(result["signed"])
        self.assertEqual(result["signature_alg"], "HMAC-SHA256")
        self.assertTrue(result["signature"].startswith("sha256:"))

    def test_evidence_reports_unsigned_without_key(self):
        with patch.dict(os.environ, {"FADS_EVIDENCE_KEY": ""}, clear=False):
            result = sign_evidence({"a": 1})
        self.assertFalse(result["signed"])


if __name__ == "__main__":
    unittest.main()
