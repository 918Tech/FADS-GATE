import os
import unittest
from unittest.mock import patch

from fads_gate.geo_attestation import (
    GeoAttestationError,
    GeoExcludedError,
    attest_source_ip,
    source_ip_from_headers,
)


class GeoAttestationTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(
            os.environ,
            {
                "FADS_GEO_HASH_SALT": "s" * 64,
                "FADS_GEO_PROVIDERS": "https://one.example/{ip},https://two.example/{ip}",
            },
            clear=False,
        )
        self.env.start()

    def tearDown(self):
        self.env.stop()

    def test_rightmost_public_forwarded_ip_wins(self):
        headers = {
            "X-Forwarded-For": "203.0.113.9, 198.51.100.8, 8.8.8.8"
        }
        self.assertEqual(source_ip_from_headers(headers, "10.0.0.2"), "8.8.8.8")

    def test_private_only_forwarded_chain_fails_closed(self):
        with self.assertRaises(GeoAttestationError):
            source_ip_from_headers(
                {"X-Forwarded-For": "10.0.0.1, 192.168.1.20"},
                "172.16.0.5",
            )

    def test_two_provider_consensus_attests_country(self):
        with patch(
            "fads_gate.geo_attestation._lookup",
            side_effect=[("US", "one.example"), ("US", "two.example")],
        ):
            result = attest_source_ip("8.8.8.8")
        self.assertEqual(result.country, "US")
        self.assertTrue(result.consensus)
        self.assertEqual(result.providers, ("one.example", "two.example"))
        self.assertTrue(result.source_ip_hash.startswith("sha256:"))
        self.assertNotIn("8.8.8.8", result.source_ip_hash)

    def test_provider_disagreement_fails_closed(self):
        with patch(
            "fads_gate.geo_attestation._lookup",
            side_effect=[("US", "one.example"), ("DE", "two.example")],
        ):
            with self.assertRaises(GeoAttestationError):
                attest_source_ip("8.8.8.8")

    def test_single_provider_success_fails_closed(self):
        with patch(
            "fads_gate.geo_attestation._lookup",
            side_effect=[("US", "one.example"), GeoAttestationError("down")],
        ):
            with self.assertRaises(GeoAttestationError):
                attest_source_ip("8.8.8.8")

    def test_kp_consensus_is_excluded(self):
        with patch(
            "fads_gate.geo_attestation._lookup",
            side_effect=[("KP", "one.example"), ("KP", "two.example")],
        ):
            with self.assertRaises(GeoExcludedError):
                attest_source_ip("8.8.8.8")


if __name__ == "__main__":
    unittest.main()
