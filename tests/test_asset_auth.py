import os
import unittest
from unittest.mock import patch

from fads_gate.asset_auth import AssetAuthError, issue_asset_token, verify_asset_token
from fads_gate.server import _decision

IP_HASH = "sha256:" + ("a" * 64)
PROVIDERS = ("ipwho.is", "ipapi.co")


class AssetEnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(
            os.environ,
            {
                "FADS_TOKEN_KEY": "t" * 64,
                "FADS_ENROLLMENT_KEY": "e" * 64,
                "FADS_GEO_HASH_SALT": "g" * 64,
            },
            clear=False,
        )
        self.env.start()

    def tearDown(self):
        self.env.stop()

    def _issue(self, **overrides):
        values = {
            "asset_id": "host-01",
            "country": "US",
            "region": "us-central",
            "platform": "linux",
            "attested_ip_hash": IP_HASH,
            "attestation_providers": PROVIDERS,
            "attested_at": 1_000,
            "now": 1_000,
            "ttl_seconds": 600,
        }
        values.update(overrides)
        return issue_asset_token(**values)

    def test_issue_and_verify_geo_attested_token(self):
        token, identity = self._issue()
        verified = verify_asset_token(token, now=1_100)
        self.assertEqual(verified.asset_id, identity.asset_id)
        self.assertEqual(verified.country, "US")
        self.assertEqual(verified.attested_ip_hash, IP_HASH)
        self.assertEqual(verified.attestation_providers, PROVIDERS)
        self.assertEqual(verified.scope, "GLOBAL_EXCEPT_KP")

    def test_kp_token_is_rejected(self):
        with self.assertRaises(AssetAuthError):
            self._issue(country="KP")

    def test_expired_token_is_rejected(self):
        token, _ = self._issue(ttl_seconds=300)
        with self.assertRaises(AssetAuthError):
            verify_asset_token(token, now=1_301)

    def test_tampered_token_is_rejected(self):
        token, _ = self._issue()
        head, payload, signature = token.split(".")
        replacement = "A" if payload[-1] != "A" else "B"
        tampered = head + "." + payload[:-1] + replacement + "." + signature
        with self.assertRaises(AssetAuthError):
            verify_asset_token(tampered, now=1_100)

    def test_single_attestation_provider_is_rejected(self):
        with self.assertRaises(AssetAuthError):
            self._issue(attestation_providers=("one.example",))

    def test_token_country_drives_scope(self):
        token, identity = self._issue(platform="windows")
        verified = verify_asset_token(token, now=1_100)
        payload = {
            "protected_asset": {
                "country": verified.country,
                "region": verified.region,
                "platform": verified.platform,
            },
            "capabilities": ["telemetry.read"],
        }
        result = _decision(payload)
        self.assertTrue(result["scope"]["in_scope"])
        self.assertEqual(result["scope"]["country"], identity.country)


if __name__ == "__main__":
    unittest.main()
