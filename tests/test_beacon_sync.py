import os
import unittest
from unittest.mock import patch

from fads_gate.beacon_sync_auth import BeaconSyncAuthError, headers, verify
from fads_gate.proximity_coordinator import _validate_anchor


class BeaconSyncTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(
            os.environ,
            {"FADS_BEACON_SYNC_KEY": "b" * 64},
            clear=False,
        )
        self.env.start()

    def tearDown(self):
        self.env.stop()

    def test_signed_request_verifies(self):
        body = b'{"asset_id":"sensor-a"}'
        signed = headers(method="POST", path="/v2/beacon-sync/anchor", body=body, timestamp=1000)
        verify(
            method="POST",
            path="/v2/beacon-sync/anchor",
            body=body,
            timestamp_header=signed["x-918-beacon-timestamp"],
            signature_header=signed["x-918-beacon-signature"],
            now=1000,
        )

    def test_replay_window_fails_closed(self):
        body = b"{}"
        signed = headers(method="POST", path="/v2/beacon-sync/anchor", body=body, timestamp=1000)
        with self.assertRaises(BeaconSyncAuthError):
            verify(
                method="POST",
                path="/v2/beacon-sync/anchor",
                body=body,
                timestamp_header=signed["x-918-beacon-timestamp"],
                signature_header=signed["x-918-beacon-signature"],
                now=1200,
            )

    def test_tampered_body_fails(self):
        body = b'{"asset_id":"sensor-a"}'
        signed = headers(method="POST", path="/v2/beacon-sync/anchor", body=body, timestamp=1000)
        with self.assertRaises(BeaconSyncAuthError):
            verify(
                method="POST",
                path="/v2/beacon-sync/anchor",
                body=b'{"asset_id":"sensor-b"}',
                timestamp_header=signed["x-918-beacon-timestamp"],
                signature_header=signed["x-918-beacon-signature"],
                now=1000,
            )

    def test_coordinator_rejects_raw_wifi_identifier(self):
        with self.assertRaises(ValueError):
            _validate_anchor(
                {
                    "asset_id": "sensor-a",
                    "observations": [
                        {
                            "landmark_id": "AA:BB:CC:DD:EE:FF",
                            "rssi": -40,
                            "channel": 6,
                            "observed_at": 100,
                            "captive_portal": True,
                        }
                    ],
                    "echo_score": 0.5,
                    "observed_at": 100,
                    "beacon": {"id": "918-beacon-north-america"},
                }
            )

    def test_coordinator_accepts_pseudonymized_anchor(self):
        result = _validate_anchor(
            {
                "asset_id": "sensor-a",
                "observations": [
                    {
                        "landmark_id": "hmac-sha256:" + "a" * 64,
                        "rssi": -40,
                        "channel": 6,
                        "observed_at": 100,
                        "captive_portal": True,
                    }
                ],
                "echo_score": 0.7,
                "observed_at": 100,
                "beacon": {
                    "id": "918-beacon-north-america",
                    "logical_continent": "North America",
                    "hosting_continent": "North America",
                    "physical_host_region": "ohio",
                    "relay_hosted": False,
                },
            }
        )
        self.assertEqual(result["asset_id"], "sensor-a")
        self.assertEqual(result["beacon"]["logical_continent"], "North America")


if __name__ == "__main__":
    unittest.main()
