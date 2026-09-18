import os
import unittest
from unittest.mock import patch

from fads_gate.proximity_jumper import (
    AnchorObservation,
    LandmarkObservation,
    next_hop,
    pseudonymize_landmark,
    rank_hops,
    sanitize_observation,
    shared_landmark_score,
)
from fads_gate.proximity_store import list_anchors, parse_anchor, put_anchor


class PassiveProximityTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(
            os.environ,
            {"FADS_LANDMARK_KEY": "l" * 64},
            clear=False,
        )
        self.env.start()

    def tearDown(self):
        self.env.stop()

    def test_landmark_is_pseudonymized_locally(self):
        value = pseudonymize_landmark(bssid="AA:BB:CC:DD:EE:FF", ssid="Portal")
        self.assertTrue(value.startswith("hmac-sha256:"))
        self.assertNotIn("AA:BB", value)
        self.assertNotIn("Portal", value)

    def test_sanitize_never_associates_or_authenticates(self):
        observation = sanitize_observation(
            {
                "bssid": "AA:BB:CC:DD:EE:FF",
                "ssid": "Portal",
                "rssi": -45,
                "channel": 6,
                "captive_portal": True,
                "observed_at": 100,
            }
        )
        self.assertTrue(observation.captive_portal)
        self.assertEqual(observation.rssi, -45)

    def test_shared_landmark_score_requires_same_landmark(self):
        a = LandmarkObservation("hmac-sha256:" + "a" * 64, -50, 6, 100, True)
        b = LandmarkObservation("hmac-sha256:" + "a" * 64, -55, 6, 100, True)
        c = LandmarkObservation("hmac-sha256:" + "b" * 64, -40, 11, 100, True)
        self.assertGreater(shared_landmark_score((a,), (b,)), 0.0)
        self.assertEqual(shared_landmark_score((a,), (c,)), 0.0)

    def test_next_hop_moves_only_toward_higher_echo_score(self):
        landmark = LandmarkObservation("hmac-sha256:" + "a" * 64, -50, 6, 100, True)
        current = AnchorObservation("sensor-a", (landmark,), 0.30, 100)
        closer = AnchorObservation(
            "sensor-b",
            (LandmarkObservation(landmark.landmark_id, -52, 6, 100, True),),
            0.70,
            100,
        )
        farther = AnchorObservation(
            "sensor-c",
            (LandmarkObservation(landmark.landmark_id, -49, 6, 100, True),),
            0.20,
            100,
        )
        hop = next_hop(current=current, candidates=(farther, closer), now=110)
        self.assertIsNotNone(hop)
        self.assertEqual(hop["next_asset"], "sensor-b")
        self.assertFalse(hop["network_use"])
        self.assertFalse(hop["association"])
        self.assertFalse(hop["authentication"])

    def test_stale_candidate_is_not_ranked(self):
        landmark = LandmarkObservation("hmac-sha256:" + "a" * 64, -50, 6, 100, True)
        current = AnchorObservation("sensor-a", (landmark,), 0.30, 400)
        stale = AnchorObservation(
            "sensor-b",
            (LandmarkObservation(landmark.landmark_id, -50, 6, 100, True),),
            0.90,
            100,
        )
        self.assertEqual(rank_hops(current=current, candidates=(stale,), now=400), [])

    def test_server_store_accepts_only_pseudonymized_landmarks(self):
        with self.assertRaises(ValueError):
            parse_anchor(
                asset_id="sensor-a",
                payload={
                    "landmarks": [
                        {
                            "landmark_id": "AA:BB:CC:DD:EE:FF",
                            "rssi": -40,
                            "channel": 6,
                            "captive_portal": True,
                        }
                    ],
                    "echo_score": 0.5,
                },
                observed_at=100,
            )

    def test_cache_expires(self):
        anchor = AnchorObservation("sensor-cache", (), 0.1, 100)
        put_anchor(anchor)
        alive = {item.asset_id for item in list_anchors(now=150, ttl_seconds=180)}
        expired = {item.asset_id for item in list_anchors(now=400, ttl_seconds=180)}
        self.assertIn("sensor-cache", alive)
        self.assertNotIn("sensor-cache", expired)


if __name__ == "__main__":
    unittest.main()
