import os
import unittest
from unittest.mock import patch

from fads_gate import proximity_coordinator as coordinator
from fads_gate import defense_posture


class AttackActivatedDefenseTests(unittest.TestCase):
    def setUp(self):
        coordinator._DEFENSE_EVENTS.clear()

    def tearDown(self):
        coordinator._DEFENSE_EVENTS.clear()

    def test_restricted_event_sets_heightened_posture(self):
        event = coordinator._validate_defense_event(
            {
                "event_id": "evt-1",
                "asset_id": "asset-1",
                "state": "RESTRICTED",
                "route": "CLOAK_RESTRICTED",
                "observed_at": 1000,
                "node": {"id": "node-a", "region": "ohio", "beacon": {}},
            }
        )
        coordinator._DEFENSE_EVENTS[event["event_id"]] = event
        with patch("fads_gate.proximity_coordinator.time.time", return_value=1001):
            posture = coordinator._defense_posture()
        self.assertEqual(posture["mode"], "HEIGHTENED")
        self.assertEqual(posture["severity"], 1)
        self.assertFalse(posture["remote_action"])

    def test_quarantine_sets_containment_posture(self):
        event = coordinator._validate_defense_event(
            {
                "event_id": "evt-2",
                "asset_id": "asset-2",
                "state": "QUARANTINED",
                "route": "HOUSE_OF_MIRRORS_WATERPLUM",
                "observed_at": 1000,
                "node": {"id": "node-a", "region": "ohio", "beacon": {}},
            }
        )
        coordinator._DEFENSE_EVENTS[event["event_id"]] = event
        with patch("fads_gate.proximity_coordinator.time.time", return_value=1001):
            posture = coordinator._defense_posture()
        self.assertEqual(posture["mode"], "CONTAINMENT")
        self.assertEqual(posture["severity"], 2)

    def test_terminated_sets_critical_posture(self):
        event = coordinator._validate_defense_event(
            {
                "event_id": "evt-3",
                "asset_id": "asset-3",
                "state": "TERMINATED",
                "route": "NO_CAPABILITY",
                "observed_at": 1000,
                "node": {"id": "node-a", "region": "ohio", "beacon": {}},
            }
        )
        coordinator._DEFENSE_EVENTS[event["event_id"]] = event
        with patch("fads_gate.proximity_coordinator.time.time", return_value=1001):
            posture = coordinator._defense_posture()
        self.assertEqual(posture["mode"], "CRITICAL")
        self.assertEqual(posture["severity"], 3)

    def test_stale_attack_event_expires_to_normal(self):
        event = coordinator._validate_defense_event(
            {
                "event_id": "evt-4",
                "asset_id": "asset-4",
                "state": "QUARANTINED",
                "route": "HOUSE_OF_MIRRORS_WATERPLUM",
                "observed_at": 1000,
                "node": {"id": "node-a", "region": "ohio", "beacon": {}},
            }
        )
        coordinator._DEFENSE_EVENTS[event["event_id"]] = event
        with patch(
            "fads_gate.proximity_coordinator.time.time",
            return_value=1000 + coordinator.DEFENSE_EVENT_TTL_SECONDS + 1,
        ):
            posture = coordinator._defense_posture()
        self.assertEqual(posture["mode"], "NORMAL")
        self.assertEqual(posture["active_events"], 0)

    def test_global_posture_tightens_rate_limit(self):
        with patch.dict(os.environ, {"FADS_AUTO_DEPLOY_ON_ATTACK": "true"}, clear=False):
            with patch.object(
                defense_posture,
                "_STATE",
                {
                    "mode": "CRITICAL",
                    "severity": 3,
                    "active_events": 1,
                    "updated_at": 1000,
                    "source": "global-coordinator",
                },
            ):
                self.assertEqual(defense_posture.rate_limit_for(120), 30)

    def test_invalid_state_is_rejected(self):
        with self.assertRaises(ValueError):
            coordinator._validate_defense_event(
                {
                    "event_id": "evt-bad",
                    "asset_id": "asset-bad",
                    "state": "TRUSTED",
                    "route": "CLOAK_CANONICAL",
                    "observed_at": 1000,
                    "node": {},
                }
            )


if __name__ == "__main__":
    unittest.main()
