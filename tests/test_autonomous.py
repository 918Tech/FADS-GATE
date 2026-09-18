import os
import unittest
from unittest.mock import patch

from fads_gate.autonomous import apply_public_threat_policy


class AutonomousDefenseTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {"FADS_AUTONOMOUS_MODE": "true"}, clear=False)
        self.env.start()

    def tearDown(self):
        self.env.stop()

    def test_high_confidence_public_threat_quarantines_local_asset(self):
        base = {
            "state": "TRUSTED",
            "route": "CLOAK_CANONICAL",
            "decision": "ALLOW_LIMITED",
            "granted": ["repo.read", "telemetry.read"],
        }
        enrichment = {
            "schema": "918-PUBLIC-THREAT-ARRAYS/1",
            "sources_used": ["greynoise-community"],
            "findings": [],
            "malicious_infrastructure": ["8.8.8.8"],
            "threat_clusters": ["example-cluster"],
            "confidence": 95,
            "errors": [],
            "personal_identity_inference": False,
            "physical_person_tracking": False,
        }
        with patch("fads_gate.autonomous.enrich_observables", return_value=enrichment):
            result = apply_public_threat_policy(
                base,
                {"observables": {"ips": ["8.8.8.8"]}},
            )
        self.assertEqual(result["state"], "QUARANTINED")
        self.assertEqual(result["route"], "HOUSE_OF_MIRRORS_PUBLIC_THREAT")
        self.assertEqual(result["granted"], ["telemetry.read"])
        self.assertFalse(result["autonomous_action"]["remote_contact"])

    def test_medium_confidence_restricts_trusted_asset(self):
        base = {
            "state": "TRUSTED",
            "route": "CLOAK_CANONICAL",
            "decision": "ALLOW_LIMITED",
            "granted": ["repo.read", "telemetry.read"],
        }
        enrichment = {
            "malicious_infrastructure": ["8.8.8.8"],
            "confidence": 75,
        }
        with patch("fads_gate.autonomous.enrich_observables", return_value=enrichment):
            result = apply_public_threat_policy(
                base,
                {"observables": {"ips": ["8.8.8.8"]}},
            )
        self.assertEqual(result["state"], "RESTRICTED")
        self.assertEqual(result["route"], "CLOAK_RESTRICTED")
        self.assertFalse(result["autonomous_action"]["remote_contact"])

    def test_autonomous_policy_does_not_downgrade_terminated_state(self):
        base = {
            "state": "TERMINATED",
            "route": "NO_CAPABILITY",
            "decision": "TERMINATE_SESSION",
            "granted": [],
        }
        enrichment = {
            "malicious_infrastructure": ["8.8.8.8"],
            "confidence": 100,
        }
        with patch("fads_gate.autonomous.enrich_observables", return_value=enrichment):
            result = apply_public_threat_policy(
                base,
                {"observables": {"ips": ["8.8.8.8"]}},
            )
        self.assertEqual(result["state"], "TERMINATED")
        self.assertEqual(result["route"], "NO_CAPABILITY")


if __name__ == "__main__":
    unittest.main()
