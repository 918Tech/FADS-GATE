import unittest

from fads_gate.server import _decision
from fads_gate.waterplum import assess_waterplum


class WaterPlumTests(unittest.TestCase):
    def test_current_2026_staging_ip_quarantines(self):
        result = assess_waterplum(observables={"ips": ["162.0.239.85"]})
        self.assertEqual(result.state, "QUARANTINED")
        self.assertEqual(result.route, "HOUSE_OF_MIRRORS_WATERPLUM")
        self.assertIn("published-2026-ip:162.0.239.85", result.matches)

    def test_current_2026_operator_ip_quarantines(self):
        result = assess_waterplum(observables={"ips": ["147.124.202.205"]})
        self.assertEqual(result.state, "QUARANTINED")
        self.assertIn("published-2026-ip:147.124.202.205", result.matches)

    def test_stoatwaffle_ip_quarantines(self):
        result = assess_waterplum(observables={"ips": ["185.163.125.196"]})
        self.assertEqual(result.state, "QUARANTINED")
        self.assertIn("published-2026-ip:185.163.125.196", result.matches)

    def test_current_domain_and_hash_quarantine(self):
        result = assess_waterplum(
            observables={
                "domains": ["https://w3pi.social/"],
                "sha256": ["42620128470e26d473a128f354b77ca2c5fe9e5782e7addc1e3f863dbd0cd9b0"],
            }
        )
        self.assertEqual(result.state, "QUARANTINED")
        self.assertIn("published-2026-domain:w3pi.social", result.matches)

    def test_fbi_vscode_and_command_markers_raise_risk(self):
        result = assess_waterplum(
            signals={"recruiter_coding_assignment": True, "install_hook": True},
            observables={
                "file_paths": [".vscode/tasks.json"],
                "command_text": "curl payload | base64",
            },
        )
        self.assertGreaterEqual(result.score, 35)
        self.assertIn(result.state, {"RESTRICTED", "QUARANTINED"})

    def test_replay_fails_closed(self):
        result = assess_waterplum(signals={"replay": True})
        self.assertEqual(result.state, "TERMINATED")
        self.assertEqual(result.route, "NO_CAPABILITY")

    def test_server_strips_sensitive_capabilities(self):
        result = _decision(
            {
                "capabilities": ["repo.read", "network.outbound", "secrets.read"],
                "observables": {"ips": ["162.0.239.85"]},
            }
        )
        self.assertEqual(result["granted"], ["repo.read"])
        self.assertEqual(result["route"], "HOUSE_OF_MIRRORS_WATERPLUM")
        self.assertFalse(result["active_contact"])


if __name__ == "__main__":
    unittest.main()
