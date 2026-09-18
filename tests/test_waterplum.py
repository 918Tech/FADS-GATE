import unittest

from fads_gate.server import _decision
from fads_gate.waterplum import assess_waterplum


class WaterPlumTests(unittest.TestCase):
    def test_exact_published_ip_quarantines(self):
        result = assess_waterplum(observables={"ips": ["95.164.17.24"]})
        self.assertEqual(result.state, "QUARANTINED")
        self.assertEqual(result.route, "HOUSE_OF_MIRRORS_WATERPLUM")
        self.assertIn("published-ip:95.164.17.24", result.matches)

    def test_published_package_quarantines(self):
        result = assess_waterplum(observables={"packages": ["passports-js"]})
        self.assertEqual(result.state, "QUARANTINED")
        self.assertIn("published-package:passports-js", result.matches)

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
                "observables": {"ips": ["95.164.17.24"]},
            }
        )
        self.assertEqual(result["granted"], ["repo.read"])
        self.assertEqual(result["route"], "HOUSE_OF_MIRRORS_WATERPLUM")
        self.assertFalse(result["active_contact"])


if __name__ == "__main__":
    unittest.main()
