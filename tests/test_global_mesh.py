import os
import unittest
from unittest.mock import patch

from fads_gate.global_mesh import GLOBAL_SCOPE, evaluate_scope
from fads_gate.server import _decision


class GlobalMeshTests(unittest.TestCase):
    def test_global_scope_excludes_kp(self):
        decision = evaluate_scope({"protected_asset": {"country": "KP"}})
        self.assertFalse(decision.in_scope)
        self.assertEqual(decision.scope, GLOBAL_SCOPE)
        self.assertEqual(decision.country, "KP")

    def test_global_scope_allows_other_country(self):
        decision = evaluate_scope({"protected_asset": {"country": "US"}})
        self.assertTrue(decision.in_scope)
        self.assertEqual(decision.country, "US")

    def test_unknown_country_remains_in_scope(self):
        decision = evaluate_scope({})
        self.assertTrue(decision.in_scope)
        self.assertEqual(decision.country, "UNKNOWN")

    def test_server_returns_no_operation_for_kp(self):
        result = _decision(
            {
                "protected_asset": {"country": "KP"},
                "capabilities": ["repo.read", "telemetry.read"],
                "observables": {"ips": ["162.0.239.85"]},
            }
        )
        self.assertEqual(result["state"], "OUT_OF_SCOPE")
        self.assertEqual(result["route"], "NO_OPERATION")
        self.assertEqual(result["granted"], [])
        self.assertFalse(result["active_contact"])

    def test_server_advertises_node_identity(self):
        with patch.dict(
            os.environ,
            {"FADS_NODE_ID": "mesh-test", "FADS_NODE_REGION": "test-region"},
            clear=False,
        ):
            result = _decision({"protected_asset": {"country": "DE"}})
        self.assertEqual(result["node"]["id"], "mesh-test")
        self.assertEqual(result["node"]["region"], "test-region")


if __name__ == "__main__":
    unittest.main()
