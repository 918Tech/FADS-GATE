import json
import tempfile
import unittest
from pathlib import Path

from fads_gate.audit import HashChainAuditLog
from fads_gate.gateway import CapabilityGateway
from fads_gate.guardian import FADSGuardian
from fads_gate.models import CapabilityRequest
from fads_gate.policy import CapabilityPolicy


class GuardianTests(unittest.TestCase):
    def test_declared_agent_evidence(self):
        report = FADSGuardian().inspect({"kind": "agent", "protocol": "mcp", "tools": ["repo"]})
        self.assertTrue(report.is_declared_agent)
        self.assertGreaterEqual(report.confidence, 50)
        self.assertIn("declared-kind:agent", report.signals)

    def test_empty_manifest_is_not_claimed_as_agent(self):
        report = FADSGuardian().inspect({})
        self.assertFalse(report.is_declared_agent)
        self.assertEqual(report.confidence, 0)


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.policy = CapabilityPolicy.from_mapping(
            {
                "default": "deny",
                "hard_denies": ["secrets.*", "capability.delegate"],
                "rules": [
                    {
                        "id": "trusted-read",
                        "effect": "allow",
                        "subjects": ["trusted:*"],
                        "capabilities": ["repo.read", "telemetry.read"],
                        "max_risk": 25,
                    },
                    {
                        "id": "agent-read",
                        "effect": "allow",
                        "subjects": ["agent:*"],
                        "capabilities": ["repo.read"],
                        "max_risk": 25,
                        "require_declared_agent": True,
                    },
                ],
            }
        )

    def test_default_deny_strips_unapproved_capabilities(self):
        result = CapabilityGateway(self.policy).authorize(
            CapabilityRequest(
                subject_id="trusted:scanner",
                requested=("repo.read", "process.exec", "secrets.read"),
                manifest={},
            )
        )
        self.assertEqual(result.granted, ("repo.read",))
        self.assertEqual(result.stripped, ("process.exec", "secrets.read"))

    def test_hard_deny_wins(self):
        policy = CapabilityPolicy.from_mapping(
            {"default": "allow", "hard_denies": ["secrets.*"], "rules": []}
        )
        result = CapabilityGateway(policy).authorize(
            CapabilityRequest("trusted:any", ("repo.read", "secrets.read"), {})
        )
        self.assertEqual(result.granted, ("repo.read",))
        self.assertEqual(result.stripped, ("secrets.read",))

    def test_declared_agent_constraint(self):
        gateway = CapabilityGateway(self.policy)
        denied = gateway.authorize(CapabilityRequest("agent:x", ("repo.read",), {}))
        allowed = gateway.authorize(
            CapabilityRequest("agent:x", ("repo.read",), {"kind": "agent"})
        )
        self.assertFalse(denied.decisions[0].allowed)
        self.assertTrue(allowed.decisions[0].allowed)

    def test_manifest_reduction(self):
        reduced, result = CapabilityGateway(self.policy).strip_manifest(
            subject_id="trusted:scanner",
            manifest={"capabilities": ["repo.read", "repo.push"]},
        )
        self.assertEqual(reduced["capabilities"], ["repo.read"])
        self.assertTrue(result.changed)

    def test_hash_chain_detects_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            log = HashChainAuditLog(path)
            gateway = CapabilityGateway(self.policy, audit_log=log)
            gateway.authorize(CapabilityRequest("trusted:a", ("repo.read",), {}))
            gateway.authorize(CapabilityRequest("trusted:b", ("repo.read",), {}))
            ok, count = log.verify()
            self.assertTrue(ok)
            self.assertEqual(count, 2)

            lines = path.read_text(encoding="utf-8").splitlines()
            record = json.loads(lines[0])
            record["subject_id"] = "tampered"
            lines[0] = json.dumps(record, sort_keys=True, separators=(",", ":"))
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            ok, failed_at = log.verify()
            self.assertFalse(ok)
            self.assertEqual(failed_at, 1)


if __name__ == "__main__":
    unittest.main()
