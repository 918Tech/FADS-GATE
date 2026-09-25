import json
import tempfile
import unittest
from pathlib import Path

from fads_gate.arsenal_registry import (
    REGISTRY_SCHEMA,
    classify_tool,
    find_tool,
    import_catalog,
    load_registry,
)


class ArsenalRegistryTests(unittest.TestCase):
    def test_offensive_tool_is_default_denied(self):
        policy = classify_tool({
            "id": "demo",
            "name": "Exploit Scanner",
            "description": "credential exploitation framework",
            "category": "red-team-offensive",
            "tags": ["phishing"],
        })
        self.assertEqual(policy.capability_class, "OFFENSIVE_OR_CREDENTIAL")
        self.assertEqual(policy.execution_policy, "DENY_AUTONOMOUS")
        self.assertFalse(policy.autonomous_execution)
        self.assertFalse(policy.remote_contact_allowed)
        self.assertTrue(policy.requires_explicit_authorization)

    def test_defensive_tool_is_catalog_only(self):
        policy = classify_tool({
            "id": "zeek",
            "name": "Zeek",
            "description": "network security monitor",
            "category": "blue-team-defensive",
            "tags": ["threat-intel"],
        })
        self.assertEqual(policy.capability_class, "DEFENSIVE_SENSOR_OR_THREAT_INTEL")
        self.assertEqual(policy.execution_policy, "DEFENSIVE_SANDBOX")
        self.assertFalse(policy.autonomous_execution)
        self.assertFalse(policy.remote_contact_allowed)

    def test_unknown_tool_is_default_deny(self):
        policy = classify_tool({
            "id": "mystery",
            "name": "Mystery Tool",
            "description": "does something unspecified",
            "category": "misc",
            "tags": [],
        })
        self.assertEqual(policy.capability_class, "UNCLASSIFIED")
        self.assertEqual(policy.execution_policy, "DEFAULT_DENY")
        self.assertTrue(policy.requires_explicit_authorization)

    def test_import_preserves_catalog_hash_and_never_imports_execution_material(self):
        catalog = [{
            "id": "sigma",
            "name": "Sigma",
            "description": "generic detection rules",
            "category": "blue-team-defensive",
            "tags": ["detection"],
            "install": {"method": "git"},
        }]
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "tools.json"
            output = Path(tmp) / "registry.json"
            source.write_text(json.dumps(catalog), encoding="utf-8")
            registry = import_catalog(source, output, source_commit="abc123")
            self.assertEqual(registry["schema"], REGISTRY_SCHEMA)
            self.assertTrue(registry["invariants"]["default_deny"])
            self.assertFalse(registry["invariants"]["execution_material_imported"])
            self.assertEqual(registry["source"]["commit"], "abc123")
            self.assertTrue(registry["source"]["catalog_sha256"].startswith("sha256:"))
            loaded = load_registry(output)
            entry = find_tool(loaded, "sigma")
            self.assertIsNotNone(entry)
            assert entry is not None
            self.assertFalse(entry["execution_material_imported"])

    def test_identity_osint_never_gets_fads_enforcement_authority(self):
        policy = classify_tool({
            "id": "people",
            "name": "People Search",
            "description": "public identity osint",
            "category": "people-identity",
            "tags": ["username"],
        })
        self.assertEqual(policy.capability_class, "PUBLIC_IDENTITY_OSINT")
        self.assertEqual(policy.fads_use, ())
        self.assertFalse(policy.autonomous_execution)


if __name__ == "__main__":
    unittest.main()
