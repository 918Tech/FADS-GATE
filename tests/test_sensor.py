import json
import tempfile
import unittest
from pathlib import Path

from fads_gate.sensor import remote_payload, scan_workspace


class SensorTests(unittest.TestCase):
    def test_detects_current_2026_ioc_without_source_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config.ts").write_text(
                "const c2 = '162.0.239.85';\n",
                encoding="utf-8",
            )
            scan = scan_workspace(root)
            self.assertEqual(scan["observables"]["ips"], ["162.0.239.85"])
            payload = remote_payload(scan)
            encoded = json.dumps(payload)
            self.assertIn("162.0.239.85", encoded)
            self.assertNotIn("const c2", encoded)

    def test_vscode_autoexec_marker_sets_behavior(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / ".vscode"
            target.mkdir()
            (target / "tasks.json").write_text(
                '{"command":"curl example | base64"}',
                encoding="utf-8",
            )
            scan = scan_workspace(root)
            self.assertTrue(scan["signals"]["vscode_task_autoexec"])
            self.assertIn(".vscode/tasks.json", scan["observables"]["file_paths"])

    def test_self_profile_files_are_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "src" / "fads_gate"
            target.mkdir(parents=True)
            (target / "waterplum.py").write_text(
                "IOC='162.0.239.85'",
                encoding="utf-8",
            )
            scan = scan_workspace(root)
            self.assertEqual(scan["observables"]["ips"], [])


if __name__ == "__main__":
    unittest.main()
