import unittest
from unittest.mock import patch

from fads_gate import watchdog


class WatchdogTests(unittest.TestCase):
    def test_all_targets_healthy_passes(self):
        with patch(
            "fads_gate.watchdog._targets",
            return_value=(("a", "https://a.invalid/healthz"), ("b", "https://b.invalid/healthz")),
        ):
            with patch(
                "fads_gate.watchdog._probe",
                side_effect=[
                    {"name": "a", "ok": True, "build_commit": "abc"},
                    {"name": "b", "ok": True, "build_commit": "abc"},
                ],
            ):
                self.assertEqual(watchdog.main(), 0)

    def test_version_skew_fails(self):
        with patch(
            "fads_gate.watchdog._targets",
            return_value=(("a", "https://a.invalid/healthz"), ("b", "https://b.invalid/healthz")),
        ):
            with patch(
                "fads_gate.watchdog._probe",
                side_effect=[
                    {"name": "a", "ok": True, "build_commit": "abc"},
                    {"name": "b", "ok": True, "build_commit": "def"},
                ],
            ):
                self.assertEqual(watchdog.main(), 2)

    def test_any_unhealthy_target_fails(self):
        with patch(
            "fads_gate.watchdog._targets",
            return_value=(("a", "https://a.invalid/healthz"), ("b", "https://b.invalid/healthz")),
        ):
            with patch(
                "fads_gate.watchdog._probe",
                side_effect=[
                    {"name": "a", "ok": True, "build_commit": "abc"},
                    {"name": "b", "ok": False, "build_commit": "abc"},
                ],
            ):
                self.assertEqual(watchdog.main(), 2)


if __name__ == "__main__":
    unittest.main()
