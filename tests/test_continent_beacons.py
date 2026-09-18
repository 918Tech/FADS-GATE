import os
import unittest
from unittest.mock import patch

from fads_gate.continent_beacons import CONTINENTS, current_beacon, validate_continent


class ContinentBeaconTests(unittest.TestCase):
    def test_all_seven_continents_are_defined(self):
        self.assertEqual(
            CONTINENTS,
            (
                "North America",
                "South America",
                "Europe",
                "Africa",
                "Asia",
                "Oceania",
                "Antarctica",
            ),
        )

    def test_in_continent_beacon_is_not_relay_hosted(self):
        with patch.dict(
            os.environ,
            {
                "FADS_BEACON_ID": "918-beacon-europe",
                "FADS_BEACON_CONTINENT": "Europe",
                "FADS_HOSTING_CONTINENT": "Europe",
                "FADS_NODE_REGION": "frankfurt",
            },
            clear=False,
        ):
            beacon = current_beacon()
        self.assertFalse(beacon.relay_hosted)
        self.assertEqual(beacon.logical_continent, "Europe")

    def test_cross_continent_beacon_is_explicitly_relay_hosted(self):
        with patch.dict(
            os.environ,
            {
                "FADS_BEACON_ID": "918-beacon-africa",
                "FADS_BEACON_CONTINENT": "Africa",
                "FADS_HOSTING_CONTINENT": "Europe",
                "FADS_NODE_REGION": "frankfurt",
            },
            clear=False,
        ):
            beacon = current_beacon()
        self.assertTrue(beacon.relay_hosted)
        self.assertEqual(beacon.logical_continent, "Africa")
        self.assertEqual(beacon.hosting_continent, "Europe")

    def test_unknown_continent_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_continent("Atlantis")


if __name__ == "__main__":
    unittest.main()
