import os
import unittest
from unittest.mock import patch

from fads_gate.public_threat_arrays import (
    enrich_observables,
    greynoise_community_lookup,
    threatfox_lookup,
)


class PublicThreatArrayTests(unittest.TestCase):
    def test_greynoise_malicious_ip_is_flagged(self):
        payload = {
            "ip": "8.8.8.8",
            "noise": True,
            "riot": False,
            "classification": "malicious",
            "name": "example-scanner",
            "link": "https://viz.greynoise.io/ip/8.8.8.8",
            "message": "Success",
        }
        with patch("fads_gate.public_threat_arrays._json_request", return_value=payload):
            finding = greynoise_community_lookup("8.8.8.8")
        self.assertIsNotNone(finding)
        self.assertTrue(finding.malicious_infrastructure)
        self.assertEqual(finding.classification, "malicious")
        self.assertIn("internet-noise", finding.cluster_labels)

    def test_greynoise_riot_is_not_malicious(self):
        payload = {
            "ip": "1.1.1.1",
            "noise": False,
            "riot": True,
            "classification": "benign",
            "name": "known-service",
            "link": "https://viz.greynoise.io/riot/1.1.1.1",
            "message": "Success",
        }
        with patch("fads_gate.public_threat_arrays._json_request", return_value=payload):
            finding = greynoise_community_lookup("1.1.1.1")
        self.assertIsNotNone(finding)
        self.assertFalse(finding.malicious_infrastructure)
        self.assertIn("known-benign-service", finding.cluster_labels)

    def test_threatfox_exact_ioc_becomes_cluster_finding(self):
        response = {
            "query_status": "ok",
            "data": [
                {
                    "ioc": "8.8.8.8:443",
                    "ioc_type": "ip:port",
                    "threat_type": "botnet_cc",
                    "threat_type_desc": "Botnet C2",
                    "malware_printable": "ExampleMalware",
                    "tags": ["c2", "loader"],
                    "confidence_level": 90,
                    "first_seen": "2026-09-01 00:00:00",
                    "last_seen": "2026-09-18 00:00:00",
                    "is_compromised": False,
                    "reference": "https://example.invalid/report",
                }
            ],
        }
        with patch.dict(os.environ, {"THREATFOX_AUTH_KEY": "x" * 32}, clear=False):
            with patch("fads_gate.public_threat_arrays._json_request", return_value=response):
                findings = threatfox_lookup("8.8.8.8")
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].malicious_infrastructure)
        self.assertIn("ExampleMalware", findings[0].cluster_labels)
        self.assertEqual(findings[0].confidence, 90)

    def test_missing_threatfox_key_is_nonfatal(self):
        with patch.dict(os.environ, {"THREATFOX_AUTH_KEY": ""}, clear=False):
            self.assertEqual(threatfox_lookup("8.8.8.8"), ())

    def test_enrichment_never_claims_person_identity(self):
        with patch("fads_gate.public_threat_arrays.greynoise_community_lookup", return_value=None):
            with patch("fads_gate.public_threat_arrays.threatfox_lookup", return_value=()):
                result = enrich_observables(ips=["8.8.8.8"])
        self.assertFalse(result["personal_identity_inference"])
        self.assertFalse(result["physical_person_tracking"])
        self.assertEqual(result["threat_clusters"], [])

    def test_duplicate_malicious_infrastructure_is_deduplicated(self):
        from fads_gate.public_threat_arrays import ThreatArrayFinding
        finding = ThreatArrayFinding(
            source="test",
            observable="8.8.8.8",
            observable_type="ip",
            classification="malicious",
            confidence=80,
            cluster_labels=("cluster-a",),
            malicious_infrastructure=True,
            reference=None,
            evidence={},
        )
        with patch("fads_gate.public_threat_arrays.greynoise_community_lookup", return_value=finding):
            with patch("fads_gate.public_threat_arrays.threatfox_lookup", return_value=(finding,)):
                result = enrich_observables(ips=["8.8.8.8"])
        self.assertEqual(result["malicious_infrastructure"], ["8.8.8.8"])
        self.assertIn("cluster-a", result["threat_clusters"])


if __name__ == "__main__":
    unittest.main()
