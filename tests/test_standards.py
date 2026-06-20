import unittest

from redflare.core.models import Finding
from redflare.core.standards import TEST_REGISTRY, enrich_finding


class StandardsTests(unittest.TestCase):
    def test_registry_ids_are_unique_and_versioned(self):
        ids = [item.id for item in TEST_REGISTRY]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(item.wstg and item.asvs and item.cwe and item.api_security for item in TEST_REGISTRY))
        self.assertTrue(all(ref.startswith("WSTG-") for item in TEST_REGISTRY for ref in item.wstg))
        self.assertTrue(all(ref.startswith("v5.0.0-") for item in TEST_REGISTRY for ref in item.asvs))

    def test_enriches_known_finding(self):
        finding = Finding("run", "https://example.test", "http_headers", "security-headers", "Missing", "low", 1.0, "desc")
        enrich_finding(finding)
        self.assertEqual(finding.test_id, "RFV2-CONF-001")
        self.assertIn("OWASP_ASVS", finding.standards)
        self.assertEqual(finding.standards["OWASP_WSTG"][0]["version"], "4.2")


if __name__ == "__main__":
    unittest.main()
