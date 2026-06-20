import tempfile
import unittest

from redflare.core.models import Finding
from redflare.core.storage import RunStore, deduplicate_findings


class StorageTests(unittest.TestCase):
    def test_run_folders_do_not_collide(self):
        with tempfile.TemporaryDirectory() as directory:
            first = RunStore(directory, "run_test")
            second = RunStore(directory, "run_test")
            self.assertNotEqual(first.root, second.root)
            self.assertTrue(first.root.is_dir())
            self.assertTrue(second.root.is_dir())

    def test_corroborated_header_findings_are_deduplicated(self):
        common = {
            "run_id": "run_test",
            "target": "https://example.test",
            "severity": "low",
            "confidence": 0.95,
            "description": "missing headers",
        }
        findings = [
            Finding(module="http_headers", category="security-headers", title="Missing headers", **common),
            Finding(module="gatekeeper", category="browser-security-headers", title="Browser missing headers", **common),
        ]
        deduplicated = deduplicate_findings(findings)
        self.assertEqual(len(deduplicated), 1)
        self.assertEqual(
            deduplicated[0].evidence["corroborated_by"],
            ["gatekeeper", "http_headers"],
        )


if __name__ == "__main__":
    unittest.main()
