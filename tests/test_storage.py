import tempfile
import unittest

from redflare.core.models import Finding
from redflare.core.models import Target
from redflare.core.storage import RunStore, deduplicate_findings, target_run_id


class StorageTests(unittest.TestCase):
    def test_target_run_name_is_human_readable(self):
        value = target_run_id([Target("https://example.test", "example.test", "https", 443)])
        self.assertRegex(value, r"^scan_example\.test_\d{8}_\d{6}$")

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
