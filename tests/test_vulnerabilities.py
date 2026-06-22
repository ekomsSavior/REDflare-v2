from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
import io
import urllib.error

from redflare.core.models import Target
from redflare.core.standards import enrich_finding
from redflare.modules.base import ModuleContext
from redflare.modules.http import HTTPResponse
from redflare.modules.vulnerabilities import CVEIntelligenceModule, Fingerprint, fingerprint_response, query_nvd


class CVEIntelligenceTests(unittest.TestCase):
    @patch("redflare.modules.vulnerabilities.time.sleep")
    @patch("redflare.modules.vulnerabilities.urllib.request.urlopen")
    def test_nvd_retries_503_and_honors_successful_retry(self, open_url, _sleep):
        error = urllib.error.HTTPError("https://nvd.test", 503, "busy", {"Retry-After": "0"}, None)
        response = Mock(); response.__enter__ = Mock(return_value=io.StringIO('{"vulnerabilities": []}'))
        response.__exit__ = Mock(return_value=False)
        open_url.side_effect = [error, response]
        fingerprint = Fingerprint("nginx", "1.24.0", "f5", "nginx", "header", "fixture")
        self.assertEqual(query_nvd(fingerprint, 1, 10, api_key="fixture", retries=2), [])
        self.assertEqual(open_url.call_count, 2)

    @patch("redflare.modules.vulnerabilities.query_nvd", side_effect=RuntimeError("NVD unavailable"))
    @patch("redflare.modules.http.request")
    def test_reports_unavailable_coverage_without_claiming_zero_cves(self, get, _nvd):
        get.return_value = HTTPResponse("https://example.test", 200, {"server": "nginx/1.24.0"}, b"")
        with tempfile.TemporaryDirectory() as directory:
            context = ModuleContext("run_test", Path(directory), timeout=1)
            result = CVEIntelligenceModule().run(Target("https://example.test", "example.test", "https", 443), context)
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.observations["coverage_status"], "unavailable")
        self.assertEqual(result.observations["coverage"][0]["status"], "unavailable")
        self.assertTrue(result.errors)
    def test_fingerprints_only_explicit_versions(self):
        body = b'<meta name="generator" content="WordPress 6.4.2"><script src="jquery-3.6.0.min.js"></script>'
        values = fingerprint_response({"server": "nginx/1.24.0", "x-powered-by": "Express"}, body)
        products = {(item.product, item.version) for item in values}
        self.assertEqual(products, {("nginx", "1.24.0"), ("WordPress", "6.4.2"), ("jQuery", "3.6.0")})
        self.assertNotIn("Express", {item.product for item in values})

    @patch("redflare.modules.vulnerabilities.query_nvd")
    @patch("redflare.modules.http.request")
    def test_emits_cve_findings_with_clickable_reference(self, get, nvd):
        get.return_value = HTTPResponse("https://example.test", 200, {"server": "nginx/1.24.0"}, b"")
        nvd.return_value = [{
            "id": "CVE-2026-12345",
            "published": "2026-01-02T00:00:00Z",
            "lastModified": "2026-01-03T00:00:00Z",
            "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": "Fixture vulnerability."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N"}}]},
            "references": [{"url": "https://vendor.example/advisory"}],
        }]
        with tempfile.TemporaryDirectory() as directory:
            context = ModuleContext("run_test", Path(directory), timeout=1)
            result = CVEIntelligenceModule().run(Target("https://example.test", "example.test", "https", 443), context)
        self.assertEqual(len(result.findings), 1)
        finding = enrich_finding(result.findings[0])
        self.assertEqual(finding.test_id, "RFV2-COMP-001")
        self.assertEqual(finding.severity, "critical")
        self.assertEqual(finding.standards["CVE"][0]["id"], "CVE-2026-12345")
        self.assertTrue(finding.standards["CVE"][0]["url"].startswith("https://nvd.nist.gov/"))


if __name__ == "__main__":
    unittest.main()
