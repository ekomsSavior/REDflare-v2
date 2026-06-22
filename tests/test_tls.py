from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from redflare.core.models import Target
from redflare.core.standards import enrich_finding
from redflare.modules.base import ModuleContext
from redflare.modules.tls import TLSAssessmentModule
from redflare.modules.http import HTTPResponse


class TLSAssessmentTests(unittest.TestCase):
    @patch("redflare.modules.http.request")
    def test_unverified_retry_is_pinned_to_the_recorded_origin(self, request):
        request.return_value = HTTPResponse("https://example.test/path", 200, {}, b"", tls_verified=False)
        with tempfile.TemporaryDirectory() as directory:
            context = ModuleContext("run", Path(directory)); context.allow_unverified_tls("example.test", 443)
            context.http_request("https://example.test/path", 2)
        self.assertEqual(request.call_args.kwargs["allowed_origin"], ("example.test", 443))

    @patch("redflare.modules.tls.assess_service")
    def test_records_trust_failure_and_enables_controlled_continuation(self, assess):
        assess.return_value = {
            "address": "127.0.0.1", "port": 443, "hostname": "example.test",
            "trust": {"verified": False, "verify_code": 18, "failure_kind": "self-signed", "message": "self-signed"},
            "certificate": {"subject": "CN=example.test", "issuer": "CN=example.test", "serial": "01", "sans": ["example.test"],
                            "sha256": "a" * 64, "self_signed": True, "hostname_match": True, "days_remaining": 60,
                            "key_algorithm": "RSA", "key_size": 2048, "signature_algorithm": "sha256"},
            "negotiated": {"version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "compression": None},
            "sni_behavior": {"accepted_without_sni": True, "same_certificate": True},
            "protocols": {"supported": ["TLSv1.2", "TLSv1.3"], "rejected": ["TLSv1.0", "TLSv1.1"], "errors": {}},
            "ciphers": {"supported": ["ECDHE-RSA-AES256-GCM-SHA384"], "weak": [], "tested": 1},
        }
        with tempfile.TemporaryDirectory() as directory:
            context = ModuleContext("run", Path(directory))
            target = Target("https://example.test", "example.test", "https", 443)
            context.surface_graph.add_network_host(target.url, "127.0.0.1")
            context.surface_graph.add_service(target.url, "127.0.0.1", {"port": 443, "protocol": "tcp", "service": "https", "tls": {}})
            result = TLSAssessmentModule().run(target, context)
            self.assertFalse(context.tls_verification_required(target.url))
        self.assertEqual(enrich_finding(result.findings[0]).test_id, "RFV2-TLS-001")
        self.assertEqual(result.observations["trust_failures"], 1)


if __name__ == "__main__": unittest.main()
