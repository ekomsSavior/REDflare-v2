from __future__ import annotations

import json
import io
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from redflare.core.models import Target
from redflare.core.standards import enrich_finding
from redflare.core.storage import RunStore
from redflare.modules.base import ModuleContext
from redflare.modules.exposure import SensitiveExposureModule
from redflare.ui import LiveConsole


FAKE_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
FAKE_HASH = "$2b$12$" + "A" * 53


class ExposureFixture(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            body = b'<html><script src="/app.js"></script></html>'
            content_type = "text/html"
            status = 200
        elif self.path == "/app.js":
            body = (
                f'const api_key = "{FAKE_TOKEN}";\n'
                f'const password_hash = "{FAKE_HASH}";\n'
                'const backend = "10.20.30.40";\n'
            ).encode()
            content_type = "application/javascript"
            status = 200
        else:
            body = b"not found"
            content_type = "text/plain"
            status = 404
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        return


class ExposureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), ExposureFixture)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_detects_and_redacts_sensitive_values(self):
        text = f'api_key="{FAKE_TOKEN}"; password_hash="{FAKE_HASH}"; host="10.20.30.40"'
        matches = SensitiveExposureModule.detect(text, "https://example.test/app.js")
        types = {item["type"] for item in matches}
        self.assertIn("GitHub token", types)
        self.assertIn("bcrypt password hash", types)
        self.assertIn("private/internal IP address", types)
        serialized = json.dumps(matches)
        self.assertNotIn(FAKE_TOKEN, serialized)
        self.assertNotIn(FAKE_HASH, serialized)
        self.assertIn("10.20.30.40", serialized)

    def test_detects_labeled_public_ip_without_flagging_documentation_ip(self):
        matches = SensitiveExposureModule.detect(
            'client_ip="8.8.8.8"; client_ip="192.0.2.10"',
            "https://example.test/profile",
        )
        previews = {item["value_preview"] for item in matches}
        self.assertIn("8.8.8.8", previews)
        self.assertNotIn("192.0.2.10", previews)

    def test_scans_graph_endpoints_and_writes_masked_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            url = f"http://127.0.0.1:{self.server.server_port}"
            target = Target(url, "127.0.0.1", "http", self.server.server_port)
            messages = []
            context = ModuleContext(
                "exposure-test",
                Path(directory),
                timeout=2,
                reporter=lambda *items: messages.append(items),
            )
            context.surface_graph.add_endpoint(
                target.url, f"{url}/app.js", method="GET", source="test"
            )
            result = SensitiveExposureModule().run(target, context)
            for finding in result.findings:
                enrich_finding(finding)
            self.assertGreaterEqual(len(result.findings), 3)
            self.assertTrue(any(item[2] == "finding" for item in messages))
            self.assertTrue(all(item.test_id == "RFV2-DATA-001" for item in result.findings))
            artifact = Path(result.artifacts[0])
            self.assertTrue(artifact.exists())
            saved = artifact.read_text(encoding="utf-8")
            self.assertNotIn(FAKE_TOKEN, saved)
            self.assertNotIn(FAKE_HASH, saved)
            self.assertIn("10.20.30.40", saved)

            store = RunStore(directory, "report-test")
            store.write_result(result)
            summary = store.finalize([result], surface_graph=context.surface_graph.snapshot())
            self.assertEqual(summary["sensitive_exposures"], len(result.findings))
            report = (store.root / "report.html").read_text(encoding="utf-8")
            jsonl = (store.root / "findings.jsonl").read_text(encoding="utf-8")
            self.assertIn("RFV2-DATA-001", report)
            self.assertIn("10.20.30.40", report)
            self.assertNotIn(FAKE_TOKEN, report + jsonl)
            terminal = io.StringIO()
            LiveConsole(stream=terminal).final_report(summary, [result], store.root)
            terminal_output = terminal.getvalue()
            self.assertIn("RFV2-DATA-001", terminal_output)
            self.assertIn("10.20.30.40", terminal_output)
            self.assertNotIn(FAKE_TOKEN, terminal_output)


if __name__ == "__main__":
    unittest.main()
