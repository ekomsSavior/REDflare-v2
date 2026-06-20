from __future__ import annotations

import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from redflare.core.models import Target
from redflare.core.runner import Runner
from redflare.core.storage import RunStore
from redflare.modules.base import ModuleContext
from redflare.modules.headers import HeaderModule
from redflare.modules.paths import PathDiscoveryModule


class FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/admin":
            body = b"admin dashboard"
            self.send_response(200)
        elif self.path == "/":
            body = b"fixture home"
            self.send_response(200)
        else:
            body = b"not found"
            self.send_response(404)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        return


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_web_pipeline_and_correlation(self):
        with tempfile.TemporaryDirectory() as directory:
            url = f"http://127.0.0.1:{self.server.server_port}"
            target = Target(url, "127.0.0.1", "http", self.server.server_port)
            store = RunStore(directory, "run_fixture")
            context = ModuleContext(store.run_id, store.artifacts, timeout=2, rate=0, max_paths=20)
            results, summary = Runner(
                store,
                [HeaderModule(), PathDiscoveryModule()],
                context,
                workers=2,
            ).run([target])
            categories = {
                finding.category for result in results for finding in result.findings
            }
            self.assertIn("security-headers", categories)
            self.assertIn("discovered-path", categories)
            self.assertIn("exposed-surface", categories)
            self.assertGreaterEqual(summary["findings"], 3)
            self.assertTrue((store.root / "report.html").exists())
            self.assertTrue((store.root / "summary.json").exists())
            self.assertTrue((store.root / "attack_surface.json").exists())
            self.assertTrue((store.root / "test_registry.json").exists())
            report = (store.root / "report.html").read_text(encoding="utf-8")
            self.assertIn("HTTP HEADERS ASSESSMENT", report)
            self.assertIn("PATH DISCOVERY ASSESSMENT", report)
            self.assertIn("missing_security_headers", report)


if __name__ == "__main__":
    unittest.main()
