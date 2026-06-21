from __future__ import annotations

import json
import tempfile
import threading
import unittest
from importlib.resources import files
from pathlib import Path
from urllib.request import urlopen

from redflare.visualize import VisualServer, build_visual_graph, resolve_run_directory


class VisualizeTests(unittest.TestCase):
    def make_run(self, directory: str) -> Path:
        root = Path(directory) / "run_visual"
        root.mkdir()
        (root / "summary.json").write_text(
            json.dumps({"run_id": "run_visual", "findings": 1}), encoding="utf-8"
        )
        (root / "attack_surface.json").write_text(
            json.dumps(
                {
                    "summary": {"targets": 1},
                    "targets": {
                        "https://example.test": {
                            "network_hosts": [{"address": "127.0.0.1", "roles": [{"role": "web-server", "confidence": 0.9}], "services": [{"port": 443, "protocol": "tcp", "service": "https", "product": "nginx", "version": "1.24.0"}]}],
                            "endpoints": [
                                {
                                    "url": "https://example.test/api/users",
                                    "methods": ["GET"],
                                    "parameters": [
                                        {"name": "id", "location": "query", "required": True}
                                    ],
                                    "sources": ["javascript-route"],
                                }
                            ],
                            "edges": [],
                            "documents": [
                                {"kind": "openapi", "title": "Fixture API", "url": "https://example.test/openapi.json"}
                            ],
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        finding = {
            "id": "finding123",
            "target": "https://example.test",
            "module": "sensitive_exposure",
            "category": "sensitive-data-exposure",
            "title": "Potential token exposed",
            "severity": "critical",
            "evidence": {
                "url": "https://example.test/api/users",
                "value_preview": "ghp_…7890",
            },
            "standards": {
                "CWE": [{"id": "CWE-798", "url": "https://cwe.mitre.org/data/definitions/798.html"}],
                "CVE": [{"id": "CVE-2026-12345", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-12345"}],
            },
        }
        (root / "findings.jsonl").write_text(json.dumps(finding) + "\n", encoding="utf-8")
        modules = root / "modules"
        modules.mkdir()
        (modules / "example__sensitive_exposure.json").write_text(
            json.dumps(
                {
                    "module": "sensitive_exposure",
                    "target": "https://example.test",
                    "status": "completed",
                    "findings": [finding],
                    "observations": {"responses_scanned": 2},
                    "artifacts": [],
                    "errors": [],
                    "duration_seconds": 0.1,
                }
            ),
            encoding="utf-8",
        )
        return root

    def test_normalizes_run_into_typed_graph(self):
        with tempfile.TemporaryDirectory() as directory:
            graph = build_visual_graph(self.make_run(directory))
            types = {node["type"] for node in graph["nodes"]}
            self.assertTrue({"run", "target", "network_host", "service", "technology", "endpoint", "parameter", "document", "module", "exposure", "standard", "cve"} <= types)
            relations = {edge["type"] for edge in graph["edges"]}
            self.assertTrue({"contains", "resolves_to", "exposes_service", "identified_as", "serves", "accepts", "executed", "reported", "exposes", "maps_to"} <= relations)
            self.assertEqual(graph["metadata"]["severity_counts"]["critical"], 1)

    def test_loopback_server_serves_ui_and_graph(self):
        with tempfile.TemporaryDirectory() as directory:
            server = VisualServer(self.make_run(directory), 0)
            thread = threading.Thread(target=server.httpd.serve_forever, daemon=True)
            thread.start()
            try:
                with urlopen(server.url, timeout=2) as response:
                    self.assertIn(b"Visual investigation console", response.read())
                    self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
                with urlopen(server.url + "api/graph", timeout=2) as response:
                    graph = json.loads(response.read())
                    self.assertEqual(graph["metadata"]["run_id"], "run_visual")
            finally:
                server.httpd.shutdown()
                server.httpd.server_close()
                thread.join(timeout=2)

    def test_rejects_non_run_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                build_visual_graph(directory)

    def test_accepts_local_file_url_for_run_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            run = self.make_run(directory)
            self.assertEqual(resolve_run_directory(run.as_uri()), run.resolve())
            self.assertEqual(build_visual_graph(run.as_uri())["metadata"]["run_id"], "run_visual")

    def test_visual_assets_keep_node_clicks_on_the_node(self):
        app = files("redflare.web").joinpath("app.js").read_text(encoding="utf-8")
        styles = files("redflare.web").joinpath("styles.css").read_text(encoding="utf-8")
        self.assertIn("group.setPointerCapture(event.pointerId)", app)
        self.assertIn("selectNode(node.id)", app)
        self.assertIn("centerOnNode(node)", app)
        self.assertIn('.graph-stage.dense .node[data-type="endpoint"] .node-label', styles)


if __name__ == "__main__":
    unittest.main()
