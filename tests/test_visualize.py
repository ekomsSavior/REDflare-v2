from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.request import urlopen

from redflare.visualize import VisualServer, build_visual_graph


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
                "CWE": [{"id": "CWE-798", "url": "https://cwe.mitre.org/data/definitions/798.html"}]
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
            self.assertTrue({"run", "target", "endpoint", "parameter", "document", "module", "exposure", "standard"} <= types)
            relations = {edge["type"] for edge in graph["edges"]}
            self.assertTrue({"contains", "serves", "accepts", "executed", "reported", "exposes", "maps_to"} <= relations)
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


if __name__ == "__main__":
    unittest.main()
