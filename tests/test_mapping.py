from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from redflare.core.models import Target
from redflare.modules.base import ModuleContext
from redflare.modules.mapping import ApplicationMappingModule


class MappingFixture(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            body = b'''<html><a href="/account?tab=profile">Account</a>
                <form action="/login" method="post"><input name="username"><input name="password" type="password"></form>
                <script src="/app.js"></script></html>'''
            content_type = "text/html"
            status = 200
        elif self.path == "/app.js":
            body = b'fetch("/api/session"); axios.post("/api/messages", {});'
            content_type = "application/javascript"
            status = 200
        elif self.path == "/openapi.json":
            body = json.dumps(
                {
                    "openapi": "3.0.3",
                    "info": {"title": "Fixture API"},
                    "paths": {
                        "/api/users/{id}": {
                            "get": {
                                "parameters": [
                                    {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
                                ],
                                "security": [{"bearerAuth": []}],
                            }
                        },
                        "/api/users": {
                            "post": {
                                "requestBody": {
                                    "required": True,
                                    "content": {
                                        "application/json": {
                                            "schema": {
                                                "type": "object",
                                                "required": ["email"],
                                                "properties": {"email": {"type": "string"}},
                                            }
                                        }
                                    },
                                }
                            }
                        },
                    },
                }
            ).encode()
            content_type = "application/json"
            status = 200
        elif self.path.startswith("/account"):
            body = b"<html>account</html>"
            content_type = "text/html"
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

    def do_POST(self):
        if self.path != "/graphql":
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps(
            {
                "data": {
                    "__schema": {
                        "queryType": {"name": "Query"},
                        "mutationType": {"name": "Mutation"},
                        "types": [
                            {"name": "Query", "kind": "OBJECT", "fields": [{"name": "viewer", "args": []}]},
                            {"name": "Mutation", "kind": "OBJECT", "fields": [{"name": "updateProfile", "args": []}]},
                        ],
                    }
                }
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        return


class MappingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), MappingFixture)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_builds_graph_from_html_javascript_and_openapi(self):
        url = f"http://127.0.0.1:{self.server.server_port}"
        target = Target(url, "127.0.0.1", "http", self.server.server_port)
        context = ModuleContext(
            "mapping-test",
            Path("/tmp"),
            timeout=2,
            max_crawl_pages=4,
            max_crawl_depth=1,
            graphql_introspection=True,
        )
        result = ApplicationMappingModule().run(target, context)
        self.assertEqual(result.status, "completed")
        endpoints = context.surface_graph.snapshot()["targets"][url]["endpoints"]
        by_url = {item["url"]: item for item in endpoints}
        self.assertIn(f"{url}/login", by_url)
        self.assertIn(f"{url}/api/session", by_url)
        self.assertIn(f"{url}/api/messages", by_url)
        self.assertIn(f"{url}/api/users/{{id}}", by_url)
        self.assertIn("bearerAuth", by_url[f"{url}/api/users/{{id}}"]["authentication"])
        body_parameters = by_url[f"{url}/api/users"]["parameters"]
        self.assertIn("email", {item["name"] for item in body_parameters})
        self.assertEqual(
            by_url[f"{url}/graphql"]["metadata"]["graphql_operations"],
            ["updateProfile", "viewer"],
        )


if __name__ == "__main__":
    unittest.main()
