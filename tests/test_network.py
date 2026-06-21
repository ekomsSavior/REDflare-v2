from __future__ import annotations

import tempfile
import threading
import unittest
import asyncio
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from redflare.core.models import Target
from redflare.modules.base import ModuleContext
from redflare.modules.network import NetworkDiscoveryModule, PORT_SERVICE, close_writer, infer_roles, parse_ports


class Handler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200); self.send_header("Server", "nginx/1.24.0"); self.end_headers()
    def log_message(self, *_): pass


class NetworkDiscoveryTests(unittest.TestCase):
    def test_tls_close_noise_is_non_fatal(self):
        class Writer:
            def close(self): pass
            async def wait_closed(self): raise ssl.SSLError("APPLICATION_DATA_AFTER_CLOSE_NOTIFY")
        asyncio.run(close_writer(Writer()))
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True); cls.thread.start()

    @classmethod
    def tearDownClass(cls): cls.server.shutdown(); cls.server.server_close(); cls.thread.join(timeout=2)

    def test_parses_ports_and_ranges(self): self.assertEqual(parse_ports("22,80,443-445"), (22,80,443,444,445))

    def test_infers_domain_controller_only_from_correlated_services(self):
        roles = infer_roles([{"port": value} for value in (53,88,389,445)])
        self.assertEqual(roles[0]["role"], "probable-domain-controller")

    def test_scans_local_service_and_populates_shared_graph(self):
        port=self.server.server_port; PORT_SERVICE[port]="http"
        try:
            with tempfile.TemporaryDirectory() as directory:
                context=ModuleContext("run",Path(directory),network_addresses=("127.0.0.1",),network_ports=(port,),network_timeout=1)
                target=Target(f"http://127.0.0.1:{port}","127.0.0.1","http",port)
                result=NetworkDiscoveryModule().run(target,context); snapshot=context.surface_graph.snapshot()
            self.assertEqual(result.observations["open_services"],1)
            service=snapshot["targets"][target.url]["network_hosts"][0]["services"][0]
            self.assertEqual(service["product"],"nginx"); self.assertEqual(service["version"],"1.24.0")
        finally: PORT_SERVICE.pop(port,None)


if __name__ == "__main__": unittest.main()
