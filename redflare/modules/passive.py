from __future__ import annotations

import socket
import ssl
import time

from redflare.core.models import ModuleResult, Target
from .base import Module, ModuleContext


class PassiveReconModule(Module):
    name = "passive_recon"
    description = "Resolve DNS and collect TLS certificate metadata"

    def run(self, target: Target, context: ModuleContext) -> ModuleResult:
        started = time.monotonic()
        result = ModuleResult(self.name, target.url)
        try:
            context.emit(target.url, self.name, "progress", f"Resolving {target.host}")
            addresses = sorted({item[4][0] for item in socket.getaddrinfo(target.host, target.port)})
            result.observations["addresses"] = addresses
            context.emit(target.url, self.name, "info", f"Resolved addresses: {', '.join(addresses)}")
            if target.scheme == "https":
                context.emit(target.url, self.name, "progress", f"Negotiating TLS on port {target.port}")
                verified = context.tls_verification_required(target.url)
                tls_context = ssl.create_default_context() if verified else ssl._create_unverified_context()
                with socket.create_connection((target.host, target.port), timeout=context.timeout) as raw:
                    with tls_context.wrap_socket(raw, server_hostname=target.host) as wrapped:
                        cert = wrapped.getpeercert()
                if not verified:
                    graph = context.surface_graph.snapshot().get("targets", {}).get(target.url, {})
                    assessed = next((service.get("tls_assessment", {}).get("certificate", {})
                                     for host in graph.get("network_hosts", []) for service in host.get("services", [])
                                     if int(service.get("port", 0)) == target.port and service.get("tls_assessment")), {})
                    cert = {"subject": assessed.get("subject"), "issuer": assessed.get("issuer"),
                            "notBefore": assessed.get("not_before"), "notAfter": assessed.get("not_after"),
                            "subjectAltName": [("DNS", value) for value in assessed.get("sans", [])]}
                result.observations["tls"] = {
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "san": [value for key, value in cert.get("subjectAltName", []) if key == "DNS"],
                    "trust_validation": "verified" if verified else "continued-after-recorded-trust-failure",
                }
                context.emit(
                    target.url,
                    self.name,
                    "info",
                    f"TLS certificate expires {cert.get('notAfter', 'unknown')}",
                )
        except Exception as exc:
            result.status = "error"
            result.errors.append(f"{type(exc).__name__}: {exc}")
        result.duration_seconds = round(time.monotonic() - started, 4)
        return result
