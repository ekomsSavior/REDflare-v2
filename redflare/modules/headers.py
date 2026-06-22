from __future__ import annotations

import time

from redflare.core.models import Finding, ModuleResult, Target
from .base import Module, ModuleContext
from .http import request


SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "Content Security Policy",
    "x-content-type-options": "MIME sniffing protection",
    "referrer-policy": "Referrer Policy",
    "permissions-policy": "Permissions Policy",
}


class HeaderModule(Module):
    name = "http_headers"
    description = "Inspect HTTP status, redirects, server metadata, and security headers"

    def run(self, target: Target, context: ModuleContext) -> ModuleResult:
        started = time.monotonic()
        result = ModuleResult(self.name, target.url)
        try:
            context.emit(target.url, self.name, "progress", f"Requesting {target.url}")
            response = context.http_request(target.url, context.timeout, method="GET", max_body=200_000)
            missing = [header for header in SECURITY_HEADERS if header not in response.headers]
            result.observations.update(
                {
                    "status": response.status,
                    "final_url": response.url,
                    "headers": response.headers,
                    "body_bytes_sampled": len(response.body),
                    "missing_security_headers": missing,
                }
            )
            context.emit(
                target.url,
                self.name,
                "info",
                f"HTTP {response.status}; final={response.url}; sampled={len(response.body)} bytes",
            )
            if missing:
                result.findings.append(
                    Finding(
                        context.run_id,
                        target.url,
                        self.name,
                        "security-headers",
                        "Common security headers are missing",
                        "low",
                        0.95,
                        "The response omitted: " + ", ".join(missing),
                        {"status": response.status, "missing": missing},
                        ["headers", "hardening"],
                    )
                )
        except Exception as exc:
            result.status = "error"
            result.errors.append(f"{type(exc).__name__}: {exc}")
        result.duration_seconds = round(time.monotonic() - started, 4)
        return result
