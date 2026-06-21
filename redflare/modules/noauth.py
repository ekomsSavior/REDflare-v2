from __future__ import annotations

import json
import re
import time
from urllib.parse import urljoin

from redflare.core.models import Finding, ModuleResult, Target
from .base import Module, ModuleContext
from .http import request

PATHS = ("/", "/login", "/admin", "/dashboard", "/panel", "/console", "/manage", "/manager",
         "/status", "/api/status", "/health", "/metrics", "/config", "/config.json", "/api/config",
         "/graphql", "/swagger-ui.html", "/openapi.json", "/actuator/env", "/debug/vars", "/.env")
SENSITIVE = re.compile(r"(?:config|secret|credential|token|\.env|actuator|debug|metrics|console|admin|dashboard)", re.I)
AUTH = re.compile(r"(?:type=[\"']?password|/(?:login|signin|auth)(?:/|\?|$)|sign\s*in|log\s*in)", re.I)


class NativeNoAuthModule(Module):
    name = "authorization_surface"
    description = "Natively triage bounded in-scope web surfaces for missing authentication barriers"

    def run(self, target: Target, context: ModuleContext) -> ModuleResult:
        started = time.monotonic(); result = ModuleResult(self.name, target.url); hits = []
        for path in PATHS:
            url = urljoin(target.url.rstrip("/") + "/", path.lstrip("/"))
            try:
                response = request(url, context.timeout, max_body=200_000, allowed_origin=(target.host, target.port))
            except Exception:
                continue
            body = response.body.decode("utf-8", errors="replace")
            authenticated = response.status in {401, 403} or "www-authenticate" in response.headers or bool(AUTH.search(body))
            context.surface_graph.add_endpoint(target.url, response.url, method="GET", source=self.name,
                                               content_type=response.headers.get("content-type"), status=response.status,
                                               authentication="required" if authenticated else "not-observed")
            if response.status == 200 and not authenticated and (path != "/" or SENSITIVE.search(body)) and SENSITIVE.search(path + " " + body[:5000]):
                evidence = {"url": response.url, "path": path, "status": response.status,
                            "content_type": response.headers.get("content-type", ""), "authentication_barrier": "not observed"}
                hits.append(evidence)
                result.findings.append(Finding(context.run_id, target.url, self.name, "unauthenticated-service",
                    f"Potential unauthenticated surface at {path}", "high" if SENSITIVE.search(path) else "medium", .85,
                    "A bounded GET request reached a potentially sensitive interface without an observed authentication barrier.",
                    evidence, ["authorization", "native", "noauth"],
                    remediation="Require server-side authentication and authorization before returning sensitive interface content."))
                context.emit(target.url, self.name, "finding", f"Potential unauthenticated surface: {response.url}")
            if context.rate > 0: time.sleep(min(1.0 / context.rate, 1.0))
        result.observations = {"engine": "native-redflare", "paths_checked": len(PATHS), "candidate_surfaces": len(hits)}
        directory = context.artifact_dir / self.name / target.host; directory.mkdir(parents=True, exist_ok=True)
        artifact = directory / "findings.json"; artifact.write_text(json.dumps({"target": target.url, "findings": hits}, indent=2), encoding="utf-8")
        result.artifacts.append(str(artifact)); result.duration_seconds = round(time.monotonic() - started, 4); return result
