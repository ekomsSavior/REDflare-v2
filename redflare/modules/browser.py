from __future__ import annotations

import asyncio
import json
import time
from urllib.parse import urlsplit

from redflare.core.models import Finding, ModuleResult, Target
from .base import Module, ModuleContext
from .headers import SECURITY_HEADERS
from .http import request

INTERESTING = ("api", "graphql", "admin", "auth", "token", "upload", "config", "internal")


class NativeBrowserRuntimeModule(Module):
    name = "browser_runtime"
    description = "Natively capture browser/runtime requests, responses, redirects, console events, and application endpoints"

    def run(self, target: Target, context: ModuleContext) -> ModuleResult:
        started = time.monotonic(); result = ModuleResult(self.name, target.url)
        try:
            capture = asyncio.run(self._capture(target, context))
        except Exception as exc:
            capture = self._fallback(target, context, f"{type(exc).__name__}: {exc}")
        requests_seen = capture.get("requests", []); responses = capture.get("responses", [])
        for item in requests_seen:
            url = str(item.get("url") or ""); parsed = urlsplit(url)
            if parsed.hostname == target.host:
                context.surface_graph.add_endpoint(target.url, url, method=str(item.get("method") or "GET"), source=self.name,
                                                   authentication="observed" if item.get("authentication") else None)
        headers = {k.lower(): v for k, v in (capture.get("main_headers") or {}).items()}
        missing = [name for name in SECURITY_HEADERS if name not in headers]
        if missing:
            result.findings.append(Finding(context.run_id, target.url, self.name, "browser-security-headers",
                "Browser-runtime response headers need hardening", "low", .95,
                "Native runtime capture confirmed missing common security headers.", {"missing": missing}, ["browser", "headers", "native"]))
        interesting = [item for item in requests_seen if any(term in str(item.get("url", "")).lower() for term in INTERESTING)]
        if interesting:
            result.findings.append(Finding(context.run_id, target.url, self.name, "browser-endpoints",
                "Interesting endpoints observed during browser execution", "info", .8,
                "Native runtime capture observed assessment-relevant endpoints.", {"endpoints": interesting[:50]}, ["browser", "endpoints", "native"]))
        result.observations = {"engine": capture.get("engine"), "requests": len(requests_seen), "responses": len(responses),
                               "console_events": len(capture.get("console", [])), "final_url": capture.get("final_url"),
                               "fallback_reason": capture.get("fallback_reason")}
        directory = context.artifact_dir / self.name / target.host; directory.mkdir(parents=True, exist_ok=True)
        artifact = directory / "network_capture.json"; artifact.write_text(json.dumps(capture, indent=2), encoding="utf-8")
        result.artifacts.append(str(artifact)); result.duration_seconds = round(time.monotonic() - started, 4); return result

    async def _capture(self, target: Target, context: ModuleContext) -> dict:
        from playwright.async_api import async_playwright
        captured = {"engine": "native-playwright", "target": target.url, "requests": [], "responses": [], "console": [], "main_headers": {}}
        async with async_playwright() as runtime:
            browser = await runtime.chromium.launch(headless=True)
            browser_context = await browser.new_context(ignore_https_errors=True)
            page = await browser_context.new_page()
            page.on("request", lambda req: captured["requests"].append({"url": req.url, "method": req.method, "resource_type": req.resource_type}))
            page.on("response", lambda res: captured["responses"].append({"url": res.url, "status": res.status}))
            page.on("console", lambda msg: captured["console"].append({"type": msg.type, "text": msg.text[:500]}))
            response = await page.goto(target.url, wait_until="domcontentloaded", timeout=int(max(5, context.timeout) * 1000))
            if response: captured["main_headers"] = await response.all_headers()
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await page.wait_for_timeout(1500)
            captured["final_url"] = page.url; captured["title"] = await page.title()
            await page.screenshot(path=str(context.artifact_dir / f"{target.host}_runtime.png"), full_page=True)
            await browser.close()
        return captured

    @staticmethod
    def _fallback(target: Target, context: ModuleContext, reason: str) -> dict:
        response = context.http_request(target.url, context.timeout, max_body=500_000)
        urls = context.surface_graph.request_urls(target.url)
        return {"engine": "native-http-fallback", "fallback_reason": reason, "target": target.url,
                "final_url": response.url, "main_headers": response.headers,
                "requests": [{"url": url, "method": "GET", "resource_type": "mapped"} for url in urls] or [{"url": response.url, "method": "GET", "resource_type": "document"}],
                "responses": [{"url": response.url, "status": response.status}], "console": []}
