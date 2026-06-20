from __future__ import annotations

import importlib.util
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

from redflare.core.models import Finding, ModuleResult, Target
from .base import Module, ModuleContext


SOURCES_ROOT = Path(__file__).resolve().parents[3]
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


class CommandAdapter(Module):
    script: Path

    def available(self) -> bool:
        return self.script.exists()

    def command(self, target: Target, context: ModuleContext, output: Path) -> list[str]:
        raise NotImplementedError

    def live_line(self, line: str) -> tuple[str, str] | None:
        if not line or set(line) <= {"=", "-", " ", "_"}:
            return None
        return "progress", line

    def parse_output(
        self, target: Target, context: ModuleContext, output: Path, result: ModuleResult
    ) -> None:
        return

    def run(self, target: Target, context: ModuleContext) -> ModuleResult:
        started = time.monotonic()
        result = ModuleResult(self.name, target.url)
        output = context.artifact_dir / self.name / target.host
        output.mkdir(parents=True, exist_ok=True)
        if not self.available():
            result.status = "skipped"
            result.errors.append(f"source tool not found: {self.script}")
            return result
        command = self.command(target, context, output)
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            lines: list[str] = []
            messages: queue.Queue[str | None] = queue.Queue()

            def read_output():
                assert process.stdout is not None
                for line in process.stdout:
                    messages.put(line.rstrip())
                messages.put(None)

            threading.Thread(target=read_output, daemon=True).start()
            deadline = time.monotonic() + max(60, int(context.timeout * 20))
            reader_done = False
            while not reader_done or process.poll() is None:
                if time.monotonic() > deadline:
                    process.kill()
                    result.errors.append("adapter timed out and was terminated")
                    break
                try:
                    line = messages.get(timeout=0.2)
                except queue.Empty:
                    continue
                if line is None:
                    reader_done = True
                elif line:
                    clean = ANSI_ESCAPE.sub("", line)
                    lines.append(clean)
                    live = self.live_line(clean)
                    if live:
                        context.emit(target.url, self.name, live[0], live[1])
            exit_code = process.wait(timeout=5)
            log_file = output / "console.log"
            log_file.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
            result.artifacts.append(str(log_file))
            result.observations["command"] = command
            result.observations["exit_code"] = exit_code
            if exit_code != 0:
                result.status = "error"
                result.errors.append(f"adapter exited with status {exit_code}")
            else:
                self.parse_output(target, context, output, result)
        except Exception as exc:
            result.status = "error"
            result.errors.append(f"{type(exc).__name__}: {exc}")
        result.duration_seconds = round(time.monotonic() - started, 4)
        return result


class GatekeeperAdapter(CommandAdapter):
    name = "gatekeeper"
    description = "Run browser interaction and network capture through GATEkeeper"
    script = SOURCES_ROOT / "GATEkeeper" / "gatekeeper.py"

    def live_line(self, line: str) -> tuple[str, str] | None:
        keep = (
            "Starting browser",
            "Running lightweight target recon",
            "Navigating to",
            "Waiting for selector",
            "Starting interaction simulation",
            "URL changed",
            "[req]",
            "[res]",
            "[fail]",
            "[console]",
            "navigation error",
            "load timeout",
            "interaction loop error",
        )
        if any(token.lower() in line.lower() for token in keep):
            kind = "error" if "error" in line.lower() or "[fail]" in line else "progress"
            message = line.strip()
            if not any(marker in message for marker in ("[req]", "[res]", "[fail]", "[console]")):
                message = message.lstrip("[*+]! ")
            return kind, message
        return None

    def parse_output(self, target, context, output, result):
        report = output / "report.json"
        if not report.exists():
            return
        data = json.loads(report.read_text(encoding="utf-8"))
        result.observations["report"] = data
        browser_endpoints = ingest_browser_traffic(target, context, data)
        result.artifacts.append(str(report))
        capture = output / "network_capture.json"
        if capture.exists():
            capture_data = json.loads(capture.read_text(encoding="utf-8"))
            browser_endpoints = ingest_browser_traffic(target, context, capture_data)
            result.artifacts.append(str(capture))
        result.observations["surface_graph_endpoints_added"] = browser_endpoints
        missing = [
            name
            for name, details in data.get("security_headers", {}).items()
            if not details.get("present")
        ]
        if missing:
            result.findings.append(
                Finding(
                    context.run_id,
                    target.url,
                    self.name,
                    "browser-security-headers",
                    "Browser-observed response headers need hardening",
                    "low",
                    0.95,
                    "Browser capture confirmed missing common security headers.",
                    {"missing": missing},
                    ["browser", "headers"],
                )
            )
        interesting = data.get("interesting_endpoints", [])
        if interesting:
            result.findings.append(
                Finding(
                    context.run_id,
                    target.url,
                    self.name,
                    "browser-endpoints",
                    "Interesting endpoints observed during browser execution",
                    "info",
                    0.8,
                    "Browser network capture observed endpoints matching assessment terms.",
                    {"endpoints": interesting[:50]},
                    ["browser", "endpoints"],
                )
            )

    def command(self, target: Target, context: ModuleContext, output: Path) -> list[str]:
        return [
            sys.executable,
            "-u",
            str(self.script),
            target.url,
            "--headless",
            "--non-interactive",
            "--report",
            "--duration",
            "5",
            "--timeout",
            str(int(context.timeout * 1000)),
            "--output",
            str(output),
        ]


class NoAuthAdapter(CommandAdapter):
    name = "noauth_finder"
    description = "Run focused unauthenticated web UI triage through noauth_finder"
    script = SOURCES_ROOT / "noauth_finder" / "noauth_finder.py"

    def live_line(self, line: str) -> tuple[str, str] | None:
        if "hosts ×" in line:
            return "progress", "Focused unauthenticated service probe running"
        return None

    def parse_output(self, target, context, output, result):
        report = output / "findings.json"
        if not report.exists():
            return
        data = json.loads(report.read_text(encoding="utf-8"))
        result.observations["scan_meta"] = data.get("scan_meta", {})
        for host_report in data.get("findings", []):
            for endpoint in host_report.get("noauth_endpoints", []):
                severity = str(endpoint.get("severity", "medium")).lower()
                result.findings.append(
                    Finding(
                        context.run_id,
                        target.url,
                        self.name,
                        "unauthenticated-service",
                        "Potential unauthenticated web interface",
                        severity if severity in {"low", "medium", "high", "critical"} else "medium",
                        0.85,
                        "Focused service triage reported a web interface without a clear authentication barrier.",
                        endpoint,
                        ["noauth", "service"],
                    )
                )

    def command(self, target: Target, context: ModuleContext, output: Path) -> list[str]:
        command = [
            sys.executable,
            "-u",
            str(self.script),
            target.host,
            "--ports",
            f"{target.port},",
            "--fast",
            "--threads",
            "2",
            "--timeout",
            str(max(1, int(context.timeout))),
            "--output-dir",
            str(output),
            "--no-color",
            "--no-live-feed",
        ]
        if context.allow_public:
            command.append("--allow-public")
        return command


def adapter_health() -> list[dict[str, str | bool]]:
    playwright = importlib.util.find_spec("playwright") is not None
    requests = importlib.util.find_spec("requests") is not None
    adapters = [GatekeeperAdapter(), NoAuthAdapter()]
    health = [
        {
            "name": adapter.name,
            "available": adapter.available(),
            "path": str(adapter.script),
            "note": (
                "Python Playwright and Chromium are required"
                if adapter.name == "gatekeeper" and not playwright
                else "requests is required"
                if adapter.name == "noauth_finder" and not requests
                else ""
            ),
        }
        for adapter in adapters
    ]
    reaper = SOURCES_ROOT / "REAPER" / "reaper"
    health.append(
        {
            "name": "reaper",
            "available": reaper.exists() and os.access(reaper, os.X_OK),
            "path": str(reaper),
            "note": "GITHUB_TOKEN is required when running intelligence scans",
        }
    )
    return health


def run_reaper(repositories: list[str], output: Path, timeout: int = 3600) -> dict:
    binary = SOURCES_ROOT / "REAPER" / "reaper"
    if not (binary.exists() and os.access(binary, os.X_OK)):
        return {"status": "error", "error": f"REAPER binary not found or executable: {binary}"}
    try:
        repositories = [normalize_repository(value) for value in repositories]
    except ValueError as exc:
        return {"status": "error", "error": str(exc)}
    output.mkdir(parents=True, exist_ok=True)
    command = [
        str(binary),
        "-continuous=false",
        "-scan-advisories=false",
        "-output",
        str(output),
    ]
    for repository in repositories:
        command.extend(["-repo", repository])
    completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    (output / "stdout.log").write_text(completed.stdout, encoding="utf-8")
    (output / "stderr.log").write_text(completed.stderr, encoding="utf-8")
    return {
        "status": "completed" if completed.returncode == 0 else "error",
        "exit_code": completed.returncode,
        "command": command,
        "output": str(output),
    }


def normalize_repository(value: str) -> str:
    value = value.strip().removesuffix(".git")
    if value.startswith(("https://github.com/", "http://github.com/")):
        parts = [part for part in urlparse(value).path.split("/") if part]
    else:
        parts = [part for part in value.split("/") if part]
    if len(parts) != 2:
        raise ValueError(
            f"invalid GitHub repository {value!r}; expected owner/repository or a GitHub URL"
        )
    return f"https://github.com/{parts[0]}/{parts[1]}"


def ingest_browser_traffic(target: Target, context: ModuleContext, payload: object) -> int:
    """Merge request/response-shaped browser records without retaining credentials."""
    added: set[tuple[str, str]] = set()

    def walk(value: object):
        if isinstance(value, dict):
            yield value
            for child in value.values():
                yield from walk(child)
        elif isinstance(value, list):
            for child in value:
                yield from walk(child)

    for item in walk(payload):
        request_data = item.get("request") if isinstance(item.get("request"), dict) else item
        response_data = item.get("response") if isinstance(item.get("response"), dict) else item
        url = request_data.get("url") or item.get("request_url")
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            continue
        parsed = urlparse(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if parsed.hostname != target.host or port != target.port:
            continue
        method = str(request_data.get("method") or item.get("method") or "GET").upper()
        headers = request_data.get("headers") if isinstance(request_data.get("headers"), dict) else {}
        header_names = {str(name).lower() for name in headers}
        authentication = "observed" if {"authorization", "cookie"} & header_names else "unknown"
        response_headers = response_data.get("headers") if isinstance(response_data.get("headers"), dict) else {}
        content_type = next(
            (str(value) for name, value in response_headers.items() if str(name).lower() == "content-type"),
            None,
        )
        status = response_data.get("status") or item.get("status")
        context.surface_graph.add_endpoint(
            target.url,
            url,
            method=method,
            source="browser-traffic",
            authentication=authentication,
            content_type=content_type,
            status=int(status) if str(status).isdigit() else None,
        )
        added.add((url, method))
    return len(added)
