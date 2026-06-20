from __future__ import annotations

import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from redflare.core.models import ModuleResult
from redflare.core.storage import deduplicate_findings


class LiveConsole:
    COLORS = {
        "start": "\033[96m",
        "progress": "\033[90m",
        "info": "\033[94m",
        "finding": "\033[93m",
        "success": "\033[92m",
        "error": "\033[91m",
        "skipped": "\033[95m",
    }
    ICONS = {
        "start": "▶",
        "progress": "·",
        "info": "i",
        "finding": "!",
        "success": "✓",
        "error": "✗",
        "skipped": "↷",
    }

    def __init__(self, stream=None):
        self.stream = stream or sys.stdout
        self.color = hasattr(self.stream, "isatty") and self.stream.isatty()
        self.lock = threading.Lock()

    def emit(self, target: str, module: str, kind: str, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        icon = self.ICONS.get(kind, "·")
        prefix = f"[{timestamp}] {icon} [{short_target(target)}] {module}"
        line = f"{prefix} — {message}"
        if self.color:
            line = f"{self.COLORS.get(kind, '')}{line}\033[0m"
        with self.lock:
            print(line, file=self.stream, flush=True)

    def final_report(
        self,
        summary: dict,
        results: list[ModuleResult],
        run_directory: Path,
    ) -> None:
        findings = deduplicate_findings(
            [finding for result in results for finding in result.findings]
        )
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda item: (severity_order.get(item.severity, 9), item.target, item.title))
        width = 88
        with self.lock:
            print("\n" + "═" * width, file=self.stream)
            print("REDFLARE FINAL ASSESSMENT REPORT", file=self.stream)
            print("═" * width, file=self.stream)
            print(f"Run:       {summary['run_id']}", file=self.stream)
            print(f"Evidence:  {run_directory}", file=self.stream)
            print(
                f"Modules:   {summary['completed']} completed / {summary['errors']} errors",
                file=self.stream,
            )
            print(f"Findings:  {summary['findings']}  {summary.get('by_severity', {})}", file=self.stream)
            if summary.get("sensitive_exposures"):
                print(
                    f"Sensitive exposures: {summary['sensitive_exposures']}",
                    file=self.stream,
                )

            print("\nMODULE EXECUTION", file=self.stream)
            print("─" * width, file=self.stream)
            for result in sorted(results, key=lambda item: (item.target, item.module)):
                print(
                    f"{result.status.upper():9} {result.duration_seconds:7.2f}s  "
                    f"{result.module:20} {short_target(result.target)}",
                    file=self.stream,
                )

            for result in sorted(results, key=lambda item: (item.target, item.module)):
                self._module_assessment(result, width)

            print("\nCONSOLIDATED FINDINGS", file=self.stream)
            print("─" * width, file=self.stream)
            if not findings:
                print("No findings were produced by the configured modules.", file=self.stream)
            for index, finding in enumerate(findings, start=1):
                print(
                    f"{index:>3}. [{finding.severity.upper():8}] {finding.title}",
                    file=self.stream,
                )
                print(f"     Target: {finding.target}", file=self.stream)
                print(f"     Module: {finding.module} | Confidence: {finding.confidence:.2f}", file=self.stream)
                if finding.test_id:
                    print(f"     Test ID: {finding.test_id}", file=self.stream)
                print(f"     {finding.description}", file=self.stream)
                if finding.evidence:
                    print("     Evidence:", file=self.stream)
                    self._print_value(finding.evidence, indent=7)
                if finding.remediation:
                    print(f"     Remediation: {finding.remediation}", file=self.stream)

            intel = summary.get("repository_intelligence")
            if intel:
                print("\nREPOSITORY INTELLIGENCE", file=self.stream)
                print("─" * width, file=self.stream)
                print(f"Status: {intel.get('status')} | Output: {intel.get('output', 'n/a')}", file=self.stream)

            print("\nREPORT FILES", file=self.stream)
            print("─" * width, file=self.stream)
            for name in (
                "report.html",
                "summary.json",
                "findings.jsonl",
                "attack_surface.json",
                "test_registry.json",
                "manifest.json",
            ):
                print(f"{run_directory / name}", file=self.stream)
            print("═" * width, file=self.stream, flush=True)

    def _module_assessment(self, result: ModuleResult, width: int) -> None:
        title = result.module.replace("_", " ").upper()
        print(f"\n{title} ASSESSMENT — {result.target}", file=self.stream)
        print("─" * width, file=self.stream)
        print(
            f"Status: {result.status.upper()} | Duration: {result.duration_seconds:.2f}s | "
            f"Findings: {len(result.findings)}",
            file=self.stream,
        )

        print("\nObservations:", file=self.stream)
        if result.observations:
            self._print_value(result.observations, indent=2)
        else:
            print("  None recorded.", file=self.stream)

        print("\nModule findings:", file=self.stream)
        if not result.findings:
            print("  No module findings.", file=self.stream)
        for index, finding in enumerate(result.findings, start=1):
            print(
                f"  {index}. [{finding.severity.upper()}] {finding.title} "
                f"(confidence {finding.confidence:.2f})",
                file=self.stream,
            )
            if finding.test_id:
                print(f"     Test ID: {finding.test_id}", file=self.stream)
            print(f"     {finding.description}", file=self.stream)
            if finding.evidence:
                print("     Evidence:", file=self.stream)
                self._print_value(finding.evidence, indent=7)
            if finding.remediation:
                print(f"     Remediation: {finding.remediation}", file=self.stream)

        print("\nErrors:", file=self.stream)
        if result.errors:
            for error in result.errors:
                print(f"  - {error}", file=self.stream)
        else:
            print("  None.", file=self.stream)

        print("Artifacts:", file=self.stream)
        if result.artifacts:
            for artifact in result.artifacts:
                print(f"  - {artifact}", file=self.stream)
        else:
            print("  None.", file=self.stream)

    def _print_value(self, value: Any, indent: int = 0, label: str | None = None) -> None:
        prefix = " " * indent
        if isinstance(value, dict):
            if label is not None:
                print(f"{prefix}{human_label(label)}:", file=self.stream)
                indent += 2
            if not value:
                print(f"{' ' * indent}{{}}", file=self.stream)
            for key, item in value.items():
                self._print_value(item, indent, str(key))
            return
        if isinstance(value, list):
            if label is not None:
                print(f"{prefix}{human_label(label)} ({len(value)}):", file=self.stream)
                indent += 2
            if not value:
                print(f"{' ' * indent}None", file=self.stream)
            for index, item in enumerate(value, start=1):
                marker = f"[{index}]"
                if isinstance(item, (dict, list)):
                    print(f"{' ' * indent}{marker}", file=self.stream)
                    self._print_value(item, indent + 2)
                else:
                    print(f"{' ' * indent}{marker} {display_scalar(item)}", file=self.stream)
            return
        if label is None:
            print(f"{prefix}{display_scalar(value)}", file=self.stream)
        else:
            print(f"{prefix}{human_label(label)}: {display_scalar(value)}", file=self.stream)


def short_target(target: str) -> str:
    value = target.replace("https://", "").replace("http://", "")
    return value[:42] + ("…" if len(value) > 42 else "")


def human_label(value: str) -> str:
    return value.replace("_", " ").strip().capitalize()


def display_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)
