from __future__ import annotations

import html
import json
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Iterable

from .models import Finding, ModuleResult


class RunStore:
    def __init__(self, base: str = "runs", run_id: str | None = None):
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.run_id = run_id or f"run_{stamp}"
        root = Path(base)
        candidate = root / self.run_id
        sequence = 1
        while candidate.exists():
            candidate = root / f"{self.run_id}_{sequence:02d}"
            sequence += 1
        self.root = candidate
        self.modules = self.root / "modules"
        self.artifacts = self.root / "artifacts"
        self.modules.mkdir(parents=True)
        self.artifacts.mkdir(parents=True)
        self.findings_file = self.root / "findings.jsonl"
        self.findings_file.touch()

    def write_manifest(self, manifest: dict) -> None:
        self._write_json(self.root / "manifest.json", manifest)

    def write_result(self, result: ModuleResult) -> None:
        safe_target = result.target.replace("://", "_").replace("/", "_").replace(":", "_")
        self._write_json(self.modules / f"{safe_target}__{result.module}.json", result.to_dict())
        with self.findings_file.open("a", encoding="utf-8") as handle:
            for finding in result.findings:
                handle.write(json.dumps(finding.to_dict(), sort_keys=True) + "\n")

    def write_surface_graph(self, graph: dict) -> None:
        self._write_json(self.root / "attack_surface.json", graph)

    def write_test_registry(self, registry: dict) -> None:
        self._write_json(self.root / "test_registry.json", registry)

    def finalize(self, results: Iterable[ModuleResult], surface_graph: dict | None = None) -> dict:
        results = list(results)
        findings = deduplicate_findings(
            [finding for result in results for finding in result.findings]
        )
        with self.findings_file.open("w", encoding="utf-8") as handle:
            for finding in findings:
                handle.write(json.dumps(finding.to_dict(), sort_keys=True) + "\n")
        summary = {
            "run_id": self.run_id,
            "module_results": len(results),
            "completed": sum(result.status == "completed" for result in results),
            "errors": sum(result.status == "error" for result in results),
            "findings": len(findings),
            "by_severity": count_by(finding.severity for finding in findings),
            "by_module": count_by(finding.module for finding in findings),
            "by_category": count_by(finding.category for finding in findings),
            "sensitive_exposures": sum(
                finding.category == "sensitive-data-exposure" for finding in findings
            ),
            "attack_surface": (surface_graph or {}).get("summary", {}),
        }
        self._write_json(self.root / "summary.json", summary)
        (self.root / "report.html").write_text(
            render_html(summary, findings, results), encoding="utf-8"
        )
        return summary

    @staticmethod
    def _write_json(path: Path, value: dict) -> None:
        path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


def count_by(values: Iterable[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    canonical_categories = {
        "browser-security-headers": "security-headers",
    }
    selected: dict[tuple[str, str], Finding] = {}
    sources: dict[tuple[str, str], set[str]] = {}
    for finding in findings:
        category = canonical_categories.get(finding.category, finding.category)
        key = (
            finding.target,
            category if category == "security-headers" else finding.id,
        )
        sources.setdefault(key, set()).add(finding.module)
        current = selected.get(key)
        if current is None or finding.confidence > current.confidence:
            selected[key] = replace(
                finding,
                category=category,
                evidence=dict(finding.evidence),
            )
    for key, finding in selected.items():
        modules = sorted(sources[key])
        if len(modules) > 1:
            finding.evidence["corroborated_by"] = modules
            finding.tags = sorted(set(finding.tags + ["corroborated"]))
    return list(selected.values())


def render_html(
    summary: dict,
    findings: list[Finding],
    results: list[ModuleResult] | None = None,
) -> str:
    rows = []
    for finding in sorted(findings, key=lambda item: (item.severity, item.target), reverse=True):
        rows.append(
            "<tr>"
            f"<td>{html.escape(finding.severity)}</td>"
            f"<td>{html.escape(finding.test_id)}</td>"
            f"<td>{html.escape(finding.module)}</td>"
            f"<td>{html.escape(finding.target)}</td>"
            f"<td>{html.escape(finding.title)}</td>"
            f"<td>{html.escape(finding.description)}</td>"
            "</tr>"
        )
    assessments = []
    for result in sorted(results or [], key=lambda item: (item.target, item.module)):
        module_findings = "".join(
            "<article class=\"finding\">"
            f"<h4>[{html.escape(finding.severity.upper())}] {html.escape(finding.title)}</h4>"
            f"<p><strong>Test ID:</strong> {html.escape(finding.test_id or 'unmapped')}</p>"
            f"<p>{html.escape(finding.description)}</p>"
            f"<pre>{html.escape(json.dumps(finding.evidence, indent=2, default=str))}</pre>"
            f"<p><strong>Remediation:</strong> {html.escape(finding.remediation or 'Review and remediate based on verified impact.')}</p>"
            "</article>"
            for finding in result.findings
        ) or "<p>No module findings.</p>"
        errors = "".join(f"<li>{html.escape(error)}</li>" for error in result.errors) or "<li>None</li>"
        artifacts = "".join(
            f"<li><code>{html.escape(artifact)}</code></li>" for artifact in result.artifacts
        ) or "<li>None</li>"
        assessments.append(
            "<section class=\"module\">"
            f"<h2>{html.escape(result.module.replace('_', ' ').upper())} ASSESSMENT</h2>"
            f"<p><strong>Target:</strong> {html.escape(result.target)}<br>"
            f"<strong>Status:</strong> {html.escape(result.status.upper())} &nbsp; "
            f"<strong>Duration:</strong> {result.duration_seconds:.2f}s &nbsp; "
            f"<strong>Findings:</strong> {len(result.findings)}</p>"
            "<h3>Complete observations</h3>"
            f"<pre>{html.escape(json.dumps(result.observations, indent=2, default=str))}</pre>"
            f"<h3>Module findings</h3>{module_findings}"
            f"<h3>Errors</h3><ul>{errors}</ul>"
            f"<h3>Artifacts</h3><ul>{artifacts}</ul>"
            "</section>"
        )
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>REDflare {html.escape(summary['run_id'])}</title>
<style>
:root{{color-scheme:dark}}body{{font-family:system-ui;margin:2rem auto;max-width:1500px;padding:0 1rem;background:#0d0d0f;color:#eee}}
h1,h2,h3{{color:#ff6666}}.summary,.module{{background:#17171b;border:1px solid #3d3d45;border-radius:10px;padding:1rem 1.25rem;margin:1rem 0}}
.module{{border-left:5px solid #9d2424}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#09090b;border:1px solid #333;padding:1rem;border-radius:6px}}
table{{border-collapse:collapse;width:100%}}th,td{{padding:.6rem;border:1px solid #444;text-align:left;vertical-align:top}}th{{background:#5b1515}}
.finding{{border-left:3px solid #d99a31;padding:.1rem 1rem;margin:.75rem 0}}code{{overflow-wrap:anywhere}}
</style></head>
<body><h1>REDflare Final Assessment Report</h1><section class="summary"><h2>Run summary</h2><pre>{html.escape(json.dumps(summary, indent=2))}</pre></section>
{''.join(assessments)}
<section class="summary"><h2>Assessment artifacts</h2><ul><li><code>attack_surface.json</code></li><li><code>test_registry.json</code></li></ul></section>
<section class="summary"><h2>Consolidated findings</h2><table><thead><tr><th>Severity</th><th>Test ID</th><th>Module</th><th>Target</th><th>Finding</th><th>Description</th></tr></thead><tbody>{''.join(rows)}</tbody></table></section></body></html>"""
