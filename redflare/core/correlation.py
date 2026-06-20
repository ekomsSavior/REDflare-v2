from __future__ import annotations

from collections import defaultdict

from .models import Finding, ModuleResult


def correlate(run_id: str, results: list[ModuleResult]) -> list[ModuleResult]:
    by_target: dict[str, list[ModuleResult]] = defaultdict(list)
    for result in results:
        by_target[result.target].append(result)

    correlated = []
    for target, target_results in by_target.items():
        path_hits = [
            finding
            for result in target_results
            for finding in result.findings
            if finding.category == "discovered-path" and finding.severity == "medium"
        ]
        header_gaps = [
            finding
            for result in target_results
            for finding in result.findings
            if finding.category == "security-headers"
        ]
        if path_hits and header_gaps:
            finding = Finding(
                run_id,
                target,
                "correlation",
                "exposed-surface",
                "Sensitive web surface with weak response hardening",
                "medium",
                0.85,
                "REDflare correlated an accessible sensitive path with missing security headers.",
                {
                    "paths": [item.evidence.get("path") for item in path_hits],
                    "missing_headers": header_gaps[0].evidence.get("missing", []),
                },
                ["correlated", "web"],
            )
            correlated.append(ModuleResult("correlation", target, findings=[finding]))
    return correlated
