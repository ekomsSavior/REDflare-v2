from __future__ import annotations

from io import StringIO
from pathlib import Path
import unittest

from redflare.core.models import Finding, ModuleResult
from redflare.ui import LiveConsole


class FinalReportTests(unittest.TestCase):
    def test_full_module_assessment_includes_observations_findings_and_artifacts(self):
        stream = StringIO()
        finding = Finding(
            run_id="run_test",
            target="https://example.test",
            module="path_discovery",
            category="discovered-path",
            title="Accessible path discovered: /admin",
            severity="info",
            confidence=0.8,
            description="The path returned HTTP 200.",
            evidence={"status": 200, "url": "https://example.test/admin"},
        )
        result = ModuleResult(
            module="path_discovery",
            target="https://example.test",
            findings=[finding],
            observations={
                "paths_tested": 2,
                "hits": [{"path": "/admin", "status": 200, "bytes": 42}],
            },
            artifacts=["runs/run_test/artifacts/path.log"],
            duration_seconds=1.25,
        )
        summary = {
            "run_id": "run_test",
            "completed": 1,
            "errors": 0,
            "findings": 1,
            "by_severity": {"info": 1},
        }

        LiveConsole(stream).final_report(summary, [result], Path("runs/run_test"))
        output = stream.getvalue()

        self.assertIn("PATH DISCOVERY ASSESSMENT — https://example.test", output)
        self.assertIn("Paths tested: 2", output)
        self.assertIn("Path: /admin", output)
        self.assertIn("Status: 200", output)
        self.assertIn("Module findings:", output)
        self.assertIn("runs/run_test/artifacts/path.log", output)
        self.assertIn("CONSOLIDATED FINDINGS", output)


if __name__ == "__main__":
    unittest.main()
