import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from redflare.core.models import Target
from redflare.modules.base import ModuleContext
from redflare.modules.browser import NativeBrowserRuntimeModule
from redflare.modules.http import HTTPResponse
from redflare.modules.noauth import NativeNoAuthModule
from redflare.modules.repository import normalize_repository, run_repository_intelligence


class NativeModuleTests(unittest.TestCase):
    def test_repository_slug_normalization(self):
        self.assertEqual(normalize_repository("owner/repository"), "owner/repository")
        with self.assertRaises(ValueError): normalize_repository("repository")

    @patch("redflare.modules.browser.NativeBrowserRuntimeModule._capture", side_effect=RuntimeError("fixture"))
    @patch("redflare.modules.browser.request")
    def test_browser_runtime_has_native_fallback(self, get, _capture):
        get.return_value = HTTPResponse("https://example.test", 200, {}, b"fixture")
        with tempfile.TemporaryDirectory() as directory:
            context = ModuleContext("run", Path(directory))
            result = NativeBrowserRuntimeModule().run(Target("https://example.test", "example.test", "https", 443), context)
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.observations["engine"], "native-http-fallback")

    @patch("redflare.modules.noauth.time.sleep")
    @patch("redflare.modules.noauth.request")
    def test_noauth_module_emits_native_finding(self, get, _sleep):
        get.return_value = HTTPResponse("https://example.test/admin", 200, {"content-type": "text/html"}, b"admin console")
        with tempfile.TemporaryDirectory() as directory:
            context = ModuleContext("run", Path(directory), rate=0)
            result = NativeNoAuthModule().run(Target("https://example.test", "example.test", "https", 443), context)
        self.assertGreater(len(result.findings), 0)
        self.assertEqual(result.observations["engine"], "native-redflare")

    @patch("redflare.modules.repository._github")
    @patch.dict("os.environ", {"GITHUB_TOKEN": "fixture-token"})
    def test_repository_intelligence_masks_findings(self, github):
        github.side_effect = [
            {"default_branch": "main"},
            {"tree": [{"type": "blob", "path": "config.js", "sha": "abc", "size": 100}]},
            {"encoding": "base64", "content": "YXBpX2tleSA9ICJhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eiI="},
        ]
        with tempfile.TemporaryDirectory() as directory:
            result = run_repository_intelligence(["owner/repo"], Path(directory))
            data = json.loads(Path(result["output"]).read_text())
        self.assertEqual(result["engine"], "native-redflare")
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", json.dumps(data))


if __name__ == "__main__": unittest.main()
