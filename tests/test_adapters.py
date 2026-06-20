import unittest
from pathlib import Path

from redflare.core.models import Target
from redflare.modules.adapters import GatekeeperAdapter, NoAuthAdapter, normalize_repository
from redflare.modules.base import ModuleContext


class AdapterTests(unittest.TestCase):
    def test_normalizes_repository_slug(self):
        self.assertEqual(
            normalize_repository("owner/repository"),
            "https://github.com/owner/repository",
        )

    def test_rejects_ambiguous_repository_name(self):
        with self.assertRaises(ValueError):
            normalize_repository("repository")

    def test_noauth_adapter_forces_exact_target_port(self):
        target = Target("http://127.0.0.1:8765", "127.0.0.1", "http", 8765)
        context = ModuleContext("test", Path("/tmp"))
        command = NoAuthAdapter().command(target, context, Path("/tmp/noauth"))
        self.assertEqual(command[command.index("--ports") + 1], "8765,")

    def test_adapter_banners_and_summaries_are_suppressed(self):
        gatekeeper = GatekeeperAdapter()
        self.assertIsNone(gatekeeper.live_line("GATEKEEPER SUMMARY"))
        self.assertIsNone(gatekeeper.live_line("Initial URL: https://example.test"))
        self.assertIsNotNone(gatekeeper.live_line("  [req] GET https://example.test/api"))
        self.assertIsNone(NoAuthAdapter().live_line("No-Auth Web UI Finder by ek0ms savi0r"))


if __name__ == "__main__":
    unittest.main()
