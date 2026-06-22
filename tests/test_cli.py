import io
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

from redflare.cli import main
from redflare.interactive import interactive_arguments


class CLITests(unittest.TestCase):
    def test_scan_requires_authorization_acknowledgement(self):
        error = io.StringIO()
        with redirect_stderr(error):
            code = main(["scan", "http://127.0.0.1"])
        self.assertEqual(code, 2)
        self.assertIn("--authorized", error.getvalue())

    @patch(
        "builtins.input",
        side_effect=[
            "1",                         # full profile
            "1",                         # direct targets
            "https://example.test",      # target
            "",                          # no scope file
            "yes",                       # authorized
            "no",                        # not public
            "yes",                       # full interaction permitted
            "runs",                      # output
            "1",                         # workers
            "10",                        # timeout
            "1",                         # standard network discovery
            "",                          # default ports
            "no",                        # no service enumeration
            "yes",                       # continue after TLS trust finding
            "yes",                       # enumerate TLS ciphers
            "",                          # no wordlist
            "1",                         # rate
            "25",                        # max paths
            "30",                        # max crawl pages
            "2",                         # max crawl depth
            "no",                        # no GraphQL introspection
            "75",                        # max exposure endpoints
            "",                          # no NVD key file
            "https://github.com/o/r",    # repository
        ],
    )
    def test_interactive_wizard_builds_full_pipeline(self, _):
        arguments = interactive_arguments()
        self.assertIn("full", arguments)
        self.assertIn("--authorized", arguments)
        self.assertIn("--github-repo", arguments)
        self.assertIn("https://example.test", arguments)

    @patch("redflare.interactive.recent_runs", return_value=[])
    @patch("builtins.input", side_effect=["4", "file:///tmp/run_fixture", "8765", "yes"])
    def test_interactive_menu_builds_visualizer_command(self, _, __):
        arguments = interactive_arguments()
        self.assertEqual(arguments[:2], ["visualize", "file:///tmp/run_fixture"])
        self.assertNotIn("--no-browser", arguments)


if __name__ == "__main__":
    unittest.main()
