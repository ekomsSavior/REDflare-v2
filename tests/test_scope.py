import unittest
from unittest.mock import patch

from redflare.core.scope import ScopeError, ScopePolicy, normalize_target


class ScopeTests(unittest.TestCase):
    def test_normalizes_bare_hostname(self):
        target = normalize_target("localhost:8080")
        self.assertEqual(target.url, "https://localhost:8080")
        self.assertEqual(target.port, 8080)

    @patch("redflare.core.scope.is_public_host", return_value=False)
    def test_allowed_host(self, _):
        target = normalize_target("http://localhost:8080")
        ScopePolicy({"localhost"}).validate(target)

    @patch("redflare.core.scope.is_public_host", return_value=False)
    def test_rejects_host_outside_manifest(self, _):
        target = normalize_target("http://other.local")
        with self.assertRaises(ScopeError):
            ScopePolicy({"allowed.local"}).validate(target)


if __name__ == "__main__":
    unittest.main()
