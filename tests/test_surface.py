import unittest

from redflare.modules.surface import SurfaceParser, decode_targets


class SurfaceTests(unittest.TestCase):
    def test_extracts_forms_and_redirects(self):
        parser = SurfaceParser("https://example.test/start")
        parser.feed(
            '<meta http-equiv="refresh" content="0; url=/next">'
            '<form action="/login" method="post"><input name="password" type="password"></form>'
        )
        self.assertEqual(parser.forms[0]["action"], "https://example.test/login")
        self.assertEqual(parser.meta_refresh, ["https://example.test/next"])


if __name__ == "__main__":
    unittest.main()
