import unittest

from redflare.core.surface_graph import AttackSurfaceGraph


class SurfaceGraphTests(unittest.TestCase):
    def test_merges_sources_methods_and_query_parameters(self):
        graph = AttackSurfaceGraph()
        graph.add_endpoint(
            "https://example.test",
            "https://example.test/api/users?id=7",
            method="GET",
            source="html-link",
        )
        graph.add_endpoint(
            "https://example.test",
            "https://example.test/api/users?id=9",
            method="POST",
            source="openapi",
            parameters=[{"name": "name", "location": "body", "required": True, "data_type": "string"}],
        )
        snapshot = graph.snapshot()
        endpoints = snapshot["targets"]["https://example.test"]["endpoints"]
        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0]["methods"], ["GET", "POST"])
        self.assertEqual({item["name"] for item in endpoints[0]["parameters"]}, {"id", "name"})


if __name__ == "__main__":
    unittest.main()
