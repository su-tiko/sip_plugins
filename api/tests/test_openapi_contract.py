import json
import unittest
from pathlib import Path


class TestOpenApiContract(unittest.TestCase):
    def test_openapi_json_contains_required_api_v1_paths_and_bearer_auth(self):
        path = Path(__file__).resolve().parents[1] / "openapi.json"
        spec = json.loads(path.read_text())
        self.assertTrue(spec["openapi"].startswith("3."))
        self.assertIn("/api/v1/status", spec["paths"])
        self.assertIn("/api/v1/auth/tokens", spec["paths"])
        self.assertIn("/api/v1/openapi.json", spec["paths"])
        schemes = spec["components"]["securitySchemes"]
        self.assertEqual(schemes["bearerAuth"]["type"], "http")
        self.assertEqual(schemes["bearerAuth"]["scheme"], "bearer")


if __name__ == "__main__":
    unittest.main()
