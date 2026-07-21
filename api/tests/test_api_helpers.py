import importlib.util
import json
from pathlib import Path
import unittest

API_PATH = Path(__file__).resolve().parents[1] / "api.py"


def load_api_module():
    spec = importlib.util.spec_from_file_location("sip_plugins_api_under_test", API_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestApiPluginHelpers(unittest.TestCase):
    def test_token_hash_verification_does_not_store_raw_token(self):
        api = load_api_module()
        raw, record = api.create_token_record("laptop", scopes=["read", "write"])
        self.assertTrue(raw.startswith("sip_"))
        self.assertNotIn(raw, json.dumps(record))
        self.assertTrue(api.verify_token(raw, record))
        self.assertFalse(api.verify_token(raw + "x", record))

    def test_response_envelope(self):
        api = load_api_module()
        body = json.loads(api.response_ok({"hello": "world"}))
        self.assertTrue(body["ok"])
        self.assertEqual(body["data"], {"hello": "world"})
        self.assertEqual(body["meta"]["api_version"], "v1")


if __name__ == "__main__":
    unittest.main()
