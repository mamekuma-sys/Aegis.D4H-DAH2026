import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import normal_traffic


class FakeResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, size=-1):
        if size != 1:
            raise AssertionError("response body must be bounded")
        return b"x"


class TestNormalTraffic(unittest.TestCase):
    def test_aggregate_contains_no_response_content(self):
        with patch.object(normal_traffic.urllib.request, "urlopen", return_value=FakeResponse()):
            result = normal_traffic.run(7, samples_per_route=1, timeout=1.0, interval=0.0)

        self.assertEqual(result["requests"], 6)
        self.assertEqual(result["successes"], 6)
        self.assertEqual(result["failures"], 0)
        serialized = json.dumps(result)
        for forbidden in ("body", "header", "cookie", "FLAG{"):
            self.assertNotIn(forbidden, serialized)

    def test_seed_makes_request_order_deterministic(self):
        seen = []

        def open_url(url, timeout):
            seen.append((url, timeout))
            return FakeResponse()

        with patch.object(normal_traffic.urllib.request, "urlopen", side_effect=open_url):
            normal_traffic.run(11, samples_per_route=2, timeout=1.5, interval=0.0)
            first = list(seen)
            seen.clear()
            normal_traffic.run(11, samples_per_route=2, timeout=1.5, interval=0.0)

        self.assertEqual(first, seen)


if __name__ == "__main__":
    unittest.main()
