import unittest

from aegis_attacker.models import Endpoint
from aegis_attacker.observation import (
    HttpResponse,
    Observer,
    fingerprint,
    notable_headers,
)
from aegis_attacker.rate_limit import RateLimiter


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


class FakeHttp:
    def __init__(self, response, record=None):
        self.response = response
        self.calls = []

    def request(self, method, url, headers=None, body=None, timeout=6.0):
        self.calls.append((method, url, headers, body, timeout))
        return self.response


class TestHelpers(unittest.TestCase):
    def test_fingerprint_stable_and_no_plaintext(self):
        fp = fingerprint("FLAG{secret}")
        self.assertEqual(len(fp), 16)
        self.assertNotIn("FLAG", fp)
        self.assertEqual(fp, fingerprint("FLAG{secret}"))  # 결정론적

    def test_notable_headers_filter(self):
        h = {"Set-Cookie": "s=1", "Content-Type": "text/html", "X-Role": "user"}
        picked = notable_headers(h)
        self.assertIn("Set-Cookie", picked)
        self.assertIn("X-Role", picked)
        self.assertNotIn("Content-Type", picked)


class TestObserver(unittest.TestCase):
    def _observer(self, resp):
        clk = FakeClock()
        rl = RateLimiter(clock=clk, sleep=lambda dt: clk.advance(dt))
        return Observer(FakeHttp(resp), rl, clock=clk), clk

    def test_observe_banner_builds_observation(self):
        obs_er, _ = self._observer(HttpResponse(200, "URL Fetcher", {"Server": "Werkzeug"}))
        obs, resp = obs_er.observe_banner(Endpoint("team2.lig.internal", 8082))
        self.assertEqual(obs.status, 200)
        self.assertEqual(resp.body, "URL Fetcher")
        self.assertIn("Server", obs.header_hints)
        self.assertFalse(obs.no_response)

    def test_no_response_recorded_as_observation(self):
        # status 0(연결거부/필터 DROP)도 실패가 아니라 관측이다.
        obs_er, _ = self._observer(HttpResponse(0, "", {}))
        obs, _ = obs_er.observe_banner(Endpoint("h", 8082))
        self.assertTrue(obs.no_response)
        self.assertEqual(obs.note, "no-response")

    def test_observe_respects_rate_limit(self):
        # 21회 관측해도 rate limiter가 blocking으로 흐르게 하되 예외 없이 완료.
        obs_er, _ = self._observer(HttpResponse(200, "ok", {}))
        for _ in range(25):
            obs_er.observe_banner(Endpoint("h", 8082))


if __name__ == "__main__":
    unittest.main()
