import unittest

from aegis_attacker.config import AttackerConfig
from aegis_attacker.egress import EgressGateway, build_allowlists
from aegis_attacker.models import Endpoint
from aegis_attacker.observation import (
    HttpResponse,
    Observer,
    fingerprint,
    notable_headers,
)
from aegis_attacker.rate_limit import RateLimiter

EP = Endpoint("team2.lig.internal", 8082)
CFG = AttackerConfig(targets=("team2.lig.internal",), ports=(8082,), llm_api_key="k")


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


class FakeTransport:
    def __init__(self, response):
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
        self.assertEqual(fp, fingerprint("FLAG{secret}"))

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
        gw = EgressGateway(FakeTransport(resp), build_allowlists(CFG))
        return Observer(gw, rl, round_id="r1", clock=clk), clk

    def test_observe_banner_builds_observation(self):
        obs_er, _ = self._observer(HttpResponse(200, "URL Fetcher", {"Server": "Werkzeug"}))
        obs, resp = obs_er.observe_banner(EP)
        self.assertEqual(obs.status, 200)
        self.assertEqual(resp.body, "URL Fetcher")
        self.assertIn("Server", obs.redacted_header_hints)
        self.assertEqual(obs.round_id, "r1")
        self.assertIsNotNone(obs.evidence_ref)  # 증거 참조 부착
        self.assertTrue(obs.evidence_ref.valid_at(0.0, "r1", EP.endpoint_id))
        self.assertFalse(obs.no_response)

    def test_no_response_recorded_as_observation(self):
        obs_er, _ = self._observer(HttpResponse(0, "", {}))
        obs, _ = obs_er.observe_banner(EP)
        self.assertTrue(obs.no_response)
        self.assertEqual(obs.note, "no-response")

    def test_observe_respects_rate_limit(self):
        obs_er, _ = self._observer(HttpResponse(200, "ok", {}))
        for _ in range(25):
            obs_er.observe_banner(EP)


if __name__ == "__main__":
    unittest.main()
