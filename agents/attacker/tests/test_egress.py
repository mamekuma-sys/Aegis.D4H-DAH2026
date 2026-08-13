import unittest

from aegis_attacker.config import AttackerConfig
from aegis_attacker.egress import EgressError, EgressGateway, build_allowlists
from aegis_attacker.models import Capability
from aegis_attacker.observation import HttpResponse


class RecordingTransport:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def request(self, method, url, headers=None, body=None, timeout=6.0):
        self.calls.append((method, url))
        return self.response


CFG = AttackerConfig(
    targets=("team2.lig.internal",), ports=(8082, 8083),
    submit_url="http://10.99.50.4:4100/submit", submit_token="tok",
    llm_base_url="http://litellm.lig.internal:4000", llm_api_key="sk",
)


def make_gateway(resp=None):
    t = RecordingTransport(resp or HttpResponse(200, "ok"))
    return EgressGateway(t, build_allowlists(CFG)), t


class TestAllowlists(unittest.TestCase):
    def test_build(self):
        allow = build_allowlists(CFG)
        self.assertIn(("team2.lig.internal", 8082), allow[Capability.ATTACK_TARGET])
        self.assertIn(("team2.lig.internal", 8083), allow[Capability.ATTACK_TARGET])
        self.assertIn(("10.99.50.4", 4100), allow[Capability.SUBMIT])
        self.assertIn(("litellm.lig.internal", 4000), allow[Capability.LLM])


class TestEgressGateway(unittest.TestCase):
    def test_attack_target_in_scope(self):
        gw, t = make_gateway()
        gw.request(Capability.ATTACK_TARGET, "GET",
                   "http://team2.lig.internal:8082/fetch")
        self.assertEqual(len(t.calls), 1)

    def test_out_of_scope_rejected(self):
        gw, t = make_gateway()
        with self.assertRaises(EgressError):
            gw.request(Capability.ATTACK_TARGET, "GET", "http://evil.com:80/")
        self.assertEqual(len(t.calls), 0)  # 호출 전에 거부

    def test_capability_crossing_rejected(self):
        # SUBMIT capability로 공격 표적 host를 치려는 시도 거부
        gw, t = make_gateway()
        with self.assertRaises(EgressError):
            gw.request(Capability.SUBMIT, "POST",
                       "http://team2.lig.internal:8082/submit")
        self.assertEqual(len(t.calls), 0)

    def test_port_change_rejected(self):
        # 허용 포트(8082/8083) 밖은 거부
        gw, t = make_gateway()
        with self.assertRaises(EgressError):
            gw.request(Capability.ATTACK_TARGET, "GET",
                       "http://team2.lig.internal:9999/")

    def test_submit_and_llm_scoped(self):
        gw, t = make_gateway()
        gw.request(Capability.SUBMIT, "POST", "http://10.99.50.4:4100/submit")
        gw.request(Capability.LLM, "POST",
                   "http://litellm.lig.internal:4000/v1/chat/completions")
        self.assertEqual(len(t.calls), 2)

    def test_redirect_returned_as_observation(self):
        # 전송이 3xx를 반환하면 게이트웨이는 따라가지 않고 그대로 넘긴다
        gw, t = make_gateway(HttpResponse(302, "", {"Location": "http://x/"}))
        resp = gw.request(Capability.ATTACK_TARGET, "GET",
                          "http://team2.lig.internal:8082/")
        self.assertEqual(resp.status, 302)


if __name__ == "__main__":
    unittest.main()
